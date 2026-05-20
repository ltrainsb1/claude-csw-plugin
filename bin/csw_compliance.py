#!/usr/bin/env python3
"""CSW compliance-evidence runner. Read-only. stdlib only.

Loads a framework mapping (JSON), evaluates each control against the live
cluster via reusable evidence primitives, applies a deterministic verdict
rule, and renders a markdown evidence report.

IRON LAW: read-only. This runner NEVER issues a mutating call. The only POSTs
are read-style search endpoints (inventory/search, flow_search/flows).
"""
import json
import os
import sys

STATUS_LABEL = {"satisfied": "Satisfied", "partial": "Partial", "gap": "Gap"}
ALL_STATUSES = ["Satisfied", "Partial", "Gap", "Not-evidenceable", "Indeterminate"]


def measurement(value=None, display="", indeterminate=False, reason=None):
    return {"value": value, "display": display, "indeterminate": indeterminate, "reason": reason}


def _match(value, cond):
    if cond in ("present", "absent"):
        return value == cond
    for op in (">=", "<=", ">", "<", "=="):
        if cond.startswith(op):
            threshold = float(cond[len(op):])
            v = float(value)
            return {
                ">=": v >= threshold, "<=": v <= threshold,
                ">": v > threshold, "<": v < threshold, "==": v == threshold,
            }[op]
    raise ValueError(f"Unparseable verdict condition: {cond!r}")


def evaluate_verdict(evidence_name, meas, verdict_rule):
    if evidence_name == "not_evidenceable":
        return "Not-evidenceable"
    if meas.get("indeterminate"):
        return "Indeterminate"
    value = meas.get("value")
    for key in ("satisfied", "partial"):
        cond = verdict_rule.get(key)
        if cond is not None and _match(value, cond):
            return STATUS_LABEL[key]
    return STATUS_LABEL.get(verdict_rule.get("else", "gap"), "Gap")


REQUIRED_FRAMEWORK_KEYS = ("id", "name", "version", "source", "retrieved", "disclaimer")

# Catalog of valid evidence primitive names. The callables are registered in
# PRIMITIVES (below); test_registry_matches_catalog asserts the two stay in sync.
KNOWN_PRIMITIVES = frozenset({
    "enforcing_workspaces_ratio", "inventory_enforcement_ratio", "agent_coverage",
    "flow_visibility_present", "connector_health", "scope_coverage_ratio",
})


def load_mapping(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Mapping file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {path}: {e}") from e

    fw = data.get("framework")
    if not isinstance(fw, dict):
        raise ValueError(f"{path}: missing 'framework' object")
    for k in REQUIRED_FRAMEWORK_KEYS:
        if not fw.get(k):
            raise ValueError(f"{path}: framework missing required key '{k}'")

    controls = data.get("controls")
    if not isinstance(controls, list) or not controls:
        raise ValueError(f"{path}: 'controls' must be a non-empty list")

    for c in controls:
        if not c.get("id"):
            raise ValueError(f"{path}: a control is missing 'id'")
        ev = c.get("evidence")
        if ev != "not_evidenceable" and ev not in KNOWN_PRIMITIVES:
            raise ValueError(
                f"{path}: control {c['id']} references unknown evidence '{ev}'. "
                f"Known primitives: {sorted(KNOWN_PRIMITIVES)} or 'not_evidenceable'."
            )
        if ev != "not_evidenceable" and "verdict_rule" not in c:
            raise ValueError(f"{path}: control {c['id']} missing 'verdict_rule'")
    return data


def _indet_if_bad(resp, path):
    s = resp.get("status")
    if s in (401, 403):
        return measurement(indeterminate=True, reason=f"capability missing: {path} (HTTP {s})")
    if s != 200:
        return measurement(indeterminate=True, reason=f"{path} returned HTTP {s}")
    return None


def _ratio(numerator, denominator, label):
    if denominator == 0:
        return measurement(indeterminate=True, reason=f"no {label} to measure (denominator 0)")
    r = numerator / denominator
    return measurement(value=r, display=f"{numerator}/{denominator} {label} ({r:.0%})")


def enforcing_workspaces_ratio(fetch, scope=None):
    path = "/openapi/v1/applications"
    resp = fetch("GET", path)
    bad = _indet_if_bad(resp, path)
    if bad:
        return bad
    apps = resp.get("data") or []
    if scope:
        apps = [a for a in apps if scope.lower() in (a.get("name", "").lower())]
    enforcing = sum(1 for a in apps if a.get("enforcement_enabled"))
    return _ratio(enforcing, len(apps), "workspaces enforcing")


def inventory_enforcement_ratio(fetch, scope=None):
    cpath = "/openapi/v1/inventory/count"
    cresp = fetch("GET", cpath)
    bad = _indet_if_bad(cresp, cpath)
    if bad:
        return bad
    total = (cresp.get("data") or {}).get("count", 0)
    spath = "/openapi/v1/inventory/search"
    body = {"filter": {"type": "eq", "field": "enforcement_status", "value": "enabled"},
            "dimensions": ["ip"], "limit": 0}
    sresp = fetch("POST", spath, body)
    bad = _indet_if_bad(sresp, spath)
    if bad:
        return bad
    enforcing = (sresp.get("data") or {}).get("total_count", 0)
    return _ratio(enforcing, total, "workloads enforcing")


def agent_coverage(fetch, scope=None):
    path = "/openapi/v1/sensors"
    resp = fetch("GET", path)
    bad = _indet_if_bad(resp, path)
    if bad:
        return bad
    sensors = resp.get("data") or []
    healthy = sum(1 for s in sensors if (s.get("sensor_status") or "").lower() == "active")
    return _ratio(healthy, len(sensors), "agents healthy")


def flow_visibility_present(fetch, scope=None):
    path = "/openapi/v1/flow_search/flows"
    body = {"t0": "-86400s", "t1": "now", "filter": {}, "limit": 1}
    resp = fetch("POST", path, body)
    bad = _indet_if_bad(resp, path)
    if bad:
        return bad
    results = (resp.get("data") or {}).get("results") or []
    present = "present" if results else "absent"
    return measurement(value=present, display=f"recent flows observed: {present}")


def connector_health(fetch, scope=None):
    path = "/openapi/v1/connectors"
    resp = fetch("GET", path)
    bad = _indet_if_bad(resp, path)
    if bad:
        return bad
    conns = resp.get("data") or []
    healthy = sum(1 for c in conns if (c.get("status") or "").lower() in ("active", "up", "healthy"))
    return _ratio(healthy, len(conns), "connectors healthy")


def scope_coverage_ratio(fetch, scope=None):
    spath = "/openapi/v1/scopes"
    sresp = fetch("GET", spath)
    bad = _indet_if_bad(sresp, spath)
    if bad:
        return bad
    scopes = sresp.get("data") or []
    cpath = "/openapi/v1/inventory/count"
    cresp = fetch("GET", cpath)
    bad = _indet_if_bad(cresp, cpath)
    if bad:
        return bad
    total = (cresp.get("data") or {}).get("count", 0)
    # Coarse v1: presence of any non-root scope tree is the signal; a precise
    # scoped-inventory ratio is deferred. Returns present/absent to avoid
    # overstating precision.
    present = "present" if len(scopes) > 1 else "absent"
    _ = total  # reserved for future precise rollup
    return measurement(value=present, display=f"defined scopes: {len(scopes)}")


PRIMITIVES = {
    "enforcing_workspaces_ratio": enforcing_workspaces_ratio,
    "inventory_enforcement_ratio": inventory_enforcement_ratio,
    "agent_coverage": agent_coverage,
    "flow_visibility_present": flow_visibility_present,
    "connector_health": connector_health,
    "scope_coverage_ratio": scope_coverage_ratio,
}


POINTERS = {
    "enforcing_workspaces_ratio": "/csw lifecycle",
    "inventory_enforcement_ratio": "/csw lifecycle",
    "agent_coverage": "/csw upgrade",
    "flow_visibility_present": "/csw connectors",
    "connector_health": "/csw triage",
    "scope_coverage_ratio": "/csw onboard",
}


def run_control(control, fetch):
    ev = control["evidence"]
    cid = control["id"]
    base = {"id": cid, "intent": control.get("intent", ""),
            "csw_capability": control.get("csw_capability", ""),
            "evidence_display": "", "pointer": "", "reason": ""}
    if ev == "not_evidenceable":
        base["status"] = "Not-evidenceable"
        base["pointer"] = "(manual)"
        return base
    meas = PRIMITIVES[ev](fetch, scope=control.get("scope_hint"))
    status = evaluate_verdict(ev, meas, control["verdict_rule"])
    base["status"] = status
    base["evidence_display"] = meas.get("display", "")
    base["reason"] = meas.get("reason") or ""
    if status in ("Gap", "Partial"):
        base["pointer"] = POINTERS.get(ev, "")
    return base


def run_framework(mapping, fetch):
    rows = [run_control(c, fetch) for c in mapping["controls"]]
    summary = {s: 0 for s in ALL_STATUSES}
    for r in rows:
        summary[r["status"]] = summary.get(r["status"], 0) + 1
    return {"summary": summary, "rows": rows}
