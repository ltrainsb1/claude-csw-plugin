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


def _parse_condition(cond):
    """Parse a verdict condition into (op, threshold). Raises ValueError/TypeError
    on anything unparseable, so it doubles as a load-time validator."""
    if cond in ("present", "absent"):
        return (cond, None)
    if not isinstance(cond, str):
        raise TypeError(f"verdict condition must be a string, got {type(cond).__name__}")
    for op in (">=", "<=", ">", "<", "=="):
        if cond.startswith(op):
            return (op, float(cond[len(op):]))  # ValueError if not numeric
    raise ValueError(f"Unparseable verdict condition: {cond!r}")


def _match(value, cond):
    op, threshold = _parse_condition(cond)
    if op in ("present", "absent"):
        return value == op
    v = float(value)
    return {
        ">=": v >= threshold, "<=": v <= threshold,
        ">": v > threshold, "<": v < threshold, "==": v == threshold,
    }[op]


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


def load_mapping(path, na_token="not_evidenceable"):
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
        if not isinstance(c, dict):
            raise ValueError(f"{path}: every control must be an object, got {type(c).__name__}")
        if not c.get("id"):
            raise ValueError(f"{path}: a control is missing 'id'")
        ev = c.get("evidence")
        if ev != na_token and ev not in KNOWN_PRIMITIVES:
            raise ValueError(
                f"{path}: control {c['id']} references unknown evidence '{ev}'. "
                f"Known primitives: {sorted(KNOWN_PRIMITIVES)} or '{na_token}'."
            )
        if ev != na_token:
            rule = c.get("verdict_rule")
            if rule is None:
                raise ValueError(f"{path}: control {c['id']} missing 'verdict_rule'")
            _validate_verdict_rule(rule, c["id"], path)
    return data


def _validate_verdict_rule(rule, cid, path):
    """Fail at load (not at eval) on a malformed verdict_rule, so the documented
    'drop in a JSON file, validate by running' workflow gives actionable errors."""
    if not isinstance(rule, dict):
        raise ValueError(f"{path}: control {cid} verdict_rule must be an object")
    for key in ("satisfied", "partial"):
        if key in rule:
            try:
                _parse_condition(rule[key])
            except (ValueError, TypeError) as e:
                raise ValueError(f"{path}: control {cid} verdict_rule.{key}: {e}") from e


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


def _require_list(resp, path):
    """For list endpoints. resp has already passed _indet_if_bad (HTTP 200).
    Returns (list, None) or (None, indeterminate-measurement) if the 200 body
    is not a list — never coerce an unexpected shape into an empty list."""
    data = resp.get("data")
    if not isinstance(data, list):
        return None, measurement(indeterminate=True,
                                 reason=f"{path}: 200 but expected a list, got {type(data).__name__}")
    return data, None


def _require_number(resp, key, path):
    """For count endpoints. Returns (number, None) or (None, indeterminate).
    A 200 that lacks the key, or whose key is non-numeric, is Indeterminate —
    NOT silently treated as 0 (which would manufacture a false 0%/Gap)."""
    data = resp.get("data")
    if not isinstance(data, dict) or key not in data:
        return None, measurement(indeterminate=True, reason=f"{path}: 200 but missing '{key}'")
    val = data[key]
    if not isinstance(val, (int, float)) or isinstance(val, bool):
        return None, measurement(indeterminate=True, reason=f"{path}: '{key}' is not numeric")
    return val, None


def enforcing_workspaces_ratio(fetch, scope=None):
    path = "/openapi/v1/applications"
    resp = fetch("GET", path)
    bad = _indet_if_bad(resp, path)
    if bad:
        return bad
    apps, bad = _require_list(resp, path)
    if bad:
        return bad
    if scope:
        apps = [a for a in apps if isinstance(a, dict) and scope.lower() in (a.get("name", "").lower())]
    enforcing = sum(1 for a in apps if isinstance(a, dict) and a.get("enforcement_enabled"))
    return _ratio(enforcing, len(apps), "workspaces enforcing")


def inventory_enforcement_ratio(fetch, scope=None):
    cpath = "/openapi/v1/inventory/count"
    cresp = fetch("GET", cpath)
    bad = _indet_if_bad(cresp, cpath)
    if bad:
        return bad
    total, bad = _require_number(cresp, "count", cpath)
    if bad:
        return bad
    spath = "/openapi/v1/inventory/search"
    body = {"filter": {"type": "eq", "field": "enforcement_status", "value": "enabled"},
            "dimensions": ["ip"], "limit": 0}
    sresp = fetch("POST", spath, body)
    bad = _indet_if_bad(sresp, spath)
    if bad:
        return bad
    enforcing, bad = _require_number(sresp, "total_count", spath)
    if bad:
        return bad
    return _ratio(enforcing, total, "workloads enforcing")


def agent_coverage(fetch, scope=None):
    path = "/openapi/v1/sensors"
    resp = fetch("GET", path)
    bad = _indet_if_bad(resp, path)
    if bad:
        return bad
    sensors, bad = _require_list(resp, path)
    if bad:
        return bad
    healthy = sum(1 for s in sensors
                  if isinstance(s, dict) and (s.get("sensor_status") or "").lower() == "active")
    return _ratio(healthy, len(sensors), "agents healthy")


def flow_visibility_present(fetch, scope=None):
    path = "/openapi/v1/flow_search/flows"
    body = {"t0": "-86400s", "t1": "now", "filter": {}, "limit": 1}
    resp = fetch("POST", path, body)
    bad = _indet_if_bad(resp, path)
    if bad:
        return bad
    data = resp.get("data")
    if not isinstance(data, dict) or "results" not in data:
        return measurement(indeterminate=True, reason=f"{path}: 200 but missing 'results'")
    present = "present" if data["results"] else "absent"
    return measurement(value=present, display=f"recent flows observed: {present}")


def connector_health(fetch, scope=None):
    path = "/openapi/v1/connectors"
    resp = fetch("GET", path)
    bad = _indet_if_bad(resp, path)
    if bad:
        return bad
    conns, bad = _require_list(resp, path)
    if bad:
        return bad
    healthy = sum(1 for c in conns
                  if isinstance(c, dict) and (c.get("status") or "").lower() in ("active", "up", "healthy"))
    return _ratio(healthy, len(conns), "connectors healthy")


def scope_coverage_ratio(fetch, scope=None):
    # Coarse v1: presence of any non-root scope tree is the signal; a precise
    # scoped-inventory ratio is deferred. Returns present/absent to avoid
    # overstating precision. (No inventory/count call — its result was unused.)
    spath = "/openapi/v1/scopes"
    sresp = fetch("GET", spath)
    bad = _indet_if_bad(sresp, spath)
    if bad:
        return bad
    scopes, bad = _require_list(sresp, spath)
    if bad:
        return bad
    present = "present" if len(scopes) > 1 else "absent"
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
    try:
        meas = PRIMITIVES[ev](fetch, scope=control.get("scope_hint"))
    except Exception as e:  # one bad row must never crash the whole report
        base["status"] = "Indeterminate"
        base["reason"] = f"primitive error: {e}"
        return base
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


def render_markdown(fw, results, cluster_url):
    s = results["summary"]
    lines = []
    lines.append(f"COMPLIANCE EVIDENCE — {fw['name']} {fw['version']} — {cluster_url}")
    lines.append(f"Source: {fw['source']} (retrieved {fw['retrieved']})")
    lines.append(f"⚠ {fw['disclaimer']} Process/people controls are out of scope "
                 f"and shown as \"Not-evidenceable\".")
    lines.append("")
    lines.append("Controls evaluated: {total} | Satisfied: {Satisfied} | Partial: {Partial} | "
                 "Gap: {Gap} | Not-evidenceable: {Not-evidenceable} | Indeterminate: {Indeterminate}".format(
                     total=sum(s.values()), **s))
    lines.append("")
    lines.append("| Control | Intent | CSW capability | Live evidence | Status | Pointer |")
    lines.append("|---------|--------|----------------|---------------|--------|---------|")
    for r in results["rows"]:
        evidence = r["evidence_display"] or (r["reason"] if r["status"] == "Indeterminate" else "—")
        pointer = r["pointer"] or "—"
        cells = [r["id"], r["intent"], r["csw_capability"], evidence, r["status"], pointer]
        lines.append("| " + " | ".join(_cell(c) for c in cells) + " |")
    return "\n".join(lines)


def _cell(text):
    """Make a value safe for a markdown table cell (escape pipes, flatten newlines)."""
    return str(text).replace("|", "\\|").replace("\n", " ")


MAPPINGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "skills", "csw-compliance", "mappings")


class MappingNotFound(Exception):
    pass


def available_frameworks():
    if not os.path.isdir(MAPPINGS_DIR):
        return []
    return sorted(f[:-5] for f in os.listdir(MAPPINGS_DIR) if f.endswith(".json"))


def resolve_mapping_path(arg):
    if arg.endswith(".json") and os.path.exists(arg):
        return arg
    candidate = os.path.join(MAPPINGS_DIR, f"{arg}.json")
    if os.path.exists(candidate):
        return candidate
    raise MappingNotFound(
        f"Unknown framework '{arg}'. Available: {available_frameworks() or '(none)'}")


def build_fetch():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from csw_api import make_request  # lazy: only when hitting a real cluster
    return lambda method, path, body=None: make_request(method, path, body=body)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("Usage: csw_compliance.py <framework-id|path.json> [scope]")
        print(f"Available frameworks: {available_frameworks() or '(none)'}")
        return 2
    try:
        path = resolve_mapping_path(argv[0])
    except MappingNotFound as e:
        print(str(e))
        return 2
    scope = (argv[1].strip() or None) if len(argv) > 1 else None
    mapping = load_mapping(path)
    if scope:  # coarse scope filter applies via scope_hint override on every control
        for c in mapping["controls"]:
            c.setdefault("scope_hint", scope)
    cluster_url = os.environ.get("CSW_API_URL", "<cluster>")
    results = run_framework(mapping, build_fetch())
    print(render_markdown(mapping["framework"], results, cluster_url))
    return 0


if __name__ == "__main__":
    sys.exit(main())
