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
