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
