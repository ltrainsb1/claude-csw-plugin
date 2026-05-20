#!/usr/bin/env python3
"""MITRE ATT&CK coverage runner. Read-only. stdlib only.

Reports CSW mitigation/detection **coverage** for adversary techniques. This is
COVERAGE, not compliance, and NOT proof a technique is prevented or detected.

Reuses the read-only evidence primitives, the HMAC fetch builder, the condition
parser, and the strict mapping loader from csw_compliance.py — only the report
vocabulary (Covered / Partial / Not-covered / Out-of-scope) and the header differ.

IRON LAW: read-only. Never issues a mutating call (inherited from the shared
primitives, which only GET + the two read-style POST search endpoints).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from csw_compliance import (  # noqa: E402  (path set above)
    PRIMITIVES, _match, build_fetch, _cell, load_mapping, MappingNotFound,
)

# Evidence value that means "CSW cannot address this technique" (analogue of
# compliance's not_evidenceable). Kept distinct so ATT&CK JSON reads naturally.
OUT_OF_SCOPE = "out_of_scope"

ALL_STATUSES = ["Covered", "Partial", "Not-covered", "Out-of-scope", "Indeterminate"]

# canonical verdict key -> coverage display label
LABELS = {"satisfied": "Covered", "partial": "Partial", "gap": "Not-covered"}

# How to CLOSE a coverage gap — points at the gated /csw remediation workflows.
POINTERS = {
    "enforcing_workspaces_ratio": "/csw lifecycle",
    "inventory_enforcement_ratio": "/csw lifecycle",
    "agent_coverage": "/csw upgrade",
    "flow_visibility_present": "/csw connectors",
    "connector_health": "/csw triage",
    "scope_coverage_ratio": "/csw onboard",
}

MAPPINGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "skills", "csw-attack-coverage", "mappings")


def coverage_status(evidence_name, meas, verdict_rule):
    if evidence_name == OUT_OF_SCOPE:
        return "Out-of-scope"
    if meas.get("indeterminate"):
        return "Indeterminate"
    value = meas.get("value")
    for key in ("satisfied", "partial"):
        cond = verdict_rule.get(key)
        if cond is not None and _match(value, cond):
            return LABELS[key]
    return LABELS.get(verdict_rule.get("else", "gap"), "Not-covered")


def run_technique(control, fetch):
    ev = control["evidence"]
    base = {"id": control["id"], "intent": control.get("intent", ""),
            "csw_capability": control.get("csw_capability", ""),
            "evidence_display": "", "pointer": "", "reason": ""}
    if ev == OUT_OF_SCOPE:
        base["status"] = "Out-of-scope"
        base["pointer"] = "(n/a)"
        return base
    try:
        meas = PRIMITIVES[ev](fetch, scope=control.get("scope_hint"))
    except Exception as e:  # one bad row must never crash the whole matrix
        base["status"] = "Indeterminate"
        base["reason"] = f"primitive error: {e}"
        return base
    status = coverage_status(ev, meas, control["verdict_rule"])
    base["status"] = status
    base["evidence_display"] = meas.get("display", "")
    base["reason"] = meas.get("reason") or ""
    if status in ("Not-covered", "Partial"):
        base["pointer"] = POINTERS.get(ev, "")
    return base


def run_matrix(mapping, fetch):
    rows = [run_technique(c, fetch) for c in mapping["controls"]]
    summary = {s: 0 for s in ALL_STATUSES}
    for r in rows:
        summary[r["status"]] = summary.get(r["status"], 0) + 1
    return {"summary": summary, "rows": rows}


def render_markdown(fw, results, cluster_url):
    s = results["summary"]
    lines = []
    lines.append(f"ATT&CK COVERAGE — {fw['name']} {fw['version']} — {cluster_url}")
    lines.append(f"Source: {fw['source']} (retrieved {fw['retrieved']})")
    lines.append(f"⚠ {fw['disclaimer']} Coverage means CSW provides a mitigation/detection "
                 f"signal for the technique — NOT proof it is prevented or detected. "
                 f"Techniques outside CSW's reach are shown as \"Out-of-scope\".")
    lines.append("")
    lines.append("Techniques evaluated: {total} | Covered: {Covered} | Partial: {Partial} | "
                 "Not-covered: {Not-covered} | Out-of-scope: {Out-of-scope} | "
                 "Indeterminate: {Indeterminate}".format(total=sum(s.values()), **s))
    lines.append("")
    lines.append("| Technique | How CSW helps | CSW capability | Live coverage signal | Status | Close-gap |")
    lines.append("|-----------|---------------|----------------|----------------------|--------|-----------|")
    for r in results["rows"]:
        evidence = r["evidence_display"] or (r["reason"] if r["status"] == "Indeterminate" else "—")
        pointer = r["pointer"] or "—"
        cells = [r["id"], r["intent"], r["csw_capability"], evidence, r["status"], pointer]
        lines.append("| " + " | ".join(_cell(c) for c in cells) + " |")
    return "\n".join(lines)


def available_matrices():
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
        f"Unknown matrix '{arg}'. Available: {available_matrices() or '(none)'}")


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("Usage: csw_attack.py <matrix-id|path.json> [scope]")
        print(f"Available matrices: {available_matrices() or '(none)'}")
        return 2
    try:
        path = resolve_mapping_path(argv[0])
    except MappingNotFound as e:
        print(str(e))
        return 2
    scope = (argv[1].strip() or None) if len(argv) > 1 else None
    mapping = load_mapping(path, na_token=OUT_OF_SCOPE)
    if scope:
        for c in mapping["controls"]:
            c.setdefault("scope_hint", scope)
    cluster_url = os.environ.get("CSW_API_URL", "<cluster>")
    results = run_matrix(mapping, build_fetch())
    print(render_markdown(mapping["framework"], results, cluster_url))
    return 0


if __name__ == "__main__":
    sys.exit(main())
