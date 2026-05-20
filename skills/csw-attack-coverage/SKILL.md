---
name: csw-attack-coverage
description: Use when the user asks how Cisco Secure Workload (CSW/Tetration) maps to MITRE ATT&CK, which adversary techniques CSW mitigates or detects, ATT&CK coverage/heatmap, "what techniques are we covered for", or technique-level defensive coverage. Reports CSW mitigation/detection COVERAGE against live cluster state (Covered/Partial/Not-covered/Out-of-scope). Read-only end-to-end — never proposes writes. This is coverage, NOT compliance.
user-invocable: true
allowed-tools: Bash, Read
argument-hint: [matrix-id] [optional scope]
---

# Cisco Secure Workload (CSW) — MITRE ATT&CK Coverage

You produce **adversary-technique coverage reports**: for each ATT&CK technique
mapped to CSW, the capability that addresses it AND a live signal from this
cluster that the capability is actually in place. Peer of `csw`, `csw-reports`,
and `csw-compliance`; same plugin config, same API helper, **read-only end-to-end.**

## Coverage is NOT compliance, and NOT a guarantee

- **Covered** = CSW provides a mitigation/detection *signal* for the technique and
  the underlying capability is live on this cluster. It is **not** proof the
  technique is prevented or detected in any specific intrusion.
- **Out-of-scope** = the technique is outside CSW's reach (e.g., phishing,
  on-host code execution, credential abuse, physical) — always shown, never hidden.
- Do not tell the user they are "protected from" a technique. Say CSW provides
  coverage/visibility for it. The standing disclaimer in the report says this; keep it.

## Configuration

Same env vars as the other CSW skills: `CSW_API_URL`, `CSW_API_KEY`,
`CSW_API_SECRET`. Check with:
```bash
echo "URL: ${CSW_API_URL:-NOT SET}" && echo "KEY: ${CSW_API_KEY:+SET}" && echo "SECRET: ${CSW_API_SECRET:+SET}"
```

## Read-only discipline (Iron Law)

**This skill never proposes a write. No exceptions.** It reports coverage and
points at remediation workflows; it never constructs a mutating call. For a
Not-covered/Partial technique the user wants to close, name the matching `/csw`
workflow (the report's `Close-gap` column: `/csw lifecycle`, `/csw onboard`,
`/csw upgrade`, `/csw connectors`) and stop.

## What this is NOT

- `/csw-compliance <framework>` = compliance-control evidence against a named standard.
- `/csw-attack-coverage <matrix>` = adversary-technique coverage. Different vocabulary
  (Covered/Partial/Not-covered/Out-of-scope), different framing. Do not conflate them.

## Invocation

`/csw-attack-coverage <matrix-id> [scope]`. List available matrices:
```bash
python3 "${CLAUDE_PLUGIN_ROOT}/bin/csw_attack.py"
```
If the user gives no matrix, run the above to list options and **ask which.
Do not pick a default.**

## Capability preflight

The runner needs READ tier on: `flow_inventory_query`, `app_policy_management`,
`user_role_scope_management`, `sensor_management`. There is no capability `whoami`
endpoint. If a primitive's call returns 401/403, that technique is reported
**Indeterminate (capability missing)** with the failing endpoint named — never
silently scored Not-covered.

## Running a report

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/bin/csw_attack.py" <matrix-id> [scope]
```
Present the runner's markdown verbatim (header, source attribution, standing
disclaimer, five-bucket summary, technique table). Do not re-score, re-rank, or
add a "you are protected" conclusion.

## Output rules

- Present the runner's markdown as-is. Markdown tables, operator tone, no emoji
  beyond the single ⚠ disclaimer marker.
- Out-of-scope techniques are always shown and counted — never hide them.
- For any Not-covered/Partial the user wants to close, name the `Close-gap` workflow and stop.

## Error handling

- 401/403 → technique marked Indeterminate; tell the user which read capability is missing.
- 404 → surface; 500 → suggest `/csw report` service health; connection failure → check `CSW_API_URL`.
- Always show HTTP status. No silent failures.

## Adding a matrix

Drop a new `skills/csw-attack-coverage/mappings/<id>.json` following the existing
schema (framework block + `controls` list of techniques referencing registered
evidence primitives, or `out_of_scope`). No code change. Validate by running the
skill against the new id.
