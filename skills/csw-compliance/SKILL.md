---
name: csw-compliance
description: Use when the user asks for compliance evidence, control mapping, "are we PCI/NIST/CIS compliant", framework coverage, audit evidence, or "prove control X holds" against Cisco Secure Workload (CSW/Tetration). Runs per-framework control mappings against the live cluster and reports four-state evidence (Satisfied/Partial/Gap/Not-evidenceable). Read-only end-to-end — never proposes writes.
user-invocable: true
allowed-tools: Bash, Read
argument-hint: [framework-id] [optional scope]
---

# Cisco Secure Workload (CSW) Compliance Evidence

You produce **live compliance-evidence reports**: for each framework control, the
CSW capability that satisfies it AND live proof from this cluster. This is the
peer of `csw` and `csw-reports`; same plugin config, same API helper. It is
**read-only end-to-end, no exceptions.**

## Configuration

Same env vars as the other CSW skills: `CSW_API_URL`, `CSW_API_KEY`,
`CSW_API_SECRET`. Check with:
```bash
echo "URL: ${CSW_API_URL:-NOT SET}" && echo "KEY: ${CSW_API_KEY:+SET}" && echo "SECRET: ${CSW_API_SECRET:+SET}"
```

**Deployment models.** This skill works against both Cisco-hosted SaaS tenants and customer-managed self-hosted clusters. The helper auto-detects on first call (`CSW_DEPLOYMENT=auto`, default); set `CSW_DEPLOYMENT=saas|selfhosted` to skip the probe.

**What differs for this skill specifically:** none — every endpoint used by the compliance runner (`bin/csw_compliance.py`) is available on both deployments.

## Read-only discipline (Iron Law)

**This skill never proposes a write. No exceptions.** It evaluates controls and
points at remediation workflows; it never constructs a mutating call. If a report
shows a gap the user wants fixed, name the matching `/csw` workflow
(`/csw lifecycle`, `/csw onboard`, `/csw upgrade`, `/csw triage`) and stop. If you
find yourself building a POST/PUT/DELETE body to a mutating path: STOP, delete it,
point at the workflow.

## What this is NOT (boundary vs /csw audit)

- `/csw audit` = generic, framework-agnostic posture (coverage, enforcement, orphans).
- `/csw-compliance <framework>` = framework-SPECIFIC control evidence against a named standard.
Do not duplicate audit here; do not duplicate framework mapping in audit.

## Invocation

`/csw-compliance <framework-id> [scope]`. List available frameworks:
```bash
python3 "${CLAUDE_PLUGIN_ROOT}/bin/csw_compliance.py"
```
If the user gives no framework, run the above to list options and **ask which.
Do not pick a default.**

## Capability preflight

The runner needs READ tier on: `flow_inventory_query`, `app_policy_management`,
`user_role_scope_management`, `sensor_management`, `external_integration`. There is
no capability `whoami` endpoint. If a primitive's call returns 401/403, that
control is reported **Indeterminate (capability missing)** with the failing
endpoint named — it is never silently scored Gap.

## Running a report

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/bin/csw_compliance.py" <framework-id> [scope]
```
The runner emits the full markdown report (header, source attribution, standing
disclaimer, four-bucket summary, control table). Present its output verbatim;
do not re-score, re-rank, or add a "you are compliant" conclusion. The disclaimer
("CSW evidence status, not a compliance attestation") stands.

## Output rules

- Present the runner's markdown as-is. Markdown tables, operator tone, no emoji
  beyond the single ⚠ disclaimer marker.
- Not-evidenceable controls are always shown and counted — never hide them.
- For any Gap/Partial the user wants to act on, name the `Pointer` workflow and stop.

## Error handling

- 401/403 → control marked Indeterminate; tell the user which read capability is missing.
- 404 → resource missing OR endpoint not applicable on this deployment (cross-reference `skills/csw/api-reference.md` Deploy column); surface verbatim. 500 → suggest `/csw report` service health (self-hosted) or contact Cisco support (SaaS); connection failure → check `CSW_API_URL`.
- Always show HTTP status. No silent failures.

## Adding a framework

Drop a new `skills/csw-compliance/mappings/<id>.json` following the existing
schema (framework block + controls referencing registered evidence primitives).
No code change. Validate by running the skill against the new id.
