---
name: csw-reports
description: Use when the user asks for posture, drift, top-N noisy workspaces, onboarding gaps, "what's not enforced", "what's stale", "where to look next", or focused single-question operator reports against Cisco Secure Workload (CSW/Tetration). All read-only — never proposes writes.
user-invocable: true
allowed-tools: Bash, Read, Write
argument-hint: [posture|drift|noisy|gaps] [optional scope filter]
---

# Cisco Secure Workload (CSW) Operator Reports

You produce focused single-question operator reports against the live CSW cluster. This skill is the peer of the main `csw` skill (which lives at `skills/csw/SKILL.md`); they share the same plugin config and the same API helper, but this skill is invoked separately via `/csw-reports <type>` and operates under a stricter discipline: **read-only end-to-end, no exceptions.**

## Configuration

This skill requires the same environment variables as the main CSW skill:

- `CSW_API_URL` — Cluster URL (e.g., `https://csw.example.com`)
- `CSW_API_KEY` — API key (hex string)
- `CSW_API_SECRET` — API secret (hex string)

If any are missing, prompt the user to set them. Check with:
```bash
echo "URL: ${CSW_API_URL:-NOT SET}" && echo "KEY: ${CSW_API_KEY:+SET}" && echo "SECRET: ${CSW_API_SECRET:+SET}"
```

## Authentication

CSW uses HMAC digest authentication. All API calls must be made using the helper script at `${CLAUDE_PLUGIN_ROOT}/bin/csw_api.py`:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/bin/csw_api.py" GET /openapi/v1/applications
python3 "${CLAUDE_PLUGIN_ROOT}/bin/csw_api.py" POST /openapi/v1/policies/stats/enforced '{"application_id": "..."}'
```

## Read-only discipline (Iron Law)

**This skill never proposes a write. No exceptions.**

If the report surfaces a problem the user wants fixed (e.g., "the noisy report shows workspace X has a catch-all DENY absorbing 90% of traffic — fix it"), do NOT propose a CSW write. Instead:

1. Identify the matching workflow in the existing `csw` skill (e.g., `/csw lifecycle`, `/csw investigate`, `/csw onboard`).
2. Tell the user: "this isn't something I can do — invoke `/csw <workflow>` to take that action through the gated workflow."
3. Stop.

The existing CSW skill's gate is the only place writes go through. This skill stays out of that surface entirely.

If you find yourself constructing a `POST /openapi/v1/applications/{ws}/policies` body or a `PUT /openapi/v1/policies/{id}` body or any mutating call: STOP. Delete what you wrote. Tell the user which workflow to invoke instead.

## Invocation

`/csw-reports <type>` where `<type>` is one of:

- `posture` — point-in-time coverage and enforcement metrics
- `drift` — workspace + agent staleness
- `noisy` — top-N operational pain points
- `gaps` — onboarding incompleteness

Optional second argument scopes the report (e.g., `/csw-reports drift production` limits to a scope tree).

If the user invokes `/csw-reports` with no subtype: list the 4 options and ask which. **Do not pick a default.**

## Capability preflight

Before running any report, verify the user's CSW key has the required read tiers. If a tier is missing, the report stops at the boundary and tells the user which capability is needed for the rest. **No retry, no fallback to less data without flagging.**

| Report | Required (read tier on each) |
|---|---|
| `posture` | `flow_inventory_query`, `user_role_scope_management`, `app_policy_management` |
| `drift` | `app_policy_management`, `sensor_management` |
| `noisy` | `app_policy_management` |
| `gaps` | `flow_inventory_query`, `user_role_scope_management`, `app_policy_management` |

The skill does not introspect the user's key (CSW has no `whoami` endpoint that returns capabilities). Instead: when a 401/403 surfaces mid-report, stop and report which endpoint failed. The mapping above tells the user which capability is missing.

## Output format

- **Markdown tables, operator-tone, technical language.**
- Each report opens with a 1-3 line summary block (the headline numbers) followed by per-dimension tables.
- No emoji. No charts. No JSON. No CSV. Pure markdown that scans in 30 seconds.
- Counts always show absolute and percentage where both apply.

## No drill-down

Each report is one-shot. No "type drill <N>" follow-ups, no interactive expansion. If the analyst needs deeper detail on a row, they invoke a different command (`/csw scopes <name>`, `/csw policy <ws>`, `/csw agents <host>`, etc.). The report's job is "tell me where to look"; the existing read commands' job is "show me that thing in detail." Keep the boundary clean.

## Report 1 — `csw-reports posture`

**What it provides:** point-in-time coverage and enforcement metrics across the cluster.

**Read-only discovery:**
1. `GET /openapi/v1/scopes` — full scope tree.
2. `POST /openapi/v1/inventory/count` with no filter → total inventory count. Then per-scope: `POST /openapi/v1/inventory/count` with the scope's query body.
3. `GET /openapi/v1/applications` — workspace list with `enforcement_enabled`, `enforced_version`, `latest_adm_version`.
4. `POST /openapi/v1/inventory/search` with body `{"filter": {}, "dimensions": ["ip", "enforcement_status"], "limit": 0}` (or low limit) — returns workload-level enforcement state. `enforcement_status` is an inventory dimension per `api-reference.md`, not a sensor field.

**Compute:**
- % inventory covered by any scope (sum of per-scope counts ÷ total inventory; cap at 100% if scopes overlap).
- % workspaces enforcing (count where `enforcement_enabled=true` ÷ total workspaces).
- % workloads in enforcement mode (count where inventory `enforcement_status=enabled` ÷ total inventory).
- Per-scope-tree breakdown of all three.

**Output structure:**
```
POSTURE — <cluster URL>
Total inventory: <N>; covered by scope: <M> (<P>%)
Workspaces: <W> total; enforcing: <E> (<P>%)
Workloads: <N> total; in enforcement mode: <En> (<P>%)

By scope tree:
  | Scope | Inventory | % covered | Workspaces enforcing | Workloads enforcing |
  |-------|-----------|-----------|---------------------|---------------------|
  | ...   | ...       | ...       | ...                 | ...                 |
```

Cap per-scope breakdown at top 25 by inventory count if there are more, with "showing top 25 of N" note.

## Report 2 — `csw-reports drift`

**What it provides:** divergence between intended and actual state.

**Read-only discovery:**
1. `GET /openapi/v1/applications` — workspaces with `enforcement_enabled`, `enforced_version`, `latest_adm_version`.
2. `GET /openapi/v1/sensors` — agents with `current_sw_version`, `host_name`.
3. `GET /openapi/v1/software/versions` — available agent software versions, latest first.

**Default thresholds (shown in report header so user can recalibrate):**
- Workspace stale if `enforced_version` lags `latest_adm_version` by >1 version.
- Agent stale if `current_sw_version` is more than 2 versions behind the latest available.

**Output structure:**
```
DRIFT — <cluster URL>
Thresholds: workspace lag >1 version; agent lag >2 versions.
Workspaces drifted: <W>; agents drifted: <A>

Workspace drift (sorted by lag):
  | Workspace | Enforced version | Latest analyzed | Versions behind | Action |
  |-----------|------------------|-----------------|-----------------|--------|

Agent drift (sorted by lag):
  | Agent | Hostname | Current version | Latest available | Versions behind |
  |-------|----------|-----------------|------------------|-----------------|
```

Each row's `Action` column points at `/csw lifecycle <ws>` for workspace drift or `/csw upgrade` for agent drift.

**Out of scope:**
- Scope-query drift (would require external baseline storage; deferred per design).
- Date-based staleness ("workspace not analyzed in >N days") — would require a `last_adm_run_at`-equivalent field that isn't documented in `api-reference.md`. Version-lag is the operationally-equivalent signal.

## Report 3 — `csw-reports noisy`

**What it provides:** top-N operational pain points — workspaces likely to need attention.

**Read-only discovery:**
1. `GET /openapi/v1/applications` — workspace list.
2. For each workspace: `POST /openapi/v1/policies/stats/enforced` with body `{"application_id": "<ws_id>"}` (or workspace-id-equivalent per `api-reference.md`). Returns hit counts per policy.

**Rankings (default top 10 per dimension):**

1. **Total hit count** — busiest workspaces by total policy hits in the analyzed window.
2. **DENY-hit ratio** — % of hits that DENY. High DENY ratio in an enforcing workspace = lots of blocked traffic; investigate intent.
3. **Catch-all DENY absorption** — for each workspace, hits on the lowest-priority DENY policy (the catch-all). High values suggest legitimate traffic falling through gaps in the ALLOW set.
4. **Policy count** — workspaces with the most policies; often correlates with technical debt or over-engineering.

**Output structure:**
```
NOISY — <cluster URL>
Discovered <W> workspaces; top 10 per dimension below.

Top 10 by total hit count:
  | Workspace | Total hits | Top policy | Top policy hits |

Top 10 by DENY-hit ratio:
  | Workspace | DENY % | Total hits | DENY hits |

Top 10 by catch-all DENY absorption:
  | Workspace | Catch-all hits | % of total | Investigate? |

Top 10 by policy count:
  | Workspace | Policy count | Notable |
```

If any workspace fails its `policies/stats/enforced` call, list it under a "Skipped (call failed)" footer and continue with the rest.

## Report 4 — `csw-reports gaps`

**What it provides:** onboarding incompleteness — what's missing or misconfigured for full coverage.

**Read-only discovery:**
1. `GET /openapi/v1/scopes` — full scope tree.
2. `GET /openapi/v1/applications` — workspaces.
3. `GET /openapi/v1/inventory_filters` — all filters.
4. `POST /openapi/v1/inventory/search` with body `{"filter": {}, "dimensions": ["ip", "hostname", "enforcement_status"], "limit": 0}` — workload-level enforcement state. `enforcement_status` is an inventory dimension per `api-reference.md`.

**Cross-references:**
- **Scopes without workspaces:** scope_id present in scope list but no workspace has it as `app_scope_id`.
- **Workspaces without policies:** workspace_id present but `GET /openapi/v1/applications/{id}/policies` returns 0.
- **Filters without policies:** filter_id present but no policy references it as `consumer_filter_id` or `provider_filter_id`.
- **Workloads not enforcing despite scope intent:** workload's IP matches a scope whose primary workspace has `enforcement_enabled=true`, but the workload's `enforcement_status` (from inventory dimension) is not enabled.

**Output structure:**
```
GAPS — <cluster URL>
Scopes without workspaces: <N>; workspaces without policies: <N>;
filters without policies: <N>; workloads not enforcing despite scope intent: <N>

Scopes without workspaces:
  | Scope | Parent | Inventory match count | Suggested workflow |
  |-------|--------|----------------------|--------------------|
  All rows suggest /csw onboard.

Workspaces without policies:
  | Workspace | Scope | Created | Suggested workflow |
  All rows suggest /csw lifecycle or /csw investigate (depending on whether ADM has run).

Filters without policies:
  | Filter | Scope | Query | Suggested action |
  All rows: "review whether filter is still needed; consider removing".

Workloads not enforcing despite scope intent:
  | Workload | Hostname | IP | Scope | Workspace | Reason |
  All rows suggest investigating workload sensor health or scope membership via /csw agents <host> or /csw inventory <ip>.
```

## Performance

- Each report targets <30 seconds on a 500-workspace / 5000-agent cluster.
- Larger environments: cap at top-N (default 25 for posture's per-scope breakdown, 10 for noisy's rankings) with explicit "showing N of M, sorted by …" notes.
- No pagination — the report is not a workspace explorer.

## Error handling

- 401/403 mid-report → stop, report which endpoint failed, point at the capability mapping in this skill.
- 404 → resource doesn't exist; surface in the report (e.g., "workspace X listed in applications but details endpoint returned 404").
- 500 → CSW cluster issue; suggest checking service health (`/csw report` from the main skill includes this).
- Connection failure → verify `CSW_API_URL` is correct and reachable.
- Always show HTTP status + reason from CSW. No silent failures.

## Composition with the main CSW skill

- **No overlap.** Different skill, different invocation, different shape.
- **No shared code.** This skill copy-references endpoints; it doesn't import or extend the existing skill.
- **The user picks based on need.** `/csw audit` is the comprehensive read-only audit; `/csw-reports <type>` is one focused question at a time.
- **Reports point at the existing skill's workflows for remediation** — the gaps report's `Suggested workflow` column names `/csw onboard`, `/csw lifecycle`, etc. Reports never invoke writes themselves.
