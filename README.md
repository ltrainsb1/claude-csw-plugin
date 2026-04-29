# CSW Plugin for Claude Code

A Claude Code plugin for querying the Cisco Secure Workload (CSW/Tetration) API. Provides environment reports, policy analysis, scope inspection, flow search, and workload inventory.

## Installation

Add to your Claude Code settings (`~/.claude/settings.json` or project `.claude/settings.json`):

```json
{
  "enabledPlugins": {
    "csw": {
      "source": {
        "source": "git",
        "url": "https://github.com/ltrainsb1/claude-csw-plugin.git"
      }
    }
  }
}
```

## Configuration

Set the following environment variables:

```bash
export CSW_API_URL="https://your-cluster.tetrationcloud.com"
export CSW_API_KEY="your-api-key"
export CSW_API_SECRET="your-api-secret"
```

Or configure via Claude Code settings (`~/.claude/settings.local.json`):

```json
{
  "env": {
    "CSW_API_URL": "https://your-cluster.tetrationcloud.com",
    "CSW_API_KEY": "your-api-key",
    "CSW_API_SECRET": "your-api-secret"
  }
}
```

### SSL Verification

For clusters with self-signed certificates, set:

```bash
export CSW_VERIFY_SSL=false
```

## Read-only commands

These produce reports against the live CSW cluster. None propose writes; none invoke the gate.

### `/csw report` — Environment Overview Report
- **What it provides:** comprehensive single-shot report covering scopes, inventory count, agents, connectors, orchestrators, workspaces, service health, VRFs.
- **Endpoints:** `GET /openapi/v1/app_scopes`, `POST /openapi/v1/inventory/count`, `GET /openapi/v1/sensors`, `GET /openapi/v1/connectors`, `GET /openapi/v1/orchestrators`, `GET /openapi/v1/applications`, `GET /openapi/v1/service_health`, `GET /openapi/v1/vrfs`.
- **When to use:** first-time orientation against a cluster; sanity check after a change; periodic health snapshot.
- **When NOT to use:** when you need any one detail — use the targeted command instead.

### `/csw scopes [optional name]` — Scope Detail Report
- **What it provides:** scope hierarchy (parent/child), query definitions, child counts, policy priority order. Drills into one scope if named.
- **Endpoints:** `GET /openapi/v1/app_scopes`, plus per-scope detail.
- **When to use:** understanding segmentation hierarchy, policy ordering, query shapes.

### `/csw policy [scope or workspace]` — Policy Analysis
- **What it provides:** policy listing for a workspace, including consumer/provider filters, action (ALLOW/DENY), L4 params, priority. Optional flow analysis if src/dst/port given.
- **Endpoints:** `GET /openapi/v1/applications`, `GET /openapi/v1/applications/{id}/details`, `GET /openapi/v1/applications/{id}/policies`, `POST /policies/{rootScopeID}/quick_analysis`, `POST /policies/stats/enforced`.

### `/csw filters [optional name]` — Filter Detail Report
- **What it provides:** inventory filters with name, scope, query JSON, public/private status. Optional validate of one filter's match count.
- **Endpoints:** `GET /openapi/v1/inventory_filters`, `POST /openapi/v1/inventory_filters/validate`.

### `/csw connectors` — Connector & Orchestrator Report
- **What it provides:** list of connectors and orchestrators with type, status, config; F5 BIG-IP / Kubernetes / vCenter integration health; Secure Connector tunnel status.
- **Endpoints:** `GET /openapi/v1/connectors`, `GET /openapi/v1/connectors/types`, `GET /openapi/v1/orchestrators`, `GET /openapi/v1/connector/status`.

### `/csw inventory [search query]` — Workload Inventory Search
- **What it provides:** workloads matching a query (by IP, hostname, OS, label). Returns hostname, OS, agent version, labels, scope membership, enforcement state.
- **Endpoints:** `POST /openapi/v1/inventory/search`, `POST /openapi/v1/inventory/dimensions`.

### `/csw flows [src] [dst] [port]` — Flow Search
- **What it provides:** observed flows over a time window (default last 1h). Returns 5-tuple, action (allowed/denied), policy match, byte/packet counts. Top-N talkers if requested.
- **Endpoints:** `POST /openapi/v1/flow_search/flows`, `POST /openapi/v1/flow_search/topn`.

### `/csw agents [hostname or IP]` — Agent/Sensor Report
- **What it provides:** deployed agents with platform, version, enforcement mode, last check-in, config status. Filterable by host/IP.
- **Endpoints:** `GET /openapi/v1/sensors`, `GET /openapi/v1/software/versions`.

## Workflows (7)

These are guided multi-step flows: read-only discovery → single recommended next step → if the next step is a write, route through the Write Actions gate. Each write requires its own per-call approval phrase (`approve <tier> <short-id>`).

### `/csw lifecycle [workspace]` — Policy Lifecycle
- **What it provides:** ADM diff review (enforced vs analyzed), hit-stat sanity check, then a recommended next step — publish, fresh ADM run, enable enforcement, or disable enforcement.
- **Discovery:** `GET /openapi/v1/applications`, workspace details, version diff, `POST /openapi/v1/policies/stats/analyzed`.
- **Possible writes (each gated):** `PUT /openapi/v1/applications/{id}` (publish, HIGH), `POST .../submit_run` (fresh ADM, MEDIUM), `POST .../enable_enforce` (HIGH), `POST .../disable_enforce` (HIGH).
- **Never bundles publish + enable_enforce.** Two separate `approve high <id>` phrases.
- **When to use:** promoting analyzed policies to enforced; turning enforcement on or off.

### `/csw investigate [src] [dst] [port]` — Flow Investigation
- **What it provides:** for a specific flow, identifies the matching policy (or its absence), maps to workspace/scope, recommends one next step — no action / edit policy / propose new ALLOW / re-read scope ordering.
- **Discovery:** `POST /openapi/v1/flow_search/flows`, `POST /openapi/v1/policies/{rootScopeID}/quick_analysis`, `GET /openapi/v1/policies/{matched_id}`.
- **Possible writes (each gated):** `PUT /openapi/v1/policies/{id}` (LOW), `POST /openapi/v1/applications/{id}/policies` (MEDIUM).
- **When to use:** "why is X being denied", "policy gap", "missing rule", "what policy matched".

### `/csw onboard` — Scope and Workspace Onboarding
- **What it provides:** sets up a new scope + filter + workspace from scratch; sequential gated writes with the workspace left in non-enforcing analyzed mode (ready for the lifecycle workflow).
- **Discovery:** `GET /openapi/v1/scopes` (parent context), `POST /openapi/v1/inventory_filters/validate` (match count check).
- **Possible writes (sequential, each gated):** `POST /openapi/v1/scopes` (MEDIUM), `POST /scopes/{id}/commit_query_changes` (HIGH), `POST /openapi/v1/inventory_filters` (MEDIUM), `POST /openapi/v1/applications` (MEDIUM).
- **When to use:** standing up segmentation for a new app or environment.

### `/csw upgrade [filter]` — Agent Fleet Management
- **What it provides:** fleet inventory by version/platform/agent_type; identifies stale, EOL, and at-risk agents; produces a staged upgrade plan.
- **Discovery:** `GET /openapi/v1/sensors`, `GET /openapi/v1/software/versions`.
- **Possible writes (per agent, gated independently):** `POST /openapi/v1/sensors/{id}/upgrade` (HIGH).
- **Bulk-approve carve-out is NOT available** for agent upgrades — heterogeneous host risk per agent makes a single hash unsafe. For >5 agents the workflow recommends scripting the bulk upgrade outside the chat.

### `/csw audit` — Compliance Audit
- **What it provides:** end-to-end read-only compliance report covering scope coverage, workspace enforcement state, orphaned policies/filters, agent enforcement coverage, open alerts, recent change log.
- **Discovery only — never proposes writes.** Findings point the analyst at the matching workflow (lifecycle, onboard, fleet, triage) for any remediation.
- **When to use:** monthly/quarterly compliance check; pre-audit prep.

### `/csw triage [connector]` — Connector Triage
- **What it provides:** root-cause categorization (auth / network / config drift / upstream) for a failing connector or orchestrator, with one recommended next step.
- **Discovery:** `GET /openapi/v1/connectors`, `GET /openapi/v1/orchestrators/{id}`, `GET /openapi/v1/connector/status`, `GET /openapi/v1/change_logs`.
- **Possible writes (each gated):** `POST /openapi/v1/connector/rotate_certificates` (HIGH — briefly disrupts tunnel), `PUT /openapi/v1/orchestrators/{id}` (LOW).
- **When to use:** "connector down", "K8s not syncing", "F5 not discovering".

### `/csw incident <paste>` — Incident Triage *(new in 2026-04 cycle)*
- **What it provides:** fresh-alert triage. Takes free-form paste (SIEM blob, EDR alert, plain IP/hostname). Auto-detects internal vs external indicators. Adaptive 1h→24h→7d window. Three ranked containment options with actual write counts shown.
- **Capability preflight:** asks the user about key tier upfront. If read-only, discovery still runs but write warning blocks are suppressed entirely (informational only).
- **Discovery:** parse + classify, `POST /openapi/v1/inventory/search`, `POST /openapi/v1/flow_search/flows`, `POST /openapi/v1/flow_search/topn` (IOC fan-out), `POST /openapi/v1/policies/{rootScopeID}/quick_analysis`, `GET /openapi/v1/applications/{ws_id}` (enforcement-state check).
- **Three containment options:**
  1. **Host quarantine** (HIGH × 2 deny policies + MEDIUM × 0–1 filter create) — broadest blast, fastest containment.
  2. **Targeted hop block** (HIGH × 1 deny policy + MEDIUM × 0–2 filter creates) — surgical, narrower.
  3. **Scope tighten** (LOW or MEDIUM × 1) — slowest but durable; only if `quick_analysis` matched an overly-permissive ALLOW.
- **Output format:** tight incident format (TL;DR / Severity / Facts / Options) — overrides the default Output Formatting for this workflow only. Drill-down on request.
- **Severity scoring (deterministic):** CRITICAL (allowed cross-scope external flow), HIGH (allowed external flow OR ≥2 internal hosts touching), MEDIUM (denied flows only OR single host no cross-scope), LOW (no recent traffic).
- **Enforcement-disabled trap:** if the workspace's `enforcement_enabled=false`, every warning block's Notes line includes "Workspace is not enforcing — this write will NOT stop traffic by itself." Skill recommends upstream containment (network ACL, NIC pull) for the 60-second fix in that case.
- **When to use:** fresh-alert reactive triage (one indicator, one moment, time-pressured analyst).
- **When NOT to use:** active multi-host incident command, threat hunting, post-mortem reconstruction (these are explicitly deferred).

## Operator Reports

Focused single-question reports against the live CSW cluster. All read-only end-to-end — never propose writes. Invoked via `/csw-reports <type>`. Lives in a separate skill (`skills/csw-reports/SKILL.md`) so it can evolve independently from the main `/csw` skill.

### `/csw-reports posture` — Coverage & Enforcement Snapshot
- **What it provides:** point-in-time metrics — % inventory covered by any scope, % workspaces enforcing, % workloads in enforcement mode, plus per-scope-tree breakdown.
- **Endpoints:** `GET /openapi/v1/scopes`, `POST /openapi/v1/inventory/count`, `GET /openapi/v1/applications`, `POST /openapi/v1/inventory/search` (with `enforcement_status` dimension).
- **When to use:** sanity-check segmentation maturity at a glance; before/after a major rollout; periodic posture review.

### `/csw-reports drift` — Workspace & Agent Staleness
- **What it provides:** workspaces whose enforced version lags latest analyzed; agents on stale software. Thresholds shown in report header.
- **Endpoints:** `GET /openapi/v1/applications`, `GET /openapi/v1/sensors`, `GET /openapi/v1/software/versions`.
- **When to use:** "what hasn't been published lately"; pre-audit cleanup; identifying out-of-date agents.

### `/csw-reports noisy` — Top-N Operational Pain Points
- **What it provides:** four ranked lists (top 10 each) — busiest workspaces, highest DENY-hit ratio, biggest catch-all DENY absorption, most policies. Tells you where to look next.
- **Endpoints:** `GET /openapi/v1/applications`, `POST /openapi/v1/policies/stats/enforced` (per workspace).
- **When to use:** "where should I focus this week"; finding workspaces with policy gaps (catch-all hits) or technical debt (high policy counts).

### `/csw-reports gaps` — Onboarding Incompleteness
- **What it provides:** scopes without workspaces, workspaces without policies, filters without policies, workloads not enforcing despite scope intent. Each row points at the workflow that would address it.
- **Endpoints:** `GET /openapi/v1/scopes`, `GET /openapi/v1/applications`, `GET /openapi/v1/inventory_filters`, `POST /openapi/v1/inventory/search` (with `enforcement_status` dimension).
- **When to use:** initial deployment progress check; finding partial-onboards left behind by a migration.

## Write Actions

This skill never performs a write call (create / modify / delete) without explicit, in-session, per-call approval.

For every write, the assistant will:

1. Read the target object first and show its current state.
2. Render a **WRITE ACTION** warning block with method, path, target, body summary, blast radius, reversibility, and risk tier (LOW / MEDIUM / HIGH).
3. Wait for the literal approval phrase: `approve <tier> <short-id>` (e.g., `approve high 6532abf1`).

Anything other than the exact phrase is treated as denial. Prior approval (a change ticket, a Slack thread, an earlier "yes" in the session) does **not** authorize the next call — each call gets its own gate. Multi-step workflows gate each step independently and never bundle approvals.

For **homogeneous bulk operations** (e.g., deleting many filters of the same kind), the assistant may render a single consolidated warning showing the full list and accept `approve all <kind> <list-hash>` instead of N per-call phrases — but only when every item is the same resource kind and same action. Mixed batches, agent upgrades, and privilege changes are never bulk-approved.

## Requirements

- Python 3.6+ (uses only stdlib: `urllib`, `hashlib`, `hmac`)
- CSW API key with appropriate capabilities
- Network access to your CSW cluster
