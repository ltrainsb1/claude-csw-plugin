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

## Usage

### Read-only commands

| Command | Description |
|---------|-------------|
| `/csw report` | Full environment overview (scopes, inventory, agents, connectors) |
| `/csw scopes` | Scope hierarchy with query definitions and policy counts |
| `/csw policy [scope]` | Policy analysis for a scope or workspace |
| `/csw filters` | Inventory filter details |
| `/csw connectors` | Connector and orchestrator status (F5, K8s, etc.) |
| `/csw inventory [query]` | Search workloads by IP, hostname, OS, or label |
| `/csw flows [src] [dst] [port]` | Search observed traffic flows |
| `/csw agents [host]` | Agent/sensor status and versions |

### Workflows

Each workflow runs a guided discovery, then recommends a single next step. Any write call (POST/PUT/DELETE, enforcement toggles, ADM runs, agent upgrades, etc.) is gated — see **Write Actions** below.

| Command | Description |
|---------|-------------|
| `/csw lifecycle [workspace]` | Policy lifecycle: ADM → review diff → publish → enforce |
| `/csw investigate [src] [dst] [port]` | Flow investigation: search → quick analyze → propose fix |
| `/csw onboard` | Stand up a new scope + filter + workspace (sequential gates) |
| `/csw upgrade [filter]` | Agent fleet status and staged upgrade plan |
| `/csw audit` | Compliance audit: coverage gaps, enforcement state, orphans (read-only) |
| `/csw triage [connector]` | Connector / orchestrator failure triage with root-cause categorization |
| `/csw incident <paste>` | Fresh-alert triage: parse indicator, discover exposure (with IOC fan-out), present three ranked containment options |

## Write Actions

This skill never performs a write call (create / modify / delete) without explicit, in-session, per-call approval.

For every write, the assistant will:

1. Read the target object first and show its current state.
2. Render a **WRITE ACTION** warning block with method, path, target, body summary, blast radius, reversibility, and risk tier (LOW / MEDIUM / HIGH).
3. Wait for the literal approval phrase: `approve <tier> <short-id>` (e.g., `approve high 6532abf1`).

Anything other than the exact phrase is treated as denial. Prior approval (a change ticket, a Slack thread, an earlier "yes" in the session) does **not** authorize the next call — each call gets its own gate. Multi-step workflows gate each step independently and never bundle approvals.

For **homogeneous bulk operations** (e.g., deleting many filters of the same kind), the assistant may render a single consolidated warning showing the full list and accept `approve all <kind> <list-hash>` instead of N per-call phrases — but only when every item is the same resource kind and same action. Mixed batches, agent upgrades, and privilege changes are never bulk-approved.

## API Key Capabilities

Your CSW API key needs specific capabilities depending on which commands you use:

| Command | Required Capability |
|---------|-------------------|
| report | `flow_inventory_query`, `user_role_scope_management` |
| policy | `app_policy_management` |
| scopes | `user_role_scope_management` |
| filters | `flow_inventory_query` |
| connectors | `external_integration` |
| inventory | `flow_inventory_query` |
| flows | `flow_inventory_query` |
| agents | `sensor_management` |

## Requirements

- Python 3.6+ (uses only stdlib: `urllib`, `hashlib`, `hmac`)
- CSW API key with appropriate capabilities
- Network access to your CSW cluster
