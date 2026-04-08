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
