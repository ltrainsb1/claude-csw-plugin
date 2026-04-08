# CSW OpenAPI v1 — Endpoint Reference

Base path: `/openapi/v1`

## Scopes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/scopes` | List all app scopes |
| POST | `/scopes` | Create scope |
| GET | `/scopes/{id}` | Get scope by ID |
| PUT | `/scopes/{id}` | Update scope |
| DELETE | `/scopes/{id}` | Delete scope |
| GET | `/scopes/policy_priority_order` | Get policy priority ordering |
| PUT | `/scopes/policy_priority_order` | Update policy priority ordering |
| POST | `/scopes/{id}/commit_query_changes` | Commit query changes |

**Scope object fields**: `id`, `short_name`, `name` (full path), `description`, `short_query`, `query`, `parent_app_scope_id`, `child_app_scope_ids`, `vrf_id`, `filter_type`, `dirty`, `dirty_short_query`

## Inventory Filters

| Method | Path | Description |
|--------|------|-------------|
| GET | `/inventory_filters` | List all filters |
| POST | `/inventory_filters` | Create filter |
| GET | `/inventory_filters/{id}` | Get filter |
| PUT | `/inventory_filters/{id}` | Update filter |
| DELETE | `/inventory_filters/{id}` | Delete filter |
| POST | `/inventory_filters/validate` | Validate filter query |

**Filter object fields**: `id`, `name`, `query`, `app_scope_id`, `public`, `primary`

**Query format**: `{"type": "eq|contains|range|subnet|regex|and|or|not", "field": "<dimension>", "value": "<val>"}`

Nested example:
```json
{
  "type": "and",
  "filters": [
    {"type": "eq", "field": "os", "value": "linux"},
    {"type": "subnet", "field": "ip", "value": "10.10.0.0/16"}
  ]
}
```

## Applications (Workspaces)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/applications` | List all workspaces |
| POST | `/applications` | Create workspace |
| GET | `/applications/{id}` | Get workspace |
| PUT | `/applications/{id}` | Update workspace |
| DELETE | `/applications/{id}` | Delete workspace |
| GET | `/applications/{id}/details` | Full export (policies + clusters) |
| POST | `/applications/{id}/enable_enforce` | Enable enforcement |
| POST | `/applications/{id}/disable_enforce` | Disable enforcement |
| POST | `/applications/{id}/submit_run` | Trigger ADM policy discovery |

**Workspace object fields**: `id`, `name`, `description`, `app_scope_id`, `primary`, `alternate_query_mode`, `enforcement_enabled`, `enforced_version`, `latest_adm_version`

## Policies

| Method | Path | Description |
|--------|------|-------------|
| GET | `/applications/{id}/policies` | List policies in workspace |
| POST | `/applications/{id}/policies` | Create policy |
| GET | `/policies/{id}` | Get policy |
| PUT | `/policies/{id}` | Update policy |
| DELETE | `/policies/{id}` | Delete policy |
| POST | `/policies/{id}/l4_params` | Add L4 service port/protocol |
| PUT | `/policies/{id}/l4_params/{l4_id}` | Update L4 params |
| DELETE | `/policies/{id}/l4_params/{l4_id}` | Remove L4 params |
| POST | `/policies/{rootScopeID}/quick_analysis` | Analyze flow against policies |
| POST | `/policies/stats/enforced` | Enforced policy hit stats |
| POST | `/policies/stats/analyzed` | Analyzed policy hit stats |

**Policy object fields**: `id`, `consumer_filter_id`, `provider_filter_id`, `action` (ALLOW/DENY), `priority`, `l4_params` (list of port/proto), `version`

**Quick analysis body**:
```json
{
  "src_ip": "10.10.1.216",
  "dst_ip": "10.10.10.49",
  "dst_port": 32590,
  "protocol": 6
}
```

## Inventory Search

| Method | Path | Description |
|--------|------|-------------|
| POST | `/inventory/search` | Search inventory |
| POST | `/inventory/dimensions` | Available dimensions |
| POST | `/inventory/stats` | Inventory statistics |
| GET | `/inventory/count` | Total inventory count |

**Search body**:
```json
{
  "filter": {"type": "subnet", "field": "ip", "value": "10.10.0.0/16"},
  "dimensions": ["ip", "hostname", "os", "os_version", "agent_type", "enforcement_status"],
  "limit": 100,
  "offset": 0
}
```

## Sensors (Agents)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/sensors` | List all sensors |
| GET | `/sensors/{id}` | Get sensor detail |
| PUT | `/sensors/{id}` | Update sensor |
| DELETE | `/sensors/{id}` | Delete sensor |
| POST | `/sensors/{id}/upgrade` | Upgrade agent |
| POST | `/sensors/{id}/config_intents` | Configure agent intents |

**Sensor object fields**: `uuid`, `host_name`, `interfaces` (IP list), `platform`, `agent_type`, `current_sw_version`, `desired_sw_version`, `last_config_fetch_at`, `sensor_status`

## Connectors

| Method | Path | Description |
|--------|------|-------------|
| GET | `/connectors` | List connectors |
| POST | `/connectors` | Create connector |
| GET | `/connectors/{id}` | Get connector |
| PUT | `/connectors/{id}` | Update connector |
| DELETE | `/connectors/{id}` | Delete connector |
| GET | `/connectors/types` | Available types |

## Orchestrators

| Method | Path | Description |
|--------|------|-------------|
| GET | `/orchestrators` | List orchestrators |
| POST | `/orchestrators` | Create orchestrator |
| GET | `/orchestrators/{id}` | Get orchestrator |
| PUT | `/orchestrators/{id}` | Update orchestrator |
| DELETE | `/orchestrators/{id}` | Delete orchestrator |
| GET | `/orchestrator_golden_rules` | Golden rules |
| POST | `/orchestrator_golden_rules` | Create golden rule |

**Orchestrator types**: `kubernetes`, `f5`, `vcenter`, `dns`, `infoblox`, `servicenow`

## Flow Search

| Method | Path | Description |
|--------|------|-------------|
| POST | `/flow_search/flows` | Search flows |
| POST | `/flow_search/topn` | Top-N flows |
| POST | `/flow_search/dimensions` | Available dimensions |
| POST | `/flow_search/metrics` | Available metrics |

**Flow search body**:
```json
{
  "t0": "2026-03-31T18:00:00Z",
  "t1": "2026-03-31T19:00:00Z",
  "filter": {
    "type": "and",
    "filters": [
      {"type": "eq", "field": "src_address", "value": "10.10.1.216"},
      {"type": "eq", "field": "dst_port", "value": 9001}
    ]
  },
  "dimensions": ["src_address", "dst_address", "dst_port", "proto", "fwd_policy_id", "action"],
  "limit": 100
}
```

## Secure Connector

| Method | Path | Description |
|--------|------|-------------|
| GET | `/connector/status` | Tunnel status |
| GET | `/connector/token` | Get token |
| POST | `/connector/rotate_certificates` | Rotate certs |

## Users & Roles

| Method | Path | Description |
|--------|------|-------------|
| GET | `/users` | List users |
| POST | `/users` | Create user |
| GET | `/users/{id}` | Get user |
| POST | `/users/{id}/add_role` | Assign role |
| POST | `/users/{id}/remove_role` | Remove role |
| GET | `/roles` | List roles |
| POST | `/roles` | Create role |
| GET | `/roles/{id}` | Get role |
| POST | `/roles/{id}/give_access` | Grant scope access |

## Other

| Method | Path | Description |
|--------|------|-------------|
| GET | `/service_health` | Cluster health |
| GET | `/vrfs` | List VRFs |
| GET | `/change_logs` | Change logs |
| GET | `/alerts` | List alerts |
| GET | `/kubernetes/pods` | List pods |
| GET | `/kubernetes/services` | List services |
