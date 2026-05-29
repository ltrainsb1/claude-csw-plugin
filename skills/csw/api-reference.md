# CSW OpenAPI v1 — Endpoint Reference

Base path: `/openapi/v1`

> **Deploy column.** Every table below carries a `Deploy` column: `B` (both deployments), `S` (SaaS tenants only), `H` (self-hosted clusters only). The helper `bin/csw_api.py` enforces this column at call time — calls to non-applicable endpoints are refused before signing. Set `CSW_DEPLOYMENT=saas|selfhosted` to skip auto-detection. See `ai_docs/docs/csw-deployment-models.md`.

## Scopes

| Method | Path | Description | Deploy |
|--------|------|-------------|--------|
| GET | `/scopes` | List all app scopes | B |
| POST | `/scopes` | Create scope | B |
| GET | `/scopes/{id}` | Get scope by ID | B |
| PUT | `/scopes/{id}` | Update scope | B |
| DELETE | `/scopes/{id}` | Delete scope | B |
| GET | `/scopes/policy_priority_order` | Get policy priority ordering | B |
| PUT | `/scopes/policy_priority_order` | Update policy priority ordering | B |
| POST | `/scopes/{id}/commit_query_changes` | Commit query changes | B |

**Scope object fields**: `id`, `short_name`, `name` (full path), `description`, `short_query`, `query`, `parent_app_scope_id`, `child_app_scope_ids`, `vrf_id`, `filter_type`, `dirty`, `dirty_short_query`

## Inventory Filters

| Method | Path | Description | Deploy |
|--------|------|-------------|--------|
| GET | `/inventory_filters` | List all filters | B |
| POST | `/inventory_filters` | Create filter | B |
| GET | `/inventory_filters/{id}` | Get filter | B |
| PUT | `/inventory_filters/{id}` | Update filter | B |
| DELETE | `/inventory_filters/{id}` | Delete filter | B |
| POST | `/inventory_filters/validate` | Validate filter query | B |

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

| Method | Path | Description | Deploy |
|--------|------|-------------|--------|
| GET | `/applications` | List all workspaces | B |
| POST | `/applications` | Create workspace | B |
| GET | `/applications/{id}` | Get workspace | B |
| PUT | `/applications/{id}` | Update workspace | B |
| DELETE | `/applications/{id}` | Delete workspace | B |
| GET | `/applications/{id}/details` | Full export (policies + clusters) | B |
| POST | `/applications/{id}/enable_enforce` | Enable enforcement | B |
| POST | `/applications/{id}/disable_enforce` | Disable enforcement | B |
| POST | `/applications/{id}/submit_run` | Trigger ADM policy discovery | B |

**Workspace object fields**: `id`, `name`, `description`, `app_scope_id`, `primary`, `alternate_query_mode`, `enforcement_enabled`, `enforced_version`, `latest_adm_version`

## Policies

| Method | Path | Description | Deploy |
|--------|------|-------------|--------|
| GET | `/applications/{id}/policies` | List policies in workspace | B |
| POST | `/applications/{id}/policies` | Create policy | B |
| GET | `/policies/{id}` | Get policy | B |
| PUT | `/policies/{id}` | Update policy | B |
| DELETE | `/policies/{id}` | Delete policy | B |
| POST | `/policies/{id}/l4_params` | Add L4 service port/protocol | B |
| PUT | `/policies/{id}/l4_params/{l4_id}` | Update L4 params | B |
| DELETE | `/policies/{id}/l4_params/{l4_id}` | Remove L4 params | B |
| POST | `/policies/{rootScopeID}/quick_analysis` | Analyze flow against policies | B |
| POST | `/policies/stats/enforced` | Enforced policy hit stats | B |
| POST | `/policies/stats/analyzed` | Analyzed policy hit stats | B |

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

| Method | Path | Description | Deploy |
|--------|------|-------------|--------|
| POST | `/inventory/search` | Search inventory | B |
| POST | `/inventory/dimensions` | Available dimensions | B |
| POST | `/inventory/stats` | Inventory statistics | B |
| GET | `/inventory/count` | Total inventory count | B |

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

| Method | Path | Description | Deploy |
|--------|------|-------------|--------|
| GET | `/sensors` | List all sensors | B |
| GET | `/sensors/{id}` | Get sensor detail | B |
| PUT | `/sensors/{id}` | Update sensor | B |
| DELETE | `/sensors/{id}` | Delete sensor | B |
| POST | `/sensors/{id}/upgrade` | Upgrade agent | B |
| POST | `/sensors/{id}/config_intents` | Configure agent intents | B |
| GET | `/software/versions` | Available agent software versions (catalog content differs by deployment) | B |

**Sensor object fields**: `uuid`, `host_name`, `interfaces` (IP list), `platform`, `agent_type`, `current_sw_version`, `desired_sw_version`, `last_config_fetch_at`, `sensor_status`

## Connectors

| Method | Path | Description | Deploy |
|--------|------|-------------|--------|
| GET | `/connectors` | List connectors | B |
| POST | `/connectors` | Create connector | B |
| GET | `/connectors/{id}` | Get connector | B |
| PUT | `/connectors/{id}` | Update connector | B |
| DELETE | `/connectors/{id}` | Delete connector | B |
| GET | `/connectors/types` | Available types | B |

## Orchestrators

| Method | Path | Description | Deploy |
|--------|------|-------------|--------|
| GET | `/orchestrators` | List orchestrators | B |
| POST | `/orchestrators` | Create orchestrator | B |
| GET | `/orchestrators/{id}` | Get orchestrator | B |
| PUT | `/orchestrators/{id}` | Update orchestrator | B |
| DELETE | `/orchestrators/{id}` | Delete orchestrator | B |
| GET | `/orchestrator_golden_rules` | Golden rules | B |
| POST | `/orchestrator_golden_rules` | Create golden rule | B |

**Orchestrator types**: `kubernetes`, `f5`, `vcenter`, `dns`, `infoblox`, `servicenow`

## Flow Search

| Method | Path | Description | Deploy |
|--------|------|-------------|--------|
| POST | `/flow_search/flows` | Search flows | B |
| POST | `/flow_search/topn` | Top-N flows | B |
| POST | `/flow_search/dimensions` | Available dimensions | B |
| POST | `/flow_search/metrics` | Available metrics | B |

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

| Method | Path | Description | Deploy |
|--------|------|-------------|--------|
| GET | `/connector/status` | Tunnel status (returns "not configured" on self-hosted clusters without an appliance) | B |
| GET | `/connector/token` | Get token | B |
| POST | `/connector/rotate_certificates` | Rotate certs (SaaS Secure Connector tunnel lifecycle; self-hosted rotation goes through site-admin UI) | S |

## Users & Roles

| Method | Path | Description | Deploy |
|--------|------|-------------|--------|
| GET | `/users` | List users | B |
| POST | `/users` | Create user | B |
| GET | `/users/{id}` | Get user | B |
| POST | `/users/{id}/add_role` | Assign role | B |
| POST | `/users/{id}/remove_role` | Remove role | B |
| GET | `/roles` | List roles | B |
| POST | `/roles` | Create role | B |
| GET | `/roles/{id}` | Get role | B |
| POST | `/roles/{id}/give_access` | Grant scope access | B |

## Other

| Method | Path | Description | Deploy |
|--------|------|-------------|--------|
| GET | `/service_health` | Cluster health — exposes internal services (Hadoop, Druid, etc.) on self-hosted; restricted on SaaS where the cluster is Cisco's responsibility | H |
| GET | `/vrfs` | List VRFs (single Default on SaaS; multi-VRF on self-hosted; used by deployment auto-detect) | B |
| GET | `/change_logs` | Change logs | B |
| GET | `/alerts` | List alerts | B |
| GET | `/kubernetes/pods` | List pods | B |
| GET | `/kubernetes/services` | List services | B |
