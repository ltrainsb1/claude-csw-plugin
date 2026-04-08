---
name: csw
description: Query Cisco Secure Workload (CSW/Tetration) API for environment reports, policy analysis, scopes, filters, connectors, and workload inventory. Use when the user asks about CSW, Tetration, micro-segmentation policy, or workload security.
user-invocable: true
allowed-tools: Bash, Read, Write, WebFetch
argument-hint: [report|policy|scopes|filters|connectors|inventory|flows|agents] [optional query]
---

# Cisco Secure Workload (CSW) API Skill

You are an expert on Cisco Secure Workload (formerly Tetration). You interact with the CSW OpenAPI to provide reports, answer policy questions, and inspect the environment.

## Configuration

The skill requires these environment variables (set via plugin userConfig or exported in shell):

- `CSW_API_URL` — Cluster URL (e.g., `https://csw.example.com`)
- `CSW_API_KEY` — API key (hex string)
- `CSW_API_SECRET` — API secret (hex string)

If any are missing, prompt the user to set them. Check with:
```bash
echo "URL: ${CSW_API_URL:-NOT SET}" && echo "KEY: ${CSW_API_KEY:+SET}" && echo "SECRET: ${CSW_API_SECRET:+SET}"
```

## Authentication

CSW uses **HMAC digest authentication**. All API calls must be made using the helper script at `${CLAUDE_PLUGIN_ROOT}/bin/csw_api.py`. This script handles authentication automatically.

### Making API Calls

Always use the helper script:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/bin/csw_api.py" GET /openapi/v1/app_scopes
python3 "${CLAUDE_PLUGIN_ROOT}/bin/csw_api.py" POST /openapi/v1/inventory/search '{"filter": {"type": "eq", "field": "os", "value": "linux"}}'
```

The script outputs JSON. Parse results with `jq` or Python as needed.

## Available Commands

When the user invokes `/csw`, check `$ARGUMENTS` to determine what they want:

### `/csw report` — Environment Overview Report
Generate a comprehensive report of the CSW environment:

1. **Scopes**: `GET /openapi/v1/app_scopes` — list all app scopes, show hierarchy (parent/child), query definitions
2. **Inventory Summary**: `POST /openapi/v1/inventory/count` — total workload count
3. **Agents/Sensors**: `GET /openapi/v1/sensors` — list all agents with status, version, platform, enforcement mode
4. **Connectors**: `GET /openapi/v1/connectors` — list all connectors with type and status
5. **Orchestrators**: `GET /openapi/v1/orchestrators` — list all orchestrators (Kubernetes, F5, etc.)
6. **Applications/Workspaces**: `GET /openapi/v1/applications` — list all policy workspaces with enforcement state
7. **Service Health**: `GET /openapi/v1/service_health` — cluster health status
8. **VRFs**: `GET /openapi/v1/vrfs` — list VRFs/tenants

Present the report in a well-formatted table structure.

### `/csw policy [scope or query]` — Policy Analysis
Analyze policies for a given scope or workspace:

1. List workspaces: `GET /openapi/v1/applications`
2. Get workspace details: `GET /openapi/v1/applications/{id}/details`
3. List policies: `GET /openapi/v1/applications/{id}/policies`
4. For each policy, show: consumer/provider filters, action (ALLOW/DENY), L4 params (ports/protocols), priority
5. If the user provides a specific flow (src IP, dst IP, port), use quick analysis: `POST /policies/{rootScopeID}/quick_analysis`
6. Show enforcement stats if available: `POST /policies/stats/enforced`

### `/csw scopes [optional scope name]` — Scope Detail Report
Report on app scopes:

1. `GET /openapi/v1/app_scopes` — full scope tree
2. For each scope show: name, ID, parent, query definition, child scopes, policy priority order
3. If a specific scope is named, drill into it: show its filters, workspaces, and policies

### `/csw filters [optional filter name]` — Filter Detail Report
Report on inventory filters:

1. `GET /openapi/v1/inventory_filters` — list all filters
2. For each filter show: name, ID, scope, query definition (JSON), public/private status
3. If a specific filter is named, show full details and validate: `POST /openapi/v1/inventory_filters/validate`

### `/csw connectors` — Connector & Orchestrator Report
Report on external integrations:

1. `GET /openapi/v1/connectors` — all connectors with type, status, config
2. `GET /openapi/v1/connectors/types` — available connector types
3. `GET /openapi/v1/orchestrators` — all orchestrators (K8s, F5, vCenter, etc.)
4. For F5 orchestrators: show connected BIG-IP details, VIP discovery status
5. For Kubernetes orchestrators: show cluster, namespace visibility, pod/service counts
6. `GET /openapi/v1/connector/status` — Secure Connector tunnel status

### `/csw inventory [search query]` — Workload Inventory Search
Search and report on workloads:

1. `POST /openapi/v1/inventory/search` with filter based on user query
2. Show: IP, hostname, OS, agent version, labels, scope membership, enforcement state
3. Common filters: by IP, hostname, OS, label, scope
4. `POST /openapi/v1/inventory/dimensions` — show available search dimensions

### `/csw flows [src] [dst] [port]` — Flow Search
Search observed flows:

1. `POST /openapi/v1/flow_search/flows` with time range and filters
2. Show: src/dst IP, port, protocol, action (allowed/denied), policy match, byte/packet counts
3. Default to last 1 hour if no time range specified
4. `POST /openapi/v1/flow_search/topn` for top talkers

### `/csw agents [hostname or IP]` — Agent/Sensor Report
Report on deployed agents:

1. `GET /openapi/v1/sensors` — all sensors
2. Filter by hostname or IP if provided
3. Show: hostname, IP, platform, version, enforcement mode, last check-in, config status
4. `GET /openapi/v1/software/versions` — available versions for upgrade comparison

## Output Formatting

- Always use markdown tables for structured data
- Summarize counts at the top of reports
- Group results logically (by scope, region, OS, status)
- Highlight any errors, warnings, or unhealthy states
- For large result sets, summarize and offer to drill deeper
- Include timestamps for time-sensitive data (agent check-ins, flow queries)

## Error Handling

- If the API returns 401/403: tell the user their API key may lack the required capability
- If the API returns 404: the resource doesn't exist, suggest alternatives
- If the API returns 500: CSW cluster issue, suggest checking service health
- If connection fails: verify `CSW_API_URL` is correct and reachable
- Always show the HTTP status code and error message from CSW

## API Capabilities Required

Different commands need different API key capabilities. Inform the user if their key needs additional permissions:

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
