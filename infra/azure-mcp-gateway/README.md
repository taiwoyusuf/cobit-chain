# Azure MCP Gateway R1

Read-only, PKCE-compliant gateway scaffold for controlled access to Azure MCP from COBIT-Chain / Platform B1.

## R1 invariant

R1 is **read-only**. It must not perform Azure mutations, RBAC changes, secret/key retrieval, credential export, or any operation outside the explicit allow-list.

## Upstream Azure MCP

- Default endpoint: `https://mcp.management.azure.com`
- Tenant ID, public client ID, redirect URI and delegated scope are deployment configuration supplied through environment variables.
- No client secret is used by this R1 scaffold.
- Authorization Code + PKCE (`S256`) is the required browser flow.

No real token, secret, key, connection string or tenant-specific credential belongs in this repository.

## Architecture

```text
Browser / ChatGPT connector
        |
        | OAuth 2.0 Authorization Code + PKCE
        v
Azure MCP Gateway R1
  - /oauth/start
  - /oauth/callback
  - server-side token boundary
  - explicit tool allow-list
  - deny-by-default policy enforcement
  - evidence event generation
        |
        | bearer token, allowed read-only call only
        v
Azure MCP
https://mcp.management.azure.com
```

## Frozen R1 allow-list

The executable R1 inventory surface is exactly:

- `subscription_list`
- `group_list`
- `group_resource_list`

Each has been reconciled against current Azure MCP documentation as read-only and non-secret. No other Azure MCP tool is authorized for R1.

CI requires every allow-listed tool to have a matching verified catalog-evidence entry and requires `catalog_state = frozen`. See `MCP_CATALOG_RECONCILIATION.md`.

## Security boundary

PKCE required. No client secret. No wildcard. No RBAC mutation. No secret/key/connection-string retrieval. No write/update/delete/action operations. Authentication material is redacted from evidence logs. Deployment stays behind a separate gate.

## Status

`CI_PASS_BASELINE / MCP_CATALOG_RECONCILED_AND_FROZEN / DEPLOYMENT_READINESS_PREPARED / AZURE_INVENTORY_NOT_YET_CAPTURED`

The next live action is read-only Azure inventory through an authorized Azure-connected execution path. Actual deployment remains gated.
