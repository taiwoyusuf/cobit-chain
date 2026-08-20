# Azure MCP Gateway R1

Read-only, PKCE-compliant gateway scaffold for controlled access to Azure MCP from COBIT-Chain / Platform B1.

## R1 invariant

R1 is **read-only**. It must not perform Azure mutations, RBAC changes, secret/key retrieval, credential export, or any operation outside the explicit allow-list.

## Frozen R1 allow-list

The executable R1 inventory surface is exactly:

- `subscription_list`
- `group_list`
- `group_resource_list`

Each has been reconciled against current Azure MCP documentation as read-only and non-secret. No other Azure MCP tool is authorized for R1.

CI requires every allow-listed tool to have a matching verified catalog-evidence entry and requires `catalog_state = frozen`. See `MCP_CATALOG_RECONCILIATION.md`.

## Authentication and evidence boundary

- OAuth Authorization Code + PKCE (`S256`).
- No client secret.
- Default upstream endpoint: `https://mcp.management.azure.com`.
- Tokens remain within the server-side session boundary and are redacted from evidence logs.
- No wildcard, RBAC mutation, secret/key/connection-string retrieval, or write/update/delete/action operation is permitted.

## Current canonical state

`CI_PASS_BASELINE / MCP_CATALOG_RECONCILED_AND_FROZEN / DEPLOYMENT_READINESS_PREPARED / AZURE_INVENTORY_NOT_YET_CAPTURED`

## Next gate

The next live action is read-only Azure inventory through an authorized Azure-connected execution path: account/subscription metadata, resource groups, Container Apps environments, Container Apps applications, and one scoped `group_resource_list` proof target.

Actual deployment remains gated.
