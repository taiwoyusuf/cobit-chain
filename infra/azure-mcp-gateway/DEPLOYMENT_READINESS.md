# Gateway R1 — Deployment Readiness Gate

Status: **READY FOR READ-ONLY AZURE INVENTORY; NOT YET DEPLOYED**

## Completed evidence gates

- R1 gateway scaffold exists on `feature/azure-mcp-gateway-r1`.
- Draft PR remains open.
- CI baseline passes.
- Deny-by-default policy is implemented.
- PKCE is required.
- Secret/key/RBAC/write operations remain prohibited.
- Deployment guardrail tests are present.
- Azure MCP catalog reconciliation is complete and frozen for R1.

## Frozen R1 live-proof tools

- `subscription_list`
- `group_list`
- `group_resource_list`

Each is admitted only because current Azure MCP documentation describes the corresponding operation as Read Only = true and Secret = false. No additional tool is authorized.

## Remaining live gate

The next live step is **read-only Azure inventory only** using an authenticated Azure-connected execution path:

1. current account / tenant / subscription metadata;
2. existing resource groups;
3. existing Azure Container Apps environments;
4. existing Azure Container Apps applications;
5. select one existing resource group for the scoped `group_resource_list` proof;
6. identify whether an already-approved hosting boundary exists for one gateway replica.

The live inventory step must not retrieve secrets, keys, connection strings, credentials, or modify RBAC or Azure resource state.

## Proposed application configuration after deployment authorization

- Runtime: Azure Container Apps, one replica for R1 proof.
- Container port: `8000`.
- HTTPS ingress for OAuth callback/client path.
- Health endpoint: `/healthz`.
- Non-secret environment variables only: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_REDIRECT_URI`, `AZURE_MCP_SCOPE`, and `AZURE_MCP_URL`.
- No access token, refresh token, client secret, storage key, Key Vault secret, certificate private key, or connection string is committed or supplied as a deployment environment variable.

## Stop conditions

Do not proceed if the inventory or later deployment would require RBAC creation/change, Contributor/Owner elevation, retrieval of sensitive material, creation of a new Azure hosting boundary without separate authorization, widening the frozen R1 allow-list, or an ungated Azure mutation workflow.

## Current canonical state

`CI_PASS_BASELINE / MCP_CATALOG_RECONCILED_AND_FROZEN / DEPLOYMENT_READINESS_PREPARED / AZURE_INVENTORY_NOT_YET_CAPTURED`

## Next status transition

Only after read-only Azure inventory is captured can the state move to:

`AZURE_INVENTORY_RECONCILED / DEPLOYMENT_COMMANDS_PREPARED`

Actual deployment remains a later explicit action.
