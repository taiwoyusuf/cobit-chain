# Gateway R1 — Deployment Readiness Gate

Status: **READY FOR READ-ONLY AZURE INVENTORY; NOT YET DEPLOYED**

## Purpose

This gate determines whether an existing Azure Container Apps hosting boundary can support Gateway R1 without creating or modifying RBAC, retrieving secrets/keys, or widening the gateway's read-only MCP policy.

## Completed evidence gates

- R1 gateway scaffold exists on `feature/azure-mcp-gateway-r1`.
- Draft PR remains open.
- CI baseline passes.
- Deny-by-default policy is implemented.
- PKCE is required.
- Secret/key/RBAC/write operations remain prohibited.
- Deployment guardrail tests are present.
- Azure MCP catalog reconciliation is complete for the R1 inventory surface.

## Reconciled R1 live-proof tools

- `subscription_list`
- `group_list`
- `group_resource_list`

Each is admitted only because current Azure MCP documentation describes the corresponding operation as Read Only = true and Secret = false. No additional tool is authorized.

## Current Microsoft-aligned assumptions

- Azure Container Apps supports HTTP health probes, including startup, liveness, and readiness probes.
- External HTTP ingress terminates on HTTPS and forwards to the configured target port.
- Runtime environment variables can be supplied directly or through secret references; Gateway R1 deliberately uses only non-secret deployment configuration values for tenant/client/redirect/scope/endpoint settings.
- Gateway R1 does not call `az containerapp secret list --show-values`, Key Vault secret commands, storage-key commands, or connection-string commands.

## Read-only inventory command

Run:

```bash
bash scripts/readiness_inventory.sh
```

The script is intentionally limited to signed-in account/subscription metadata, resource-group inventory, Container Apps environment inventory, and Container Apps application inventory.

## Required decision output

The inventory must establish, without mutation:

1. Which subscription is approved for Platform B1 / Gateway R1.
2. Whether a suitable existing resource group already exists.
3. Whether a suitable existing Azure Container Apps Environment already exists.
4. Whether a suitable existing logging boundary is already attached to that environment.
5. Whether a naming collision exists for the proposed gateway application.
6. Whether the signed-in principal already has sufficient rights to deploy later.
7. Which existing resource group will be used for the one scoped `group_resource_list` live proof.

If sufficient deployment rights are absent, record the gap and stop. Gateway R1 does not create or modify role assignments.

## Proposed application configuration after deployment authorization

- Runtime: Azure Container Apps, one replica for R1 proof.
- Container port: `8000`.
- External HTTPS ingress only when required for the OAuth callback/client path.
- Health endpoint: `/healthz`.
- Startup/liveness/readiness health checks target the application port and health endpoint.
- Non-secret environment variables only: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_REDIRECT_URI`, `AZURE_MCP_SCOPE`, and `AZURE_MCP_URL`.
- No access token, refresh token, client secret, storage key, Key Vault secret, certificate private key, or connection string is committed or supplied as a deployment environment variable.

## Stop conditions

Do not proceed to deployment if the read-only inventory indicates that deployment would require creating/changing a role assignment, Contributor/Owner elevation, retrieving sensitive material, creating a new Azure hosting boundary without separate authorization, widening the reviewed R1 allow-list, or enabling an ungated Azure mutation workflow.

## Current canonical state

`CI_PASS / MCP_CATALOG_RECONCILED / DEPLOYMENT_READINESS_PREPARED / AZURE_INVENTORY_NOT_YET_CAPTURED`

## Next status transition

Only after read-only Azure inventory is captured can the state move to:

`AZURE_INVENTORY_RECONCILED / DEPLOYMENT_COMMANDS_PREPARED`

Actual deployment remains a later explicit action.
