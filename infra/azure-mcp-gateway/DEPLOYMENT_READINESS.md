# Gateway R1 — Deployment Readiness Gate

Status: **READY FOR READ-ONLY AZURE INVENTORY; NOT YET DEPLOYED**

## Purpose

This gate determines whether an existing Azure Container Apps hosting boundary can support Gateway R1 without creating or modifying RBAC, retrieving secrets/keys, or widening the gateway's read-only MCP policy.

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

The script is intentionally limited to:

- signed-in account/subscription metadata;
- resource-group inventory;
- Container Apps environment inventory;
- Container Apps application inventory.

## Required decision output

The inventory must establish, without mutation:

1. Which subscription is approved for Platform B1 / Gateway R1.
2. Whether a suitable existing resource group already exists.
3. Whether a suitable existing Azure Container Apps Environment already exists.
4. Whether a suitable existing logging boundary is already attached to that environment.
5. Whether a naming collision exists for the proposed gateway application.
6. Whether the signed-in principal already has sufficient rights to deploy later.

If item 6 is false, record the gap and stop. Gateway R1 does not create or modify role assignments.

## Proposed application configuration after deployment authorization

- Runtime: Azure Container Apps, one replica for R1 proof.
- Container port: `8000`.
- External HTTPS ingress only when required for the OAuth callback/client path.
- Health endpoint: `/healthz`.
- Startup/liveness/readiness health checks should target the application port and health endpoint.
- Non-secret environment variables only:
  - `AZURE_TENANT_ID`
  - `AZURE_CLIENT_ID`
  - `AZURE_REDIRECT_URI`
  - `AZURE_MCP_SCOPE`
  - `AZURE_MCP_URL`
- No access token, refresh token, client secret, storage key, Key Vault secret, certificate private key, or connection string is committed or provided as a deployment environment variable.

## Stop conditions

Do not proceed to deployment if the read-only inventory indicates that deployment would require:

- creating/changing a role assignment;
- Contributor/Owner elevation;
- retrieving a secret, key, connection string, certificate private key, or credential;
- creating a new Azure hosting boundary without separate authorization;
- increasing the gateway allow-list beyond the reviewed R1 tools;
- enabling a deployment workflow that can mutate Azure without a separate explicit deployment gate.

## Next status transition

Only after read-only Azure inventory is captured can the state move from:

`CI_PASS / DEPLOYMENT_READINESS_PREPARED`

to:

`AZURE_INVENTORY_RECONCILED / DEPLOYMENT_COMMANDS_PREPARED`

Actual deployment is a later explicit action.
