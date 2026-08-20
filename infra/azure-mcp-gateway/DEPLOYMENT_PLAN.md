# Azure MCP Gateway R1 — Deployment Plan

Status: **PLAN ONLY — NOT AUTHORIZED FOR DEPLOYMENT**

This plan preserves the R1 invariant: no Azure write operations through the gateway, no RBAC changes, no secret/key retrieval, explicit allow-list only, evidence logging, and draft PR only.

## Proposed runtime topology

```text
ChatGPT / approved browser client
        |
        | HTTPS + OAuth Authorization Code / PKCE
        v
Azure public ingress
        |
        v
Azure Container Apps
  azure-mcp-gateway-r1
  - FastAPI gateway
  - deny-by-default allow-list
  - server-side session boundary
  - evidence events to stdout / platform logging
        |
        | bearer token, allowed read-only call only
        v
Azure MCP remote endpoint
https://mcp.management.azure.com
```

## G0 — Repository and catalog gate

Required before any Azure deployment action:

- Draft PR remains open.
- R1 policy and deployment guardrail tests pass.
- No secrets, tokens, keys, connection strings or private credentials are present in the diff.
- Allow-list contains no wildcard.
- Catalog state remains `frozen`.
- Executable tool list remains exactly `subscription_list`, `group_list`, and `group_resource_list` unless a separately reviewed R1 change expands it.
- `MCP_CATALOG_RECONCILIATION.md` remains the evidence record for all admitted tools.

## G1 — Identity contract gate

Use an existing Microsoft Entra public-client / delegated OAuth registration compatible with Authorization Code + PKCE.

Required configuration values: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_REDIRECT_URI`, `AZURE_MCP_SCOPE`, and `AZURE_MCP_URL`.

Rules: no client secret; no certificate/private key introduced for R1; no RBAC role assignment creation or modification; the signed-in principal must already possess sufficient read permissions; if required read access is missing, deployment stops and the gateway does not remediate RBAC.

## G2 — Container gate

- Python 3.12 or later approved base image.
- Non-root process.
- HTTPS terminated by Azure ingress.
- No persistent token volume.
- No environment variable containing access tokens, refresh tokens, secrets, storage keys or connection strings.
- Process-local session storage only for the isolated single-replica proof.

## G3 — Azure hosting gate

Preferred first target: Azure Container Apps in the existing Platform B1 Azure environment, one replica for the controlled proof.

Planned configuration: HTTPS ingress, one replica, `/healthz` on port 8000, platform logs for evidence events, no privileged container mode, and no mounted Azure credentials.

No resource group, Container Apps Environment, Log Analytics workspace, role assignment, managed identity or networking resource is created by this R1 branch. Existing suitable resources must be inventoried before any deployment command is proposed.

## G4 — Evidence gate

Before the first live MCP call, confirm logs capture OAuth policy events, hashed session reference, requested tool name, allow/deny decision, argument names, upstream status and content type, while excluding Authorization headers, tokens, secrets, keys, connection strings, cookies and raw session IDs.

## G5 — Live read-only proof gate

Run only:

1. `subscription_list`
2. `group_list`
3. `group_resource_list` against one selected existing resource group

Expected result: inventory data only; no Azure state change.

Negative tests must continue to deny unlisted tools, create/update/delete/write/action operations, RBAC/role-assignment operations, Key Vault secret operations, storage key/list-keys operations, and credential/connection-string operations.

## G6 — Expansion gate

Any additional Azure MCP tool requires exact identifier reconciliation, `Read Only = true`, `Secret = false`, no authorization-state changes, no sensitive-return path, added tests, and draft-PR review before entering the allow-list.

## Deployment sequence after explicit authorization

1. Capture existing Azure hosting inventory using read-only commands only.
2. Resolve the existing Entra public-client registration and exact delegated Azure MCP scope without retrieving credentials.
3. Confirm the approved callback URI; any Entra application mutation requires separate authorization outside this R1 execution.
4. Build and test the container artifact.
5. Secret-scan the artifact and Git diff.
6. Deploy one gateway replica into an already-approved Azure hosting boundary.
7. Perform PKCE sign-in proof.
8. Run only the three frozen R1 inventory tools.
9. Capture and verify redacted evidence logs.
10. Leave the PR in draft until the proof package is reviewed.

## Explicit stop conditions

Stop if any step requires Contributor/Owner elevation, new or changed RBAC, client-secret creation/retrieval, certificate/private-key retrieval, Key Vault secret access, storage keys, connection strings, wildcard MCP exposure, PKCE bypass, sensitive logging, catalog expansion without review, or merging/marking the PR ready without separate instruction.
