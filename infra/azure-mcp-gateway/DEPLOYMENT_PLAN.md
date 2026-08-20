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
        | delegated bearer token
        v
Azure MCP remote endpoint
https://mcp.management.azure.com
```

Azure API Management may be introduced as a later front-door policy layer after R1 proves the application policy boundary. It is not required for the first controlled deployment and must not be used to weaken application-level authorization.

## Deployment gates

### G0 — Repository gate

Required before any Azure deployment action:

- Draft PR remains open.
- R1 policy tests pass.
- No secrets, tokens, keys, connection strings or private credentials are present in the diff.
- Allow-list contains no wildcard.
- Executable tool list remains exactly `subscription_list` and `group_list` unless a separately reviewed R1 change expands it.
- `group_resource_list` remains denied until its live remote catalog metadata is reconciled and recorded.

### G1 — Identity contract gate

Use an existing Microsoft Entra public-client / delegated OAuth registration compatible with Authorization Code + PKCE.

Required configuration values:

- `AZURE_TENANT_ID`
- `AZURE_CLIENT_ID`
- `AZURE_REDIRECT_URI`
- `AZURE_MCP_SCOPE`
- `AZURE_MCP_URL`

Rules:

- No client secret.
- No certificate/private key introduced for R1.
- No RBAC role assignment creation or modification by this workstream.
- The signed-in user/principal must already possess sufficient read permissions for the intended Azure inventory scope.
- If required read access is missing, deployment stops and the access gap is documented; the gateway does not remediate RBAC.

### G2 — Container gate

Build a minimal Python container from this directory.

Runtime requirements:

- Python 3.12 or later approved base image.
- Non-root process.
- HTTPS terminated by Azure ingress.
- No persistent token volume.
- No environment variable containing access tokens, refresh tokens, secrets, storage keys or connection strings.
- Process-local session storage is acceptable only for the first isolated technical proof; shared/multi-replica deployment requires an encrypted server-side session design before scaling beyond one replica.

### G3 — Azure hosting gate

Preferred first target: Azure Container Apps in the existing Platform B1 Azure environment, with a single replica for the controlled proof.

Planned configuration:

- ingress: HTTPS only;
- minimum replicas: 1 during controlled proof;
- maximum replicas: 1 until session storage is redesigned;
- health probe: `GET /healthz`;
- application port: 8000;
- outbound network access restricted to Microsoft Entra endpoints and the Azure MCP endpoint where practical;
- platform logs enabled for evidence events;
- no privileged container mode;
- no mounted Azure credentials.

No resource group, Container Apps Environment, Log Analytics workspace, role assignment, managed identity or networking resource is created by this R1 branch. Existing suitable resources must be inventoried before any deployment command is proposed.

### G4 — Evidence gate

Before the first live MCP call, confirm logs capture:

- OAuth start/callback policy events without tokens;
- hashed session reference;
- requested tool name;
- allow/deny decision;
- argument names, but not credential values;
- upstream HTTP status and content type;
- error class without bearer token or response-secret leakage.

Evidence logs must never contain:

- `Authorization` headers;
- access tokens;
- refresh tokens;
- ID tokens;
- secrets;
- keys;
- connection strings;
- cookies/session IDs in raw form.

### G5 — Live read-only proof gate

Run only these R1 proof calls:

1. `subscription_list`
2. `group_list`

Expected result: inventory data only; no Azure state change.

Negative tests must demonstrate denial of at least:

- an unlisted tool;
- a create/update/delete-style tool name;
- an RBAC/role-assignment tool name;
- a Key Vault secret operation;
- a storage key/list-keys operation;
- a credential/connection-string operation.

### G6 — Expansion gate

Any additional Azure MCP tool requires all of the following before entering `config/allowlist.json`:

1. exact live tool identifier;
2. Azure MCP annotation confirms `Read Only = true`;
3. Azure MCP annotation confirms `Secret = false`;
4. operation does not alter RBAC or authorization state;
5. operation does not return credentials, keys, connection strings or secret material;
6. test coverage is added;
7. draft PR review records the expansion.

## Deployment sequence after explicit authorization

1. Reconcile existing Azure hosting resources using read-only inventory only.
2. Resolve the existing Entra client registration and exact delegated Azure MCP scope without retrieving credentials.
3. Set the approved callback URI in deployment configuration; any Entra application mutation requires separate authorization outside this R1 execution.
4. Build the container artifact.
5. Run unit tests and secret scan against the artifact and Git diff.
6. Deploy one gateway replica into an already-approved Azure hosting boundary.
7. Perform PKCE sign-in proof.
8. Run `subscription_list` and `group_list` only.
9. Capture evidence logs and verify redaction.
10. Leave the PR in draft until the proof package is reviewed.

## Explicit stop conditions

Stop deployment planning/execution if any step requires:

- Contributor/Owner elevation;
- new or changed RBAC assignment;
- client-secret creation/retrieval;
- certificate/private-key retrieval;
- Key Vault secret access;
- storage key or connection-string retrieval;
- wildcard MCP tool exposure;
- bypassing PKCE;
- logging bearer tokens or raw session identifiers;
- merging or marking the PR ready without separate instruction.
