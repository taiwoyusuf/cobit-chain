# Azure MCP Gateway R1

Read-only, PKCE-compliant gateway scaffold for controlled access to Azure MCP from COBIT-Chain / Platform B1.

## R1 invariant

R1 is **read-only**. It must not perform Azure mutations, RBAC changes, secret/key retrieval, credential export, or any operation outside the explicit allow-list.

## Upstream Azure MCP

- Default endpoint: `https://mcp.management.azure.com`
- Tenant ID, public client ID, redirect URI and delegated scope are deployment configuration supplied through environment variables.
- Additional OAuth scope may include `offline_access` when the registered client and upstream authorization contract require refresh tokens.
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
  - token held only in server-side session boundary
  - explicit tool allow-list
  - deny-by-default policy enforcement
  - evidence event generation
        |
        | bearer token, allowed read-only call only
        v
Azure MCP
https://mcp.management.azure.com
        |
        v
Azure Resource Manager read surfaces
```

## Security boundary

The gateway SHALL:

1. require PKCE (`S256`) for interactive authorization;
2. never require or store a client secret;
3. deny any tool or operation not explicitly present in `config/allowlist.json`;
4. deny operation names associated with create/update/delete/write/action/assign/grant/role/permission/key/secret/credential flows even if accidentally added to a broader upstream surface;
5. never expose OAuth access or refresh tokens in application logs or evidence records;
6. generate an evidence event for each policy decision and upstream invocation attempt;
7. keep R1 deployment planning separate from deployment execution.

## Reconciled R1 allow-list

The executable R1 inventory surface is:

- `subscription_list`
- `group_list`
- `group_resource_list`

Each has been reconciled against current Azure MCP documentation as read-only and non-secret. No other Azure MCP tool is authorized for R1.

See `MCP_CATALOG_RECONCILIATION.md` for the evidence decision record.

## R1 files

- `app/main.py` - FastAPI gateway shell and OAuth callback surface.
- `app/auth.py` - PKCE generation and OAuth URL/token-exchange helpers.
- `app/policy.py` - deny-by-default allow-list and prohibited-operation checks.
- `app/evidence.py` - structured evidence logging with token/header redaction.
- `config/allowlist.json` - R1 permitted read-only MCP tools.
- `tests/test_policy.py` - policy invariants.
- `MCP_CATALOG_RECONCILIATION.md` - current tool annotation reconciliation.
- `DEPLOYMENT_PLAN.md` - deployment plan only; no deployment is performed by R1.

## Non-goals for R1

- Azure resource creation, update, deletion, restart, redeploy, or configuration mutation.
- RBAC assignment or role-definition changes.
- Key Vault secret retrieval, storage-account key retrieval, connection-string retrieval, credential listing/export, or token introspection endpoints that disclose credentials.
- Autonomous execution.
- Production rollout.

## Status

Scaffold and deployment-readiness preparation only. Draft PR required. Deployment remains gated until live Azure inventory is captured through an authorized Azure-connected execution path.
