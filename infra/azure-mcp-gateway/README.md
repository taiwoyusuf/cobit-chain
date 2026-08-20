# Azure MCP Gateway R1

Read-only, PKCE-compliant gateway scaffold for controlled access to Azure ARM MCP from COBIT-Chain / Platform B1.

## R1 invariant

R1 is **read-only**. It must not perform Azure mutations, RBAC changes, secret/key retrieval, credential export, or any operation outside the explicit allow-list.

## Upstream Azure ARM MCP

- Endpoint: `https://mcp.management.azure.com`
- Entra application: `ChatGPT COBIT-Chain Azure ARM`
- Client ID: `1054f42d-2133-42f3-a024-a1ea065e8b53`
- Tenant ID: `f8683fda-4956-4620-9e26-a1a14bbec914`
- Delegated scope: `api://22bfbae3-f4e7-485f-be43-8cee15065084/MCP.Access`
- Additional OAuth scope: `offline_access`

No client secret is used by this R1 scaffold. Authorization Code + PKCE is the required browser flow.

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
Azure ARM MCP
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

## R1 files

- `app/main.py` - FastAPI gateway shell and OAuth callback surface.
- `app/auth.py` - PKCE generation and OAuth URL/token-exchange helpers.
- `app/policy.py` - deny-by-default allow-list and prohibited-operation checks.
- `app/evidence.py` - structured evidence logging with token/header redaction.
- `config/allowlist.json` - R1 permitted read-only MCP tools.
- `tests/test_policy.py` - policy invariants.
- `DEPLOYMENT_PLAN.md` - deployment plan only; no deployment is performed by R1.

## Non-goals for R1

- Azure resource creation, update, deletion, restart, redeploy, or configuration mutation.
- RBAC assignment or role-definition changes.
- Key Vault secret retrieval, storage-account key retrieval, connection-string retrieval, credential listing/export, or token introspection endpoints that disclose credentials.
- Autonomous execution.
- Production rollout.

## Status

Scaffold only. Draft PR required. Deployment remains a planning activity until separately authorized.
