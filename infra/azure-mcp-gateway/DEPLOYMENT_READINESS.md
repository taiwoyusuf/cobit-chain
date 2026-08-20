# Gateway R1 — Deployment Readiness Gate

Status: **READY FOR READ-ONLY AZURE INVENTORY; NOT YET DEPLOYED**

## Completed

- Draft PR remains open.
- CI baseline passes.
- PKCE and deny-by-default policy are implemented.
- Secret/key/RBAC/write operations remain prohibited.
- Deployment guardrail tests are present.
- Azure MCP catalog reconciliation is complete and frozen.

## Frozen R1 live-proof tools

- `subscription_list`
- `group_list`
- `group_resource_list`

No additional Azure MCP tool is authorized.

## Next live gate

Use an authenticated Azure-connected execution path for read-only inventory only:

1. current account / tenant / subscription metadata;
2. existing resource groups;
3. existing Azure Container Apps environments;
4. existing Azure Container Apps applications;
5. select one existing resource group for the scoped `group_resource_list` proof;
6. identify whether an already-approved hosting boundary exists for one gateway replica.

The live inventory must not retrieve secrets, keys, connection strings or credentials, and must not modify RBAC or Azure resource state.

## Stop conditions

Do not proceed if the inventory or later deployment would require RBAC creation/change, Contributor/Owner elevation, sensitive-value retrieval, creation of a new Azure hosting boundary without separate authorization, widening the frozen R1 allow-list, or an ungated Azure mutation workflow.

## Current canonical state

`CI_PASS_BASELINE / MCP_CATALOG_RECONCILED_AND_FROZEN / DEPLOYMENT_READINESS_PREPARED / AZURE_INVENTORY_NOT_YET_CAPTURED`

## Next status transition

Only after read-only Azure inventory is captured can the state move to:

`AZURE_INVENTORY_RECONCILED / DEPLOYMENT_COMMANDS_PREPARED`

Actual deployment remains a later explicit action.
