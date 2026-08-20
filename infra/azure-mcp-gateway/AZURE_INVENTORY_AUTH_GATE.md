# Gateway R1 — Azure Inventory Authentication Gate

Date: 2026-08-20
Status: **CONTROLLED STOP — OIDC SUBJECT NOT TRUSTED FOR PULL REQUEST**

## Observed result

The first live read-only inventory attempt stopped at Azure authentication before any Azure CLI inventory command executed.

GitHub presented the OIDC subject:

`repo:taiwoyusuf/cobit-chain:pull_request`

Microsoft Entra rejected the assertion with `AADSTS700213` because no matching federated identity credential exists for that pull-request subject.

## Assurance conclusion

This is a correct governed stop condition, not a reason to widen identity trust.

The existing repository deployment workflow uses GitHub OIDC from the `main` branch. Gateway R1 will therefore preserve the existing identity boundary rather than adding or changing Entra federated credentials merely to permit a feature-branch or pull-request login.

## What did NOT happen

- no Azure account inventory command executed;
- no resource group inventory executed;
- no Container Apps inventory executed;
- no Azure resource was created, updated, deleted or restarted;
- no RBAC assignment was created or changed;
- no secret, key, credential or connection string was retrieved;
- no federated identity credential was added or changed.

## Approved next authentication path

The live inventory workflow is prepared to run manually from `main` after the draft PR is reviewed and merged, using the repository's already-established OIDC identity path.

The manual inventory remains limited to:

1. `az account show` with selected non-secret metadata;
2. `az group list`;
3. `az resource list --resource-type Microsoft.App/managedEnvironments`;
4. `az resource list --resource-type Microsoft.App/containerApps`;
5. governed artifact upload of the resulting inventory.

No Entra federation mutation is authorized by this gate.

## Canonical state

`CI_PASS / MCP_CATALOG_FROZEN / LIVE_INVENTORY_AUTH_GATE_IDENTIFIED / MAIN_TRUSTED_OIDC_REQUIRED / AZURE_INVENTORY_NOT_YET_CAPTURED`
