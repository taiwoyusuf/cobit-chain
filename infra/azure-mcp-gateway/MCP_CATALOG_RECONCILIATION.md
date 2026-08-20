# Azure MCP Gateway R1 — Tool Catalog Reconciliation

Date: 2026-08-20
Status: COMPLETE FOR R1 READ-ONLY INVENTORY SURFACE

## Reconciliation rule

A tool may enter the R1 executable allow-list only when current Azure MCP documentation confirms:

- Read Only = true
- Secret = false
- the operation is inventory/read-only in purpose
- it does not modify RBAC or authorization state
- it does not return secrets, credentials, keys, connection strings, or private key material

The gateway remains deny-by-default independently of upstream MCP annotations.

## R1 verified tools

| Tool | Purpose | Read Only | Secret | R1 decision |
|---|---|---:|---:|---|
| `subscription_list` | List subscriptions visible to the current account | true | false | ALLOW |
| `group_list` | List Azure resource groups | true | false | ALLOW |
| `group_resource_list` | List resources contained in a resource group | true | false | ALLOW |

## Evidence basis

Microsoft Learn documents Azure MCP tool annotations and defines `Read Only = true` as no environment state change and `Secret = true` as a response that might contain secrets, credentials, or keys requiring sanitization.

The current Azure Subscriptions tool documentation marks List subscriptions as:

- Destructive: false
- Idempotent: true
- Read Only: true
- Secret: false
- Local Required: false

The current Azure Resource Group tool documentation marks both List resource groups and List group resources as:

- Destructive: false
- Idempotent: true
- Read Only: true
- Secret: false
- Local Required: false

Microsoft's Azure MCP repository history and current ecosystem references use the identifiers `subscription_list`, `group_list`, and `group_resource_list` for these inventory operations.

## Explicit exclusions

R1 does not enable tools merely because they are technically read-only when their response can contain sensitive values.

Example: Azure App Service application-settings retrieval is documented as Read Only = true but Secret = true because settings can contain connection strings and other sensitive values. It is therefore excluded from R1.

Key Vault secret retrieval, storage key/list-keys operations, credentials, connection strings, RBAC changes, and all write/update/delete/action operations remain prohibited.

## Defense in depth

Upstream annotations are an evidence input, not the enforcement boundary. R1 still applies:

1. exact explicit allow-list matching;
2. prohibited-name screening;
3. token/header/evidence redaction;
4. deny-by-default behavior;
5. draft-PR deployment governance.

## R1 catalog conclusion

`subscription_list`, `group_list`, and `group_resource_list` are accepted as the complete R1 Azure inventory surface for the next live proof. No additional Azure MCP tool is authorized by this reconciliation.
