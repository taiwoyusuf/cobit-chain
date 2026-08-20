# Azure MCP Gateway R1 — Tool Catalog Reconciliation

Date: 2026-08-20
Status: **COMPLETE AND FROZEN FOR R1 READ-ONLY INVENTORY SURFACE**

## Admission rule

A tool may enter the R1 executable allow-list only when current Azure MCP documentation confirms:

- Read Only = true
- Secret = false
- the operation is inventory/read-only in purpose
- it does not modify RBAC or authorization state
- it does not return secrets, credentials, keys, connection strings, or private-key material

The gateway remains deny-by-default independently of upstream MCP annotations.

## R1 verified tools

| Tool | Purpose | Read Only | Secret | R1 decision |
|---|---|---:|---:|---|
| `subscription_list` | List subscriptions visible to the current account | true | false | ALLOW |
| `group_list` | List Azure resource groups | true | false | ALLOW |
| `group_resource_list` | List resources contained in a resource group | true | false | ALLOW |

## Evidence basis

Microsoft Learn defines `Read Only = true` as an operation that does not change environment state and `Secret = true` as an operation whose response might contain secrets, credentials, or keys requiring sanitization.

Current Microsoft Azure MCP documentation marks List subscriptions, List resource groups, and List group resources as read-only and non-secret. Current Azure MCP ecosystem references use the identifiers `subscription_list`, `group_list`, and `group_resource_list` for these inventory operations.

## Explicit exclusions

R1 does not enable a tool merely because it is read-only. A read-only operation is still excluded when its response can contain sensitive values.

Example: Azure App Service application-settings retrieval is documented as Read Only = true but Secret = true because settings can contain connection strings and other sensitive values. It is excluded from R1.

Key Vault secret retrieval, storage key/list-keys operations, credentials, connection strings, RBAC changes, and all write/update/delete/action operations remain prohibited.

## Defense in depth

Upstream annotations are evidence inputs, not the enforcement boundary. R1 still applies exact allow-list matching, prohibited-name screening, token/header/evidence redaction, deny-by-default behavior, test enforcement, and draft-PR deployment governance.

## Frozen R1 catalog conclusion

`subscription_list`, `group_list`, and `group_resource_list` are the complete R1 Azure inventory surface for the next live proof.

The matching allow-list declares `catalog_state = frozen`, and CI enforces that every admitted tool has a verified `read_only=true` and `secret=false` evidence entry.

No additional Azure MCP tool is authorized by this reconciliation. Any expansion requires a new evidence decision and test change in the draft PR.
