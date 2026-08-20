# Azure MCP Gateway R1 — Tool Catalog Reconciliation

Date: 2026-08-20
Status: **COMPLETE AND FROZEN FOR R1**

## Admission rule

A tool may enter the R1 allow-list only when current Azure MCP documentation confirms `Read Only = true` and `Secret = false`, the operation does not modify RBAC/authorization state, and it does not return credentials, keys, connection strings, or other secret material.

## Frozen R1 tools

| Tool | Purpose | Read Only | Secret | Decision |
|---|---|---:|---:|---|
| `subscription_list` | List subscriptions | true | false | ALLOW |
| `group_list` | List resource groups | true | false | ALLOW |
| `group_resource_list` | List resources in one resource group | true | false | ALLOW |

Microsoft Learn defines the Azure MCP Read Only and Secret annotations and currently marks the corresponding subscription and resource-group inventory operations as read-only and non-secret.

Read-only tools whose responses are secret-bearing remain excluded. Azure App Service application-settings retrieval is an example: read-only but secret-bearing, so it is not admitted.

The gateway independently enforces exact allow-list matching, prohibited-operation screening, evidence redaction, deny-by-default behavior, and CI checks requiring verified catalog evidence for every admitted tool.

No additional Azure MCP tool is authorized for R1.
