# Platform B MVP Azure Deployment Plan

## Existing MVP Azure resources

Resource Group: rg-cobitchain-platformb-mvp-dev
Function App: func-cobitchain-pbmvp-61806
Storage Account: stpbmvp61806
Key Vault: kv-pbmvp-61806
Application Insights: appi-cobitchain-pbmvp-61806
Log Analytics Workspace: law-cobitchain-pbmvp-61806

## Deployment goal

Deploy the six Azure Functions endpoints only.

## Deployment sequence

1. Scaffold function code.
2. Validate syntax locally.
3. Commit the MVP scaffold.
4. Package functions.
5. Deploy to func-cobitchain-pbmvp-61806.
6. Test the six MVP capabilities.
7. Enable Microsoft Entra ID authentication after endpoint behavior is verified.

## Guardrail

This MVP implementation layer must not change the frozen Platform B v1 architecture.
