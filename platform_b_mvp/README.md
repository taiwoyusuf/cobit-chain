# Platform B MVP

This folder contains the Platform B MVP implementation layer.

Platform B v1 remains frozen. This MVP does not add lifecycle stages, modules, dashboards, or new foundational architecture.

## Azure MVP infrastructure

Resource Group: rg-cobitchain-platformb-mvp-dev
Function App: func-cobitchain-pbmvp-61806
Storage Account: stpbmvp61806
Key Vault: kv-pbmvp-61806
Application Insights: appi-cobitchain-pbmvp-61806
Log Analytics Workspace: law-cobitchain-pbmvp-61806

## Six MVP capabilities only

1. AI Use Case Registry
2. Assurance Check API
3. Evidence Upload
4. Operational Trust Score
5. Action Admissibility Record
6. Wearable Endpoint Simulator

## API base

After deployment:

https://func-cobitchain-pbmvp-61806.azurewebsites.net/api

## Important note

Do not commit local secrets, local Azure inventory exports, local settings, or generated deployment packages.
