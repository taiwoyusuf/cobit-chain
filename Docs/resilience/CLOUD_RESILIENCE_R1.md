# COBIT-Chain Cloud Resilience R1

Status: PREPARED_FOR_AZURE_BACKUP_ACTIVATION

Purpose: remove the local workstation as a single point of failure while preserving GitHub as the primary source-control record and Azure as an independently recoverable secondary cloud copy.

## Backup object set

Each successful run creates:
- a full Git bundle containing all fetched refs and tags;
- a commit-addressed repository archive;
- SHA-256 checksums;
- a run manifest.

Target Azure container: `cobit-chain`.

## Required Azure/GitHub configuration before activation

GitHub repository secrets:
- `AZURE_BACKUP_CLIENT_ID`
- `AZURE_BACKUP_TENANT_ID`
- `AZURE_BACKUP_SUBSCRIPTION_ID`

GitHub repository variable:
- `AZURE_BACKUP_STORAGE_ACCOUNT`

The federated Azure identity must have only the permissions required to upload and verify blobs in the dedicated backup storage account/container.

## Protection requirements

The Azure storage account should use:
- blob versioning;
- blob soft delete;
- container soft delete;
- secure transfer required;
- public blob access disabled;
- least-privilege RBAC;
- lifecycle rules for retained backup generations.

Immutable retention may be added later for sealed evidence after a separate retention-policy decision.

## Execution semantics

`GITHUB_COMMIT != AZURE_RUNTIME_DEPLOYMENT`

`AZURE_BACKUP_CREATED != APPLICATION_VALIDATED`

`BACKUP_SURVIVES != RESTORE_PROVEN`

A separate restore exercise is required before disaster-recovery closure can be claimed.
