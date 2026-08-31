# COBIT-Chain Cloud Resilience R2 — Credential-Safe Azure Backup

**Status:** `IMPLEMENTATION_CANDIDATE / NOT_YET_LIVE_VERIFIED`  
**Supersedes:** retired Cloud Resilience R1 bootstrap design in PR #56  
**Authority effect:** none

## Purpose

Provide a recoverable secondary cloud copy of the repository without introducing storage-account key retrieval, Entra application mutation, federated-credential creation, RBAC mutation, resource-group creation, storage-account creation, or container creation inside the backup workflow.

## Safety architecture

The workflow reuses the repository's already-established GitHub OIDC login path and requires the Azure storage target plus least-privilege data-plane permission to exist before execution.

The workflow itself is intentionally unable to bootstrap missing Azure authority.

`BACKUP_REQUIREMENT != AUTHORITY_TO_CREATE_BACKUP_INFRASTRUCTURE`

`OIDC_LOGIN != STORAGE_WRITE_AUTHORITY`

`BACKUP_UPLOAD_PASS != RESTORE_PROVEN`

## Backup object set

Each authorized successful run creates:

- full Git bundle of fetched refs/tags;
- commit-addressed source archive;
- SHA-256 checksum manifest;
- bounded run manifest.

The destination prefix is commit/run addressed and upload uses `--overwrite false`.

## Explicit prohibitions

The workflow must not contain or perform:

- `az storage account keys list`;
- account-key/shared-key authentication;
- Entra application/service-principal mutation;
- federated credential creation;
- RBAC assignment creation or elevation;
- resource group creation;
- storage account/container creation;
- secret/key/connection-string retrieval;
- application deployment.

## Required pre-existing configuration

- repository variable: `AZURE_BACKUP_STORAGE_ACCOUNT`;
- target container: `cobit-chain`;
- the existing repository OIDC principal must already have only the data-plane permission required to upload/read existence metadata in that container.

If any prerequisite is absent, the workflow stops without broadening authority.

## Verification states

Repository/PR guard may establish:

`CLOUD_RESILIENCE_R2_STATIC_BOUNDARY = PASS`

Only a successful manually authorized run on `main` may establish:

`AZURE_BACKUP_UPLOAD = PASS`

A separately executed restore challenge is required to establish:

`RESTORE_VERIFICATION = PASS`

Until then:

`RESTORE_VERIFICATION = NOT_ESTABLISHED`

## Evidence boundary

This implementation is source-control resilience only. It does not constitute production validation, regulated evidence retention qualification, immutable legal hold, disaster-recovery closure, or proof that all external services can be reconstructed.
