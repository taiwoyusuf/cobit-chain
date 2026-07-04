# Platform B MVP Storage Model

## Azure Table Storage

### UseCaseRegistry

PartitionKey: USECASE
RowKey: use_case_id

Stores AI use case registry records.

### AssuranceChecks

PartitionKey: use_case_id
RowKey: assurance_check_id

Stores assurance check records.

### EvidenceMetadata

PartitionKey: use_case_id
RowKey: evidence_id

Stores metadata for evidence uploaded to Blob Storage.

### TrustScores

PartitionKey: use_case_id
RowKey: trust_score_id

Stores operational trust score snapshots.

### ActionAdmissibilityRecords

PartitionKey: use_case_id
RowKey: action_record_id

Stores pre-execution action admissibility records.

### WearableSignals

PartitionKey: use_case_id
RowKey: wearable_signal_id

Stores simulated wearable/context assurance signals.

## Azure Blob Storage

### evidence-files

Stores uploaded evidence files.

Path convention:

use_case_id/evidence_id/file_name

## Security model

The deployed Function App uses managed identity and Azure RBAC.

Local secrets must not be committed.
