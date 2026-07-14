# Step 160 — AURORA-17 QC and Human Batch-Release Slice

This folder contains the first local non-production Assurance OS implementation slice.

## Demonstrated behavior

1. Seal synthetic QC evidence using SHA-256.
2. Verify the unchanged evidence and produce ACTION ADMISSIBLE.
3. Modify the sealed evidence.
4. Detect REHASH MISMATCH.
5. Produce EVIDENCE INSUFFICIENT, NO-BIND STATE ACTIVE, and ACTION HELD.
6. Restore the verified local backup.
7. Rehash the restored evidence.
8. Produce ACTION ADMISSIBLE again.
9. Preserve the rule that admissibility is not execution.
10. Produce only a DISPLAY / WITNESS ONLY RAMAT contract.

## Boundaries

- Platform B v1 was not modified.
- Thread D v1 was not modified.
- No PHI or company production data is used.
- No production connector is used.
- No autonomous batch approval or release is performed.
- No real wearable integration is performed.
- Official source-system execution remains required.
- Qualified human authority remains required.

## Run locally

Use the Step 160 PowerShell workflow that created this folder.

The Python implementation uses only the Python standard library.