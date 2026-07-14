# Step 164 - First-Tier Triad Assurance Orchestrator and Evidence Passport API

This implementation is local, synthetic, non-production, and read-only.

Equal first-tier tracks:

- IRLT and radiopharmaceutical assurance
- Compounding pharmacy assurance
- DSCSA and pharmaceutical supply-chain assurance

Four scenarios are executed for each track:

1. Baseline success
2. Evidence-tamper failure
3. Domain-specific dependency failure
4. Verified recovery success

Read-only API resources:

- GET /health
- GET /tracks
- GET /scenarios
- GET /evaluation/{track}/{baseline|tamper|domain_failure|recovery}
- GET /passport/{track}
- GET /ramat/{track}
- GET /reconstruction/{track}

The API may bind only to 127.0.0.1.

POST, PUT, PATCH, and DELETE are rejected with HTTP 405.

Manual local API command:

py -3 .\src\orchestrator_api.py --project-root . serve --host 127.0.0.1 --port 8765

Boundaries:

- Platform B v1 is not modified.
- Thread D v1 is not modified.
- No production source system is connected.
- No production write-back is supported.
- No PHI or company production data is used.
- No product is released, dispensed, administered, transferred, or shipped.
- RAMAT Vision remains DISPLAY / WITNESS ONLY.
- Qualified human authority remains required.
- Official source-system execution remains required.