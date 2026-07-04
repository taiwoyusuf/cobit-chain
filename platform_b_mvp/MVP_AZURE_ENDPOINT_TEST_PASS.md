# Platform B MVP Azure Endpoint Test Pass

## Status

PASS

## Deployment target

Resource Group: rg-cobitchain-platformb-mvp-dev
Function App: func-cobitchain-pbmvp-61806
Base API: https://func-cobitchain-pbmvp-61806.azurewebsites.net/api

## Deployment result

Azure Function zip deployment completed successfully.

Function App kind:

functionapp,linux

## Endpoint test result

The deployed Platform B MVP Azure Functions were tested successfully.

### Tested MVP capabilities

1. AI Use Case Registry
2. Action Admissibility Record
3. Evidence Upload
4. Assurance Check API
5. Wearable Endpoint Simulator
6. Operational Trust Score

## Test evidence

Use Case ID: UC-ded9c5f62207
Evidence ID: EV-632cc1636544
Action Record ID: AAR-7402be32027e
Assurance Check ID: CHK-77008bfd6bac
Wearable Signal ID: WRS-9705ef980361
Trust Score ID: TS-7c17bf0709ee

## Observed endpoint outputs

Health endpoint returned:

- status: ok
- platform: Platform B MVP
- mode: mvp
- platform_b_v1_frozen: true

AI Use Case Registry returned:

- status: registered
- lifecycle_stage: Governance
- risk_class: medium

Action Admissibility Record returned:

- admitted: true
- admissibility_state: admitted_before_execution

Evidence Upload returned:

- evidence_status: uploaded
- blob_container: evidence-files
- blob_name: UC-ded9c5f62207/EV-632cc1636544/qa_review_note.txt

Assurance Check returned:

- readiness_points: 100
- status: assurance_ready_for_review

Wearable Endpoint Simulator returned:

- context_assured: true
- context_assurance_state: context_assured
- simulated_endpoint: true

Operational Trust Score returned:

- score: 60
- trust_state: partial_trust_evidence
- evidence_count: 1
- assurance_check_count: 1
- action_admissibility_count: 1
- wearable_signal_count: 1

## Interpretation

The Platform B MVP is now deployed and operational on Azure.

This confirms that the MVP implementation layer can register an AI use case, record pre-execution action admissibility, upload evidence, record assurance checks, simulate context-assurance wearable signals, and calculate an operational trust score.

## Guardrail

Platform B v1 remains frozen.

This test pass does not add lifecycle stages, modules, pillars, dashboards, or new foundational architecture.
