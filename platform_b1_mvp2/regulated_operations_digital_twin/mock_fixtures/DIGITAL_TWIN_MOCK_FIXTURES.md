# Regulated Operations Digital Twin Mock Fixtures

Status: LOCKED MOCK FIXTURES ONLY

Workstream: Platform B1 / MVP2

## Purpose

These mock fixtures provide first software-defined object states for the Regulated Operations Digital Twin.

They cover the three first-tier tracks:

1. Compound Pharmacy
2. IRLT / Radiopharma Operations
3. DSCSA Evidence Integrity & Exception Assurance

These fixtures do not build a validator yet.

These fixtures do not deploy Azure resources.

These fixtures do not connect to real production systems.

## Fixture 1 — Compound Pharmacy Preparation Package Review

File:

`compound_pharmacy_preparation_package_review.json`

Expected outputs:

- COMPOUNDING EVIDENCE SEALED
- HASH VERIFIED
- BUD EVIDENCE REVIEW REQUIRED
- AI CONTENT REVIEW REQUIRED
- HUMAN REVIEW REQUIRED
- QUALITY REVIEW REQUIRED
- COMPOUNDING WORKFLOW APPEARS COMPLETE BUT BLOCKED
- COMPOUNDING PACKAGE NOT YET DEFENSIBLE

## Fixture 2 — IRLT Equipment / CI / Quality Handoff Review

File:

`irlt_equipment_ci_quality_handoff_review.json`

Expected outputs:

- IRLT EVIDENCE SEALED
- HASH VERIFIED
- CI READINESS GAP
- SUPPORT GROUP MISSING
- INCIDENT IMPACT REVIEW REQUIRED
- QUALITY DEPENDENCY BLOCKED
- AI RECOMMENDATION REVIEW REQUIRED
- RAMAT VISION DISPLAY READY
- HUMAN REVIEW REQUIRED
- IRLT WORKFLOW APPEARS COMPLETE BUT BLOCKED

## Fixture 3 — Late EPCIS / VRS No Response Exception

File:

`dscsa_late_epcis_vrs_no_response_exception.json`

Expected outputs:

- DSCSA EXCEPTION DETECTED
- EPCIS FILE MISMATCH
- VRS RESPONSE MISSING
- TRADING PARTNER EVIDENCE STALE
- AI EXCEPTION CLASSIFICATION GENERATED
- HUMAN REVIEW REQUIRED
- QUARANTINE REQUIRED
- EXCEPTION NOT DEFENSIBLE

## Boundary

Mock fixtures only.

Do not build validator yet.

Do not deploy Azure Digital Twins.

Do not deploy Azure resources.

Do not connect to real production systems.

No real ServiceNow production data.

No real LIS, MES, ERP, eQMS, QMS, VRS, EPCIS, pharmacy, or radiopharma production data.

No PHI.

No company production data.

No product release decision.

No GMP approval decision.

No source-system override.

No Quality Unit replacement.

Platform B1 evaluates.

Thread D2 displays.

RAMAT Vision displays only.

Official records remain in source systems.

Humans remain accountable.

## Next order of work

1. Commit digital twin mock fixtures.
2. Merge digital twin mock fixtures.
3. Create digital twin mock fixture validator.
4. Add mock validator to existing orchestration smoke after validator is locked.
