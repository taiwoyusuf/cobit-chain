# Deviation CAPA Capture and Review Model

## Purpose

Define how RAMAT Vision devices may capture deviation and CAPA-related context without closing deviations or CAPA.

## Platform rule

Wearable capture is not approval.

AI output is not approval.

Platform B decides.

## Supported functions

- Deviation / CAPA Capture Mode
- ALCOA+ Evidence Capture
- Guided SOP Overlay
- Ask-the-Asset Mode
- Batch Passport View
- Equipment Passport View

## Required objects

- DeviationDraftRecord
- CAPAEvidenceRecord
- ALCOAEvidenceRecord
- GuidedSOPStepRecord
- BatchPassportSnapshot
- EquipmentPassportSnapshot
- ActionAdmissibilityRecord
- HumanIntentConfirmation

## Capture states

- DEVIATION_CONTEXT_CAPTURED
- CAPA_EVIDENCE_CAPTURED
- REVIEWER_REQUIRED
- EVIDENCE_INCOMPLETE
- CAPTURE_EVIDENCE
- HOLD_MAINTAINED

## Forbidden actions

- The wearable does not close deviations.
- The wearable does not close CAPA.
- The wearable does not make final root-cause determinations.
- The wearable does not approve CAPA effectiveness.

## Guardrail

Deviation and CAPA capture supports evidence reconstruction and review. It does not replace the quality system.
