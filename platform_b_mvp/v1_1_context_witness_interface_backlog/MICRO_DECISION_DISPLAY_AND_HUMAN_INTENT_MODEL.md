# Micro-Decision Display and Human Intent Model

## Purpose

Define how Platform B decisions may be displayed as wearable micro-decisions and how human intent may be captured.

## Platform rule

RAMAT Vision devices display Platform B outputs. They do not generate final admissibility decisions.

## Micro-decision examples

- PROCEED
- HOLD
- ESCALATE
- CONFIRM NFC
- CAPTURE EVIDENCE
- REVIEWER REQUIRED
- TASK CONTEXT MISSING
- AUTHORITY NOT CONFIRMED
- EVIDENCE INCOMPLETE
- CONTEXT MISMATCH
- HUMAN CONFIRMATION REQUIRED
- CONTROLLED DOCUMENT REMAINS SOURCE OF TRUTH
- PRIVACY BOUNDARY ACTIVE
- STOP-LINE RECORDED

## Human intent capture

Human intent may be captured by voice, tap, button, scan confirmation, NFC confirmation, or reviewer acknowledgement.

## Required objects

- VoiceIntentRecord
- HumanIntentConfirmation
- WearableContextEvent
- ActionAdmissibilityRecord
- StopLineEvent
- ALCOAEvidenceRecord

## Intent states

- INTENT_CAPTURED
- CONFIRMATION_REQUIRED
- CONFIRMED_BY_HUMAN
- REJECTED_BY_HUMAN
- ESCALATED_TO_REVIEWER
- STOP_LINE_REQUESTED

## Guardrail

Human confirmation is evidence of human intent. It is not automatic approval unless Platform B rules and accountable review permit the action.
