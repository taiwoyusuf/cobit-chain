# Operational Trust Passport Schema

## Platform

Platform B v0.6 - Operational Trust Passport and Ambient Evidence Mesh

## Purpose

The Operational Trust Passport is a structured evidence container that explains whether a person, room, equipment item, procedure step, environmental state, time window, and action can be trusted at the moment of work.

The passport does not approve work by itself.

The passport makes operational trust visible, reviewable, portable, and challenge-ready.

## Core doctrine

A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.

## Continuity from v0.5

The device senses. Platform B assures.

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Passport object types

| Passport type | Meaning |
|---|---|
| Person Trust Passport | Operator or reviewer is trained, authorized, present, and linked to the action context |
| Room Trust Passport | Room, hood, cleanroom, suite, or controlled area is ready for the action context |
| Equipment Trust Passport | Equipment is identified, available, status-known, and evidence-linked |
| Procedure Trust Passport | Correct procedure, version, step, and decision context are in scope |
| Environmental Trust Passport | Environmental signals are current, traceable, and admissible for the action |
| Time Trust Passport | Action is inside a valid operational, process, dose, cleaning, calibration, or review window |
| Action Trust Passport | Specific action is admissible, review-required, or not admissible |
| Site Readiness Trust Passport | Site readiness agrees across people, rooms, equipment, procedures, environment, time, and evidence |

## Required passport fields

| Field | Description |
|---|---|
| passport_id | Unique passport identifier |
| passport_type | Person, room, equipment, procedure, environmental, time, action, or site readiness |
| controlled_object_id | Asset, room, person, procedure, workflow, or action being assessed |
| controlled_object_label | Human-readable object name |
| workflow_context | Work context being evaluated |
| action_context | Specific action under review |
| context_window_start | Start of evidence validity window |
| context_window_end | End of evidence validity window |
| trust_state | assured, partially_assured, not_assured, pending, expired, or retired |
| action_admissibility | proceed, review_required, stop, expired, or not_applicable |
| evidence_mesh_id | Link to supporting evidence mesh |
| context_witness_events | QR, NFC, wearable, IoT, EMS, Lasair, manual, upload, or system witness events |
| evidence_bundle_refs | Evidence records, exports, logs, screenshots, attestations, or review packets |
| reviewer_required | True or false |
| reviewer_id | Reviewer identity when review is required or completed |
| reviewer_decision | approved_to_proceed, rejected, escalated, or pending |
| exception_state | none, yellow, red, escalated, or closed |
| integrity_state | complete, incomplete, stale, conflicting, or unverifiable |
| generated_at | Passport generation timestamp |
| generated_by | System, user, or demo process that generated the passport |
| guardrail_status | Demonstrator-only, non-production, no validated-use claim |

## Example passport

```json
{
  "passport_id": "OTP-DEMO-0001",
  "passport_type": "Equipment Trust Passport",
  "controlled_object_id": "EQP-DEMO-SPEEDYGLOVE-001",
  "controlled_object_label": "Speedy Glove Demo Equipment",
  "workflow_context": "black_box_evidence_gateway",
  "action_context": "equipment_status_review",
  "context_window_start": "2026-07-04T09:00:00Z",
  "context_window_end": "2026-07-04T17:00:00Z",
  "trust_state": "partially_assured",
  "action_admissibility": "review_required",
  "evidence_mesh_id": "AEM-DEMO-0001",
  "context_witness_events": ["CTX-DEMO-QR-001", "CTX-DEMO-UPLOAD-001"],
  "evidence_bundle_refs": ["EV-DEMO-EQP-001", "EV-DEMO-REVIEW-001"],
  "reviewer_required": true,
  "reviewer_id": "Demo Reviewer 001",
  "reviewer_decision": "pending",
  "exception_state": "yellow",
  "integrity_state": "incomplete",
  "generated_at": "2026-07-04T12:00:00Z",
  "generated_by": "Platform B v0.6 demo",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Evidence mesh dependency

A passport is only as strong as the evidence mesh supporting it.

The passport should never hide evidence gaps. It should expose them clearly as yellow or red trust conditions.

## Guardrails

This schema is for a controlled non-production demonstrator.

It does not support patient use, batch release, shipment release, clinical use, regulatory submission use, validated GMP use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
