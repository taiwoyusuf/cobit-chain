# Action Admissibility Ledger Schema

## Platform

Platform B v0.6 - Operational Trust Passport and Ambient Evidence Mesh

## Purpose

The Action Admissibility Ledger records why a regulated action was allowed, blocked, expired, or routed for review under the Platform B v0.6 demo rule set.

The ledger does not approve work by itself.

The ledger makes the decision path visible, reviewable, and challenge-ready.

## Core doctrine

A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.

## Continuity from v0.5

The device senses. Platform B assures.

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Ledger decision states

| Decision state | Meaning |
|---|---|
| proceed | Evidence supports action under the demo rule set |
| review_required | Evidence exists but requires qualified human review |
| stop | Required evidence is missing, failed, conflicting, or not admissible |
| expired | Evidence or action window is no longer valid |
| not_applicable | Ledger entry is informational and does not determine the action |

## Required ledger fields

| Field | Description |
|---|---|
| ledger_entry_id | Unique action admissibility ledger entry identifier |
| action_id | Unique action being evaluated |
| action_label | Human-readable action name |
| workflow_context | Workflow or operational context |
| action_context | Specific action context |
| actor_id | Operator, reviewer, system, or demo actor associated with the action |
| controlled_object_refs | Person, room, equipment, procedure, environment, time, or site readiness objects involved |
| evidence_mesh_id | Ambient Evidence Mesh supporting the decision |
| passport_refs | Operational Trust Passports supporting the decision |
| context_witness_events | Linked QR, NFC, wearable, IoT, EMS, Lasair, manual, upload, or system witness events |
| evidence_bundle_refs | Evidence records, exports, logs, screenshots, attestations, or review packets |
| required_evidence | Evidence required before the action can proceed |
| missing_evidence | Required evidence that is absent |
| stale_evidence | Evidence that is outside its validity window |
| conflicting_evidence | Evidence that conflicts with another signal or record |
| trust_state | assured, partially_assured, not_assured, pending, expired, or retired |
| action_admissibility | proceed, review_required, stop, expired, or not_applicable |
| exception_state | none, yellow, red, escalated, closed, or expired |
| reviewer_required | True or false |
| reviewer_id | Reviewer identity when review is required or completed |
| reviewer_decision | approved_to_proceed, rejected, escalated, or pending |
| decision_reason | Human-readable explanation of the decision |
| generated_at | Ledger generation timestamp |
| generated_by | System, user, or demo process that generated the ledger entry |
| guardrail_status | Demonstrator-only, non-production, no validated-use claim |

## Rule categories

| Rule category | Example question |
|---|---|
| person_rule | Is the actor trained, authorized, and linked to the action context? |
| room_rule | Is the room, hood, cleanroom, suite, or controlled area ready? |
| equipment_rule | Is the equipment identified, available, status-known, and evidence-linked? |
| procedure_rule | Is the correct procedure version and step in scope? |
| environment_rule | Are environmental signals current, traceable, and admissible? |
| time_rule | Is the action inside the valid operational, dose, cleaning, calibration, or review window? |
| evidence_rule | Is required evidence present, complete, and coherent? |
| reviewer_rule | Is human review required, pending, approved, or rejected? |
| exception_rule | Does a yellow, red, expired, or escalated exception exist? |

## Example ledger entry

```json
{
  "ledger_entry_id": "AAL-DEMO-0001",
  "action_id": "ACT-DEMO-STATUS-REVIEW",
  "action_label": "Equipment status review before action",
  "workflow_context": "black_box_evidence_gateway",
  "action_context": "equipment_status_review",
  "actor_id": "Demo Operator 001",
  "controlled_object_refs": ["EQP-DEMO-SPEEDYGLOVE-001"],
  "evidence_mesh_id": "AEM-DEMO-0001",
  "passport_refs": ["OTP-DEMO-0001"],
  "context_witness_events": ["CTX-DEMO-QR-001"],
  "evidence_bundle_refs": ["EV-DEMO-REVIEW-001"],
  "required_evidence": ["equipment_identity", "equipment_status", "review_packet"],
  "missing_evidence": [],
  "stale_evidence": [],
  "conflicting_evidence": [],
  "trust_state": "partially_assured",
  "action_admissibility": "review_required",
  "exception_state": "yellow",
  "reviewer_required": true,
  "reviewer_id": "Demo Reviewer 001",
  "reviewer_decision": "pending",
  "decision_reason": "Evidence is linked but reviewer confirmation is required before action proceeds.",
  "generated_at": "2026-07-04T12:00:00Z",
  "generated_by": "Platform B v0.6 demo",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Relationship to v0.6 objects

The Ambient Evidence Mesh explains the evidence relationships.

The Operational Trust Passport summarizes the trust state.

The Action Admissibility Ledger records why a specific action was allowed, blocked, expired, or routed for review.

## Guardrails

This schema is for a controlled non-production demonstrator.

It does not support patient use, batch release, shipment release, clinical use, regulatory submission use, validated GMP use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
