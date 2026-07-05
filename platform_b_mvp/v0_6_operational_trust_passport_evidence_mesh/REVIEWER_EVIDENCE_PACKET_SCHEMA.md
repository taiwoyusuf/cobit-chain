# Reviewer Evidence Packet Schema

## Platform

Platform B v0.6 - Operational Trust Passport and Ambient Evidence Mesh

## Purpose

The Reviewer Evidence Packet is a structured review bundle that gives a qualified reviewer the evidence needed to understand why an action is trusted, partially trusted, not trusted, expired, or review-required.

The packet does not replace human review.

The packet makes review faster, clearer, traceable, and challenge-ready.

## Core doctrine

A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.

## Continuity from v0.5

The device senses. Platform B assures.

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Packet sections

| Section | Purpose |
|---|---|
| review_summary | Human-readable explanation of the action, trust state, and review need |
| action_context | Action, workflow, actor, room, equipment, procedure, environment, and time context |
| evidence_mesh_summary | Summary of linked evidence relationships |
| passport_summary | Operational Trust Passports supporting the decision |
| witness_chain_summary | Ordered context witness events supporting the review |
| admissibility_summary | Action Admissibility Ledger decision and reason |
| exception_summary | Yellow, red, expired, escalated, or closed exceptions |
| evidence_gaps | Missing, stale, conflicting, or unverifiable evidence |
| reviewer_decision | Reviewer assessment, decision, rationale, and timestamp |
| export_summary | Challenge-ready review packet summary |

## Required packet fields

| Field | Description |
|---|---|
| reviewer_packet_id | Unique reviewer evidence packet identifier |
| packet_type | action_review, exception_review, readiness_review, evidence_gap_review, or closure_review |
| workflow_context | Workflow or operational context |
| action_context | Specific action being evaluated |
| actor_id | Operator, reviewer, system, or demo actor associated with the action |
| reviewer_required | True or false |
| reviewer_id | Reviewer identity when review is required or completed |
| reviewer_role | Demo reviewer role or review function |
| evidence_mesh_id | Ambient Evidence Mesh supporting the review |
| passport_refs | Operational Trust Passports included in the review packet |
| witness_chain_refs | Context Witness Chains included in the review packet |
| ledger_refs | Action Admissibility Ledger entries included in the packet |
| evidence_bundle_refs | Evidence records, exports, logs, screenshots, attestations, or review packets |
| trust_state | assured, partially_assured, not_assured, pending, expired, or retired |
| action_admissibility | proceed, review_required, stop, expired, or not_applicable |
| exception_state | none, yellow, red, escalated, closed, or expired |
| evidence_gap_summary | Missing, stale, conflicting, or unverifiable evidence summary |
| review_question | Question the reviewer must answer |
| reviewer_decision | approved_to_proceed, rejected, escalated, pending, or not_required |
| reviewer_rationale | Human-readable rationale for the review decision |
| reviewed_at | Review timestamp |
| generated_at | Packet generation timestamp |
| generated_by | System, user, or demo process that generated the packet |
| guardrail_status | Demonstrator-only, non-production, no validated-use claim |

## Review question types

| Review question type | Example question |
|---|---|
| proceed_review | Is there enough evidence to proceed under the demo rule set? |
| exception_review | Does the yellow or red exception require escalation? |
| gap_review | Is missing, stale, or conflicting evidence acceptable for demo continuation? |
| readiness_review | Is the person, room, equipment, procedure, environment, time, and evidence state coherent? |
| closure_review | Is the exception or evidence gap ready to close? |
| challenge_review | Can the evidence explain why the action was allowed, blocked, expired, or routed for review? |

## Example reviewer evidence packet

```json
{
  "reviewer_packet_id": "REP-DEMO-0001",
  "packet_type": "action_review",
  "workflow_context": "cleanroom_readiness",
  "action_context": "pre_work_room_entry_review",
  "actor_id": "Demo Operator 001",
  "reviewer_required": true,
  "reviewer_id": "Demo Reviewer 001",
  "reviewer_role": "qualified_demo_reviewer",
  "evidence_mesh_id": "AEM-DEMO-0002",
  "passport_refs": ["OTP-DEMO-ROOM-001"],
  "witness_chain_refs": ["CWC-DEMO-0001"],
  "ledger_refs": ["AAL-DEMO-0002"],
  "evidence_bundle_refs": ["EV-DEMO-ROOM-001", "EV-DEMO-EMS-001"],
  "trust_state": "partially_assured",
  "action_admissibility": "review_required",
  "exception_state": "yellow",
  "evidence_gap_summary": "Environmental and cleaning evidence require reviewer confirmation before proceeding.",
  "review_question": "Is the cleanroom readiness evidence sufficient for demo continuation?",
  "reviewer_decision": "pending",
  "reviewer_rationale": "",
  "reviewed_at": null,
  "generated_at": "2026-07-04T12:05:00Z",
  "generated_by": "Platform B v0.6 demo",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Relationship to v0.6 objects

The Context Witness Chain records the event sequence.

The Ambient Evidence Mesh connects the evidence relationships.

The Operational Trust Passport summarizes the resulting trust state.

The Action Admissibility Ledger records why the action was allowed, blocked, expired, or routed for review.

The Reviewer Evidence Packet gives the reviewer a structured, explainable packet for human decision-making.

## Guardrails

This schema is for a controlled non-production demonstrator.

It does not support patient use, batch release, shipment release, clinical use, regulatory submission use, validated GMP use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
