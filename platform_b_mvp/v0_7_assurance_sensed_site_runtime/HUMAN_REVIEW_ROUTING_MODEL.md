# Human Review Routing Model

## Platform

Platform B v0.7 - Assurance-Sensed Site Runtime

## Purpose

The Human Review Routing Model defines how Platform B v0.7 routes runtime conditions to a human reviewer when operational trust is at risk.

The model preserves human accountability by ensuring that yellow, red, expired, conflicting, missing-evidence, and reviewer-required states are converted into structured review routes and reviewer evidence packets.

Platform B does not replace human review. It makes the review context traceable, evidence-linked, and challenge-ready.

## Core doctrine

The future regulated site will not only be monitored. It will be assurance-sensed.

## Carry-forward doctrines

The device senses. Platform B assures.

A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.

The environment is part of the evidence.

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Review routing question

When the runtime cannot quietly trust the action, who must review it, what evidence must they see, and what decision must be recorded?

## Review route types

| Route type | Purpose |
|---|---|
| operator_confirmation | Operator confirms context, observation, or evidence linkage |
| reviewer_confirmation | Qualified reviewer confirms whether action may proceed under the demo rule set |
| quality_review | Quality-style review for missing, conflicting, expired, or blocking evidence |
| engineering_review | Engineering-style review for equipment, sensor, runtime, or context witness issues |
| system_owner_review | System owner review for system, access, data, or integration context |
| demo_owner_review | Demo owner review for controlled non-production scenario closure |
| escalation_review | Higher-level route when prior review cannot close the condition |

## Review trigger categories

| Trigger category | Review reason |
|---|---|
| yellow_exception | Evidence exists but reviewer confirmation is required |
| red_exception | Action is blocked and needs review or closure decision |
| expired_condition | Time, evidence, cleaning, calibration, review, shipment, dose, or action window expired |
| missing_evidence | Required evidence is missing |
| conflicting_evidence | Evidence sources disagree |
| source_unverifiable | Source cannot be traced under demo rules |
| passport_review_required | Operational Trust Passport requires confirmation |
| mesh_review_required | Ambient Evidence Mesh partially agrees or conflicts |
| admissibility_review_required | Action Admissibility Ledger records review_required or stop |
| site_readiness_review_required | Site Readiness Trust State is review_ready, not_ready, pending, or expired |
| exception_closure_required | Exception cannot close until reviewer confirms closure evidence |

## Required review route fields

| Field | Description |
|---|---|
| review_route_id | Unique human review route identifier |
| runtime_id | Assurance-Sensed Site Runtime linked to the route |
| route_type | Operator, reviewer, quality, engineering, system owner, demo owner, or escalation review |
| route_status | created, assigned, in_review, approved, rejected, escalated, closed, expired, or retired |
| trigger_category | Runtime condition that triggered review routing |
| trigger_event_refs | Runtime events that triggered the review route |
| runtime_exception_refs | Runtime Exception Escalation records linked to the route |
| evidence_mesh_refs | Ambient Evidence Mesh records linked to the route |
| mesh_update_refs | Evidence Mesh Runtime Update records linked to the route |
| passport_refs | Operational Trust Passports linked to the route |
| passport_refresh_refs | Passport Refresh and Expiry records linked to the route |
| ledger_refs | Action Admissibility Ledger records linked to the route |
| reviewer_packet_refs | Reviewer Evidence Packets linked to the route |
| alert_refs | Exception-Only Alerts linked to the route |
| site_state_refs | Site Readiness Trust State records linked to the route |
| assigned_reviewer_id | Reviewer, role, or demo reviewer assigned to review |
| assigned_reviewer_role | Reviewer function or role for the route |
| review_question | Question the reviewer must answer |
| required_evidence | Evidence required before decision or closure |
| reviewer_decision | approved_to_proceed, rejected, escalated, closed, pending, or not_required |
| reviewer_rationale | Human-readable reviewer rationale |
| action_admissibility_before | proceed, review_required, stop, expired, or not_applicable |
| action_admissibility_after | proceed, review_required, stop, expired, or not_applicable |
| created_at | Review route creation timestamp |
| assigned_at | Review assignment timestamp |
| reviewed_at | Review decision timestamp |
| closed_at | Review route closure timestamp |
| generated_by | System, user, or demo process that generated the route |
| guardrail_status | Demonstrator-only, non-production, no validated-use claim |

## Review route state rules

| Condition | Route status | Runtime impact |
|---|---|---|
| Review condition detected | created | review_required |
| Reviewer assigned | assigned | review_required |
| Reviewer opens packet | in_review | review_required |
| Reviewer approves continuation | approved | proceed |
| Reviewer rejects continuation | rejected | stop |
| Reviewer cannot close condition | escalated | review_required or stop |
| Closure evidence is accepted | closed | proceed or not_applicable |
| Review window expires | expired | expired |
| Route no longer applies | retired | not_applicable |

## Example review route object

```json
{
  "review_route_id": "HRR-DEMO-0001",
  "runtime_id": "ASR-DEMO-0001",
  "route_type": "reviewer_confirmation",
  "route_status": "assigned",
  "trigger_category": "yellow_exception",
  "trigger_event_refs": ["RTE-DEMO-0001"],
  "runtime_exception_refs": ["RTEG-DEMO-0001"],
  "evidence_mesh_refs": ["AEM-DEMO-0002"],
  "mesh_update_refs": ["EMRU-DEMO-0001"],
  "passport_refs": ["OTP-DEMO-ROOM-001"],
  "passport_refresh_refs": ["PRX-DEMO-0001"],
  "ledger_refs": ["AAL-DEMO-0002"],
  "reviewer_packet_refs": ["REP-DEMO-0001"],
  "alert_refs": ["EOA-DEMO-0001"],
  "site_state_refs": ["SRTS-DEMO-0001"],
  "assigned_reviewer_id": "Demo Reviewer 001",
  "assigned_reviewer_role": "qualified_demo_reviewer",
  "review_question": "Is the cleanroom readiness evidence sufficient for demo continuation?",
  "required_evidence": ["reviewer_confirmation", "environmental_review_confirmation"],
  "reviewer_decision": "pending",
  "reviewer_rationale": "",
  "action_admissibility_before": "review_required",
  "action_admissibility_after": "review_required",
  "created_at": "2026-07-05T12:05:00Z",
  "assigned_at": "2026-07-05T12:05:05Z",
  "reviewed_at": null,
  "closed_at": null,
  "generated_by": "Platform B v0.7 demo",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Relationship to v0.7 runtime

The Runtime Exception Escalation Rules decide when review is required.

The Human Review Routing Model assigns the review route, review question, reviewer packet, and required decision.

The Live Site Readiness Evaluation Loop uses the reviewer decision to update runtime state and action admissibility.

## Guardrails

This schema is for a controlled non-production demonstrator.

It does not support patient use, batch release, shipment release, clinical use, regulatory submission use, validated GMP use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
