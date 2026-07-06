# Runtime Exception Escalation Rules

## Platform

Platform B v0.7 - Assurance-Sensed Site Runtime

## Purpose

The Runtime Exception Escalation Rules define when Platform B v0.7 should stay quiet, raise a yellow review condition, raise a red stop condition, escalate to human review, or close an exception.

The rules protect the v0.5 and v0.6 operating principle: quiet when trusted, alert when operational trust is at risk, and preserve evidence when action is challenged.

## Core doctrine

The future regulated site will not only be monitored. It will be assurance-sensed.

## Carry-forward doctrines

The device senses. Platform B assures.

A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.

The environment is part of the evidence.

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Runtime exception question

When the runtime detects a trust risk, should Platform B stay quiet, request review, stop action, escalate, or close the condition?

## Runtime exception states

| Exception state | Meaning |
|---|---|
| none | No runtime exception exists |
| informational | Runtime condition is recorded but does not require action |
| yellow | Review is required before action proceeds |
| red | Action is not admissible under the demo rule set |
| expired | Time, evidence, review, cleaning, calibration, dose, shipment, or action window expired |
| escalated | Exception requires higher-level or designated reviewer decision |
| closed | Exception has been reviewed and closed under the demo rule set |
| retired | Exception no longer applies to the runtime context |

## Escalation trigger categories

| Trigger category | Runtime meaning |
|---|---|
| missing_evidence | Required evidence is missing |
| stale_evidence | Evidence is too old for the action context |
| expired_window | Required time window expired |
| conflicting_evidence | Evidence sources disagree |
| unverified_source | Runtime witness source cannot be traced or verified under demo rules |
| reviewer_pending | Human review is required but not complete |
| reviewer_rejected | Reviewer rejected continuation |
| passport_blocked | Operational Trust Passport is blocked or expired |
| mesh_conflict | Ambient Evidence Mesh has contradiction or unresolved conflict |
| admissibility_stop | Action Admissibility Ledger records a stop or expired decision |
| site_not_ready | Site Readiness Trust State is not ready |
| runtime_rule_violation | Runtime rule set detects a blocking condition |

## Required exception fields

| Field | Description |
|---|---|
| runtime_exception_id | Unique runtime exception identifier |
| runtime_id | Assurance-Sensed Site Runtime linked to the exception |
| exception_state | none, informational, yellow, red, expired, escalated, closed, or retired |
| trigger_category | Missing evidence, stale evidence, expired window, conflict, source issue, review issue, passport issue, mesh issue, admissibility issue, site readiness issue, or rule violation |
| trigger_event_refs | Runtime events that triggered the exception |
| affected_context_refs | Person, room, equipment, procedure, environment, time, evidence, action, review, exception, or site objects affected |
| evidence_mesh_refs | Ambient Evidence Mesh records linked to the exception |
| mesh_update_refs | Evidence Mesh Runtime Update records linked to the exception |
| passport_refs | Operational Trust Passports linked to the exception |
| passport_refresh_refs | Passport Refresh and Expiry records linked to the exception |
| ledger_refs | Action Admissibility Ledger records linked to the exception |
| reviewer_packet_refs | Reviewer Evidence Packets generated or updated by the exception |
| alert_refs | Exception-Only Alert records linked to the exception |
| site_state_refs | Site Readiness Trust State records linked to the exception |
| runtime_state_before | Runtime state before the exception |
| runtime_state_after | Runtime state after the exception |
| action_admissibility_before | proceed, review_required, stop, expired, or not_applicable |
| action_admissibility_after | proceed, review_required, stop, expired, or not_applicable |
| escalation_required | True or false |
| escalation_route | none, reviewer, supervisor, quality_review, engineering_review, system_owner_review, or demo_owner_review |
| required_action | none, monitor, review, stop, escalate, close, or collect_evidence |
| exception_reason | Human-readable explanation of the exception |
| closure_required_evidence | Evidence required before exception closure |
| reviewer_decision | approved_to_proceed, rejected, escalated, closed, pending, or not_required |
| opened_at | Exception open timestamp |
| escalated_at | Exception escalation timestamp, when applicable |
| closed_at | Exception closure timestamp, when applicable |
| generated_by | System, user, or demo process that generated the exception |
| guardrail_status | Demonstrator-only, non-production, no validated-use claim |

## Escalation rule table

| Condition | Exception state | Runtime decision | Required action |
|---|---|---|---|
| Evidence complete, current, coherent, and no review condition exists | none | proceed | none |
| Runtime condition is useful but not blocking | informational | not_applicable | monitor |
| Evidence exists but reviewer confirmation is needed | yellow | review_required | review |
| Required evidence is missing | red | stop | collect_evidence |
| Evidence or action window expired | expired | expired | stop |
| Evidence conflicts across sources | red | stop or review_required | escalate |
| Source cannot be verified under demo rules | yellow | review_required | review |
| Reviewer decision is pending | yellow | review_required | review |
| Reviewer rejects continuation | red | stop | stop |
| Red condition remains unresolved | escalated | stop | escalate |
| Closure evidence is complete and reviewer closes condition | closed | proceed or not_applicable | close |

## Example runtime exception object

```json
{
  "runtime_exception_id": "RTEG-DEMO-0001",
  "runtime_id": "ASR-DEMO-0001",
  "exception_state": "yellow",
  "trigger_category": "reviewer_pending",
  "trigger_event_refs": ["RTE-DEMO-0001"],
  "affected_context_refs": ["ROOM-DEMO-CLEANROOM-001", "ENV-DEMO-CLEANROOM-001"],
  "evidence_mesh_refs": ["AEM-DEMO-0002"],
  "mesh_update_refs": ["EMRU-DEMO-0001"],
  "passport_refs": ["OTP-DEMO-ROOM-001"],
  "passport_refresh_refs": ["PRX-DEMO-0001"],
  "ledger_refs": ["AAL-DEMO-0002"],
  "reviewer_packet_refs": ["REP-DEMO-0001"],
  "alert_refs": ["EOA-DEMO-0001"],
  "site_state_refs": ["SRTS-DEMO-0001"],
  "runtime_state_before": "pending",
  "runtime_state_after": "review_required",
  "action_admissibility_before": "not_applicable",
  "action_admissibility_after": "review_required",
  "escalation_required": false,
  "escalation_route": "reviewer",
  "required_action": "review",
  "exception_reason": "Room and environmental evidence are linked but reviewer confirmation is required before action proceeds.",
  "closure_required_evidence": ["reviewer_confirmation", "environmental_review_confirmation"],
  "reviewer_decision": "pending",
  "opened_at": "2026-07-05T12:04:00Z",
  "escalated_at": null,
  "closed_at": null,
  "generated_by": "Platform B v0.7 demo",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Relationship to v0.7 runtime

The Device-Agnostic Witness Adapter normalizes source signals.

The Runtime Context Witness Event Bus routes normalized events.

The Evidence Mesh Runtime Update Rules decide how evidence relationships change.

The Passport Refresh and Expiry Model refreshes trust passports as evidence changes.

The Runtime Exception Escalation Rules decide whether the runtime stays quiet, routes review, stops action, escalates, or closes the condition.

## Guardrails

This schema is for a controlled non-production demonstrator.

It does not support patient use, batch release, shipment release, clinical use, regulatory submission use, validated GMP use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
