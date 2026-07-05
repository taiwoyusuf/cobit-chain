# Site Readiness Trust State Schema

## Platform

Platform B v0.6 - Operational Trust Passport and Ambient Evidence Mesh

## Purpose

The Site Readiness Trust State summarizes whether a regulated site, area, room, workflow, equipment group, or operational context is ready for action based on agreement across people, rooms, equipment, procedures, environmental signals, time windows, evidence, review status, and exceptions.

The Site Readiness Trust State does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.

It gives a visible trust state before action proceeds.

## Core doctrine

A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.

## Continuity from v0.5

The device senses. Platform B assures.

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Site readiness dimensions

| Dimension | Meaning |
|---|---|
| people_readiness | Operators, reviewers, approvers, and accountable actors are trained, authorized, present, and linked |
| room_readiness | Room, hood, cleanroom, suite, or controlled area is ready for the action context |
| equipment_readiness | Equipment, instruments, workstations, and black-box assets are identified, status-known, and evidence-linked |
| procedure_readiness | Procedure version, step, checklist, instruction, and decision context are in scope |
| environment_readiness | EMS, Lasair, particle, temperature, humidity, pressure, cleaning, and certification evidence are current and admissible |
| time_readiness | Dose, cleaning, calibration, review, shipment, or action windows are valid |
| evidence_readiness | Required evidence is present, current, coherent, and linked |
| review_readiness | Reviewer status is not required, complete, pending, rejected, or escalated |
| exception_readiness | No unresolved red, escalated, expired, or blocking exception exists |

## Site readiness states

| Readiness state | Meaning |
|---|---|
| trusted_ready | Evidence mesh agrees and action may proceed under the demo rule set |
| review_ready | Evidence exists but reviewer confirmation is required |
| not_ready | Required evidence is missing, failed, conflicting, or action is not admissible |
| expired | One or more required time windows or evidence windows have expired |
| pending | Evidence collection or reviewer decision is not complete |
| retired | Site, area, workflow, or object is no longer active for the action context |

## Required site state fields

| Field | Description |
|---|---|
| site_state_id | Unique Site Readiness Trust State identifier |
| site_context | Site, area, room, workflow, or operational context being assessed |
| action_context | Specific action or action family being evaluated |
| readiness_state | trusted_ready, review_ready, not_ready, expired, pending, or retired |
| trust_state | assured, partially_assured, not_assured, pending, expired, or retired |
| action_admissibility | proceed, review_required, stop, expired, or not_applicable |
| people_readiness | State of people-related evidence |
| room_readiness | State of room-related evidence |
| equipment_readiness | State of equipment-related evidence |
| procedure_readiness | State of procedure-related evidence |
| environment_readiness | State of environmental evidence |
| time_readiness | State of time-window evidence |
| evidence_readiness | State of required evidence completeness and coherence |
| review_readiness | State of reviewer requirement or reviewer decision |
| exception_readiness | State of unresolved exceptions |
| evidence_mesh_refs | Ambient Evidence Mesh records supporting the state |
| passport_refs | Operational Trust Passports supporting the state |
| witness_chain_refs | Context Witness Chains supporting the state |
| ledger_refs | Action Admissibility Ledger entries supporting the state |
| reviewer_packet_refs | Reviewer Evidence Packets supporting the state |
| alert_refs | Exception-Only Alert records supporting the state |
| top_evidence_gaps | Missing, stale, conflicting, or unverifiable evidence items |
| recommended_action | none, proceed, review, stop, escalate, close, or collect_evidence |
| generated_at | Site state generation timestamp |
| generated_by | System, user, or demo process that generated the site state |
| guardrail_status | Demonstrator-only, non-production, no validated-use claim |

## Readiness scoring model

| Score band | State | Meaning |
|---|---|---|
| 90-100 | trusted_ready | Required evidence is complete, current, coherent, and no blocking condition exists |
| 70-89 | review_ready | Evidence is mostly present but review, confirmation, or closure is needed |
| 40-69 | pending | Evidence is incomplete or still being gathered |
| 1-39 | not_ready | Required evidence is missing, conflicting, failed, or not admissible |
| 0 | expired | Critical evidence or action window expired |

## Site state rule table

| Condition | Site readiness state | Action admissibility |
|---|---|---|
| All readiness dimensions are assured | trusted_ready | proceed |
| Evidence is present but reviewer confirmation is required | review_ready | review_required |
| One or more required evidence items are missing | not_ready | stop |
| One or more required evidence items are stale or expired | expired | expired |
| Environmental or equipment signals conflict | not_ready | stop or review_required |
| Red exception exists | not_ready | stop |
| Yellow exception exists | review_ready | review_required |
| Reviewer decision is pending | pending | review_required |
| Reviewer rejects action | not_ready | stop |
| Exception is closed and evidence is coherent | trusted_ready | proceed |

## Example site readiness trust state

```json
{
  "site_state_id": "SRTS-DEMO-0001",
  "site_context": "Demo Cleanroom Area",
  "action_context": "pre_work_room_entry_review",
  "readiness_state": "review_ready",
  "trust_state": "partially_assured",
  "action_admissibility": "review_required",
  "people_readiness": "assured",
  "room_readiness": "partially_assured",
  "equipment_readiness": "assured",
  "procedure_readiness": "assured",
  "environment_readiness": "partially_assured",
  "time_readiness": "assured",
  "evidence_readiness": "incomplete",
  "review_readiness": "pending",
  "exception_readiness": "yellow",
  "evidence_mesh_refs": ["AEM-DEMO-0002"],
  "passport_refs": ["OTP-DEMO-ROOM-001"],
  "witness_chain_refs": ["CWC-DEMO-0001"],
  "ledger_refs": ["AAL-DEMO-0002"],
  "reviewer_packet_refs": ["REP-DEMO-0001"],
  "alert_refs": ["EOA-DEMO-0001"],
  "top_evidence_gaps": ["cleaning_confirmation", "environmental_review_confirmation"],
  "recommended_action": "review",
  "generated_at": "2026-07-04T12:15:00Z",
  "generated_by": "Platform B v0.6 demo",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Relationship to v0.6 objects

The Context Witness Chain records the event sequence.

The Ambient Evidence Mesh connects the evidence relationships.

The Operational Trust Passport summarizes trust for people, rooms, equipment, procedures, environment, time, action, and site readiness.

The Action Admissibility Ledger records why action was allowed, blocked, expired, or routed for review.

The Reviewer Evidence Packet gives the reviewer a structured evidence bundle.

The Exception-Only Alert Model decides whether Platform B stays quiet, routes review, stops action, escalates, or closes the condition.

The Site Readiness Trust State summarizes the overall readiness state across the operational context.

## Guardrails

This schema is for a controlled non-production demonstrator.

It does not support patient use, batch release, shipment release, clinical use, regulatory submission use, validated GMP use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
