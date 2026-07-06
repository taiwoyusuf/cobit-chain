# Passport Refresh and Expiry Model

## Platform

Platform B v0.7 - Assurance-Sensed Site Runtime

## Purpose

The Passport Refresh and Expiry Model defines how Platform B v0.7 refreshes Operational Trust Passports as runtime evidence changes.

The model also defines when a passport becomes stale, expired, blocked, review-required, or refreshed.

A passport is not a permanent approval. It is a runtime trust state that must remain current with the evidence mesh.

## Core doctrine

The future regulated site will not only be monitored. It will be assurance-sensed.

## Carry-forward doctrines

The device senses. Platform B assures.

A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.

The environment is part of the evidence.

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Runtime passport question

Is the passport still trustworthy now, after the latest witness event, evidence mesh update, time-window change, reviewer decision, or exception state?

## Passport refresh triggers

| Trigger | Refresh reason |
|---|---|
| new_runtime_event | A new witness event affects the passport context |
| evidence_mesh_update | Evidence relationship changed |
| evidence_gap_detected | Required evidence is missing or incomplete |
| evidence_conflict_detected | Evidence contradicts another signal or record |
| time_window_change | Time-sensitive context changed or moved closer to expiry |
| expiry_reached | Evidence, review, cleaning, calibration, dose, shipment, or action window expired |
| reviewer_decision | Reviewer approved, rejected, escalated, or closed a condition |
| exception_update | Yellow, red, expired, escalated, or closed alert changed |
| manual_refresh | User or reviewer requested refresh under demo rules |
| scenario_step | Demo scenario advanced to a new runtime state |

## Passport object classes

| Passport class | Runtime purpose |
|---|---|
| person_passport | Trust state for actor authorization, presence, role, and review context |
| room_passport | Trust state for room, hood, cleanroom, suite, or controlled area |
| equipment_passport | Trust state for equipment, instruments, workstations, black-box assets, or sensors |
| procedure_passport | Trust state for procedure, checklist, instruction, version, or step |
| environment_passport | Trust state for EMS, Lasair, particle, cleaning, temperature, humidity, pressure, or certification context |
| time_passport | Trust state for dose, cleaning, calibration, review, shipment, or action time window |
| evidence_passport | Trust state for evidence completeness, currency, coherence, and traceability |
| action_passport | Trust state for the specific action being evaluated |
| site_passport | Trust state for site, area, workflow, or operational readiness context |

## Passport lifecycle states

| Lifecycle state | Meaning |
|---|---|
| created | Passport has been created but not yet fully evaluated |
| refreshed | Passport has been updated using current runtime evidence |
| current | Passport is current and usable under the demo rule set |
| review_required | Passport requires reviewer confirmation before action proceeds |
| stale | Passport evidence is old or context may have changed |
| expired | Passport is outside its valid time or evidence window |
| blocked | Passport has a red, conflicting, missing, or blocking condition |
| retired | Passport is no longer active for the action context |

## Required passport refresh fields

| Field | Description |
|---|---|
| passport_refresh_id | Unique passport refresh record identifier |
| runtime_id | Assurance-Sensed Site Runtime linked to the refresh |
| passport_id | Operational Trust Passport being refreshed |
| passport_class | Person, room, equipment, procedure, environment, time, evidence, action, or site passport |
| refresh_trigger | Runtime event, evidence update, expiry, reviewer decision, exception update, or manual refresh |
| trigger_event_refs | Runtime events that caused the refresh |
| evidence_mesh_refs | Evidence mesh records used for refresh |
| mesh_update_refs | Evidence Mesh Runtime Update records used for refresh |
| prior_passport_state | Passport state before refresh |
| new_passport_state | Passport state after refresh |
| trust_state_before | assured, partially_assured, not_assured, pending, expired, or retired |
| trust_state_after | assured, partially_assured, not_assured, pending, expired, or retired |
| action_admissibility_before | proceed, review_required, stop, expired, or not_applicable |
| action_admissibility_after | proceed, review_required, stop, expired, or not_applicable |
| expiry_basis | Time, evidence, review, cleaning, calibration, dose, shipment, action, or scenario basis for expiry |
| valid_from | Timestamp when passport became valid for demo use |
| valid_until | Timestamp when passport expires, when applicable |
| refreshed_at | Timestamp when passport was refreshed |
| refresh_reason | Human-readable reason for the refresh |
| reviewer_required | True or false |
| reviewer_packet_refs | Reviewer Evidence Packets generated or updated by the refresh |
| alert_refs | Exception-Only Alert records generated or updated by the refresh |
| ledger_refs | Action Admissibility Ledger entries written or updated by the refresh |
| generated_by | System, user, or demo process that generated the refresh record |
| guardrail_status | Demonstrator-only, non-production, no validated-use claim |

## Expiry basis types

| Expiry basis | Meaning |
|---|---|
| time_window_expiry | Action, review, shipment, dose, cleaning, or calibration window expired |
| evidence_age_expiry | Evidence is older than the allowed demo rule set |
| context_change_expiry | Context changed enough that the prior passport cannot be reused |
| reviewer_expiry | Reviewer decision window expired |
| exception_expiry | Exception was not resolved within the expected demo window |
| scenario_expiry | Demo scenario moved to a new state and prior passport is no longer valid |

## Refresh rule table

| Condition | New passport state | Action admissibility impact |
|---|---|---|
| Evidence mesh agrees and no blocking condition exists | current | proceed |
| Evidence changed and remains coherent | refreshed | proceed or not_applicable |
| Evidence exists but reviewer confirmation is required | review_required | review_required |
| Required evidence is missing | blocked | stop |
| Evidence conflicts across sources | blocked | stop or review_required |
| Evidence or time window expired | expired | expired |
| Context changed and prior evidence may no longer apply | stale | review_required |
| Reviewer approves pending passport | current | proceed |
| Reviewer rejects pending passport | blocked | stop |
| Passport no longer applies to the action context | retired | not_applicable |

## Example passport refresh object

```json
{
  "passport_refresh_id": "PRX-DEMO-0001",
  "runtime_id": "ASR-DEMO-0001",
  "passport_id": "OTP-DEMO-ROOM-001",
  "passport_class": "room_passport",
  "refresh_trigger": "evidence_mesh_update",
  "trigger_event_refs": ["RTE-DEMO-0001"],
  "evidence_mesh_refs": ["AEM-DEMO-0002"],
  "mesh_update_refs": ["EMRU-DEMO-0001"],
  "prior_passport_state": "created",
  "new_passport_state": "review_required",
  "trust_state_before": "pending",
  "trust_state_after": "partially_assured",
  "action_admissibility_before": "not_applicable",
  "action_admissibility_after": "review_required",
  "expiry_basis": "context_change_expiry",
  "valid_from": "2026-07-05T12:03:00Z",
  "valid_until": "2026-07-05T12:33:00Z",
  "refreshed_at": "2026-07-05T12:03:10Z",
  "refresh_reason": "Room evidence is linked but reviewer confirmation is required before the action proceeds.",
  "reviewer_required": true,
  "reviewer_packet_refs": ["REP-DEMO-0001"],
  "alert_refs": ["EOA-DEMO-0001"],
  "ledger_refs": ["AAL-DEMO-0002"],
  "generated_by": "Platform B v0.7 demo",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Relationship to v0.7 runtime

The Device-Agnostic Witness Adapter normalizes source signals.

The Runtime Context Witness Event Bus routes normalized events.

The Evidence Mesh Runtime Update Rules decide how evidence relationships change.

The Passport Refresh and Expiry Model refreshes Operational Trust Passports as evidence and context change.

The Live Site Readiness Evaluation Loop uses refreshed passports to determine runtime readiness and action admissibility.

## Guardrails

This schema is for a controlled non-production demonstrator.

It does not support patient use, batch release, shipment release, clinical use, regulatory submission use, validated GMP use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
