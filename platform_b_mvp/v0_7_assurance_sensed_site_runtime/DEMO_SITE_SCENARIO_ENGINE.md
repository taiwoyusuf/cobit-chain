# Demo Site Scenario Engine

## Platform

Platform B v0.7 - Assurance-Sensed Site Runtime

## Purpose

The Demo Site Scenario Engine defines controlled non-production scenarios used to demonstrate how an assurance-sensed site runtime behaves as context changes.

The engine simulates runtime witness events, evidence mesh updates, passport refresh, exception escalation, human review routing, and live site readiness evaluation without using patient data, real GMP batch data, confidential company information, or regulated production data.

## Core doctrine

The future regulated site will not only be monitored. It will be assurance-sensed.

## Carry-forward doctrines

The device senses. Platform B assures.

A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.

The environment is part of the evidence.

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Scenario engine question

Can a controlled demo scenario show how site readiness changes when people, rooms, equipment, procedures, environmental signals, time windows, evidence, exceptions, and reviewer decisions change?

## Scenario engine stages

| Stage | Purpose |
|---|---|
| scenario_selected | User selects a controlled demo scenario |
| initial_context_loaded | Scenario loads starting person, room, equipment, procedure, environment, time, and evidence context |
| runtime_events_generated | Scenario generates QR, NFC, BLE, wearable, IoT, EMS, Lasair, upload, manual, or system events |
| witness_adapter_applied | Device-Agnostic Witness Adapter converts scenario events into runtime witness events |
| event_bus_published | Runtime Context Witness Event Bus receives normalized events |
| mesh_updated | Evidence Mesh Runtime Update Rules update evidence relationships |
| passport_refreshed | Passport Refresh and Expiry Model refreshes affected passports |
| readiness_evaluated | Live Site Readiness Evaluation Loop evaluates readiness |
| exception_processed | Runtime Exception Escalation Rules decide quiet, yellow, red, expired, escalated, or closed state |
| review_routed | Human Review Routing Model creates reviewer route and decision packet |
| scenario_result_recorded | Scenario records final runtime decision, evidence trace, and guardrail status |

## Scenario set

| Scenario | Runtime focus |
|---|---|
| cleanroom_entry_readiness | Person, room, environment, procedure, time, evidence, and reviewer state |
| black_box_equipment_evidence | Non-networked equipment witness, upload evidence, reviewer route, and admissibility |
| lasair_ems_runtime_check | Environmental signal, stale evidence, alert suppression, and yellow review |
| dose_time_assurance | Time-sensitive action window, evidence expiry, and reviewer escalation |
| endosafe_backup_guardian | Backup evidence, missing proof, runtime exception, and closure route |

## Scenario states

| Scenario state | Meaning |
|---|---|
| initialized | Scenario loaded but not started |
| running | Scenario is generating or evaluating runtime events |
| trusted | Scenario produced proceed or not_applicable decision under demo rules |
| review_required | Scenario produced a yellow or reviewer-required condition |
| stopped | Scenario produced a red or blocking condition |
| expired | Scenario produced an expired evidence or time-window condition |
| escalated | Scenario requires higher-level demo review |
| closed | Scenario reached a reviewed and closed state |
| retired | Scenario no longer applies |

## Required scenario fields

| Field | Description |
|---|---|
| scenario_id | Unique scenario identifier |
| scenario_name | Human-readable scenario name |
| scenario_type | Cleanroom, black-box equipment, environmental, dose-time, backup guardian, or custom demo scenario |
| scenario_state | initialized, running, trusted, review_required, stopped, expired, escalated, closed, or retired |
| runtime_id | Assurance-Sensed Site Runtime used by the scenario |
| site_context | Demo site, area, room, cleanroom, suite, workflow, or operational context |
| action_context | Action being evaluated by the scenario |
| actor_context | Demo operator, reviewer, system, or scenario actor |
| room_context | Demo room, hood, cleanroom, suite, or area context |
| equipment_context | Demo equipment, instrument, workstation, black-box asset, or sensor context |
| procedure_context | Demo procedure, checklist, instruction, version, or step context |
| environment_context | Demo EMS, Lasair, particle, cleaning, temperature, humidity, pressure, or certification context |
| time_context | Demo dose, cleaning, calibration, review, shipment, or action time-window context |
| seed_event_refs | Runtime events seeded by the scenario |
| generated_event_refs | Runtime events generated during scenario execution |
| adapter_refs | Device-Agnostic Witness Adapters used by the scenario |
| event_bus_refs | Runtime Context Witness Event Bus records used by the scenario |
| mesh_update_refs | Evidence Mesh Runtime Update records generated by the scenario |
| passport_refresh_refs | Passport Refresh and Expiry records generated by the scenario |
| exception_refs | Runtime Exception Escalation records generated by the scenario |
| review_route_refs | Human Review Routing records generated by the scenario |
| readiness_loop_refs | Live Site Readiness Evaluation Loop records generated by the scenario |
| final_runtime_state | trusted, review_required, stopped, expired, pending, or retired |
| final_runtime_decision | proceed, review_required, stop, expired, or not_applicable |
| final_decision_reason | Human-readable reason for final runtime decision |
| started_at | Scenario start timestamp |
| completed_at | Scenario completion timestamp |
| generated_by | System, user, or demo process that generated the scenario record |
| guardrail_status | Demonstrator-only, non-production, no validated-use claim |

## Scenario rule table

| Condition | Scenario state | Final runtime decision |
|---|---|---|
| Evidence mesh agrees and no exception exists | trusted | proceed |
| Evidence exists but reviewer confirmation is required | review_required | review_required |
| Required evidence is missing | stopped | stop |
| Evidence or time window expired | expired | expired |
| Evidence conflicts across sources | stopped | stop or review_required |
| Red condition cannot be closed | escalated | stop |
| Reviewer approves continuation | trusted | proceed |
| Reviewer rejects continuation | stopped | stop |
| Closure evidence is complete | closed | proceed or not_applicable |

## Example scenario object

```json
{
  "scenario_id": "DSE-DEMO-0001",
  "scenario_name": "Cleanroom Entry Readiness Runtime Demo",
  "scenario_type": "cleanroom_entry_readiness",
  "scenario_state": "review_required",
  "runtime_id": "ASR-DEMO-0001",
  "site_context": "Demo Cleanroom Area",
  "action_context": "pre_work_room_entry_review",
  "actor_context": "Demo Operator 001",
  "room_context": "ROOM-DEMO-CLEANROOM-001",
  "equipment_context": "EQP-DEMO-SPEEDYGLOVE-001",
  "procedure_context": "PROC-DEMO-CLEANROOM-ENTRY-001",
  "environment_context": "ENV-DEMO-CLEANROOM-001",
  "time_context": "TIME-DEMO-WINDOW-001",
  "seed_event_refs": ["RTE-DEMO-0001"],
  "generated_event_refs": ["RTE-DEMO-0001"],
  "adapter_refs": ["DWA-DEMO-QR-0001"],
  "event_bus_refs": ["RCWEB-DEMO-0001"],
  "mesh_update_refs": ["EMRU-DEMO-0001"],
  "passport_refresh_refs": ["PRX-DEMO-0001"],
  "exception_refs": ["RTEG-DEMO-0001"],
  "review_route_refs": ["HRR-DEMO-0001"],
  "readiness_loop_refs": ["LSREL-DEMO-0001"],
  "final_runtime_state": "review_required",
  "final_runtime_decision": "review_required",
  "final_decision_reason": "Cleanroom readiness evidence is linked but reviewer confirmation is required before action proceeds.",
  "started_at": "2026-07-05T12:00:00Z",
  "completed_at": "2026-07-05T12:06:00Z",
  "generated_by": "Platform B v0.7 demo",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Relationship to v0.7 runtime

The Demo Site Scenario Engine creates controlled demo situations.

The Device-Agnostic Witness Adapter normalizes source signals.

The Runtime Context Witness Event Bus routes normalized events.

The Evidence Mesh Runtime Update Rules update evidence relationships.

The Passport Refresh and Expiry Model refreshes trust passports.

The Runtime Exception Escalation Rules decide quiet, yellow, red, expired, escalated, or closed states.

The Human Review Routing Model routes reviewer action.

The Live Site Readiness Evaluation Loop produces the final readiness and admissibility state.

## Guardrails

This schema is for a controlled non-production demonstrator.

It does not support patient use, batch release, shipment release, clinical use, regulatory submission use, validated GMP use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
