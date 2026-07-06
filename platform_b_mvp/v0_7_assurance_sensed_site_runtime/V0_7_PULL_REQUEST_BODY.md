# Platform B v0.7 - Pull Request Body

## Title

Platform B v0.7 - Assurance-Sensed Site Runtime

## Summary

This pull request adds Platform B v0.7, titled Assurance-Sensed Site Runtime.

v0.7 extends Platform B from static operational trust artifacts into a live runtime model that receives device-agnostic witness events, updates evidence relationships, refreshes passports, evaluates readiness, raises exception-only alerts, routes human review, and records challenge-ready runtime decisions.

## Core doctrine

The future regulated site will not only be monitored. It will be assurance-sensed.

## Carry-forward doctrines

- The device senses. Platform B assures.
- A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.
- The environment is part of the evidence.
- Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Added v0.7 files

- PLATFORM_B_V0_7_PLANNING_LOCK.md
- ASSURANCE_SENSED_SITE_RUNTIME_SCHEMA.md
- RUNTIME_CONTEXT_WITNESS_EVENT_BUS_SCHEMA.md
- DEVICE_AGNOSTIC_WITNESS_ADAPTER_SCHEMA.md
- LIVE_SITE_READINESS_EVALUATION_LOOP.md
- EVIDENCE_MESH_RUNTIME_UPDATE_RULES.md
- PASSPORT_REFRESH_AND_EXPIRY_MODEL.md
- RUNTIME_EXCEPTION_ESCALATION_RULES.md
- HUMAN_REVIEW_ROUTING_MODEL.md
- DEMO_SITE_SCENARIO_ENGINE.md
- demo_console/index.html
- demo_console/assurance_sensed_site_runtime.html
- demo_console/runtime_context_witness_event_bus.html
- demo_console/device_agnostic_witness_adapter.html
- demo_console/live_site_readiness_loop.html
- demo_console/evidence_mesh_runtime_updates.html
- demo_console/passport_refresh_and_expiry.html
- demo_console/runtime_exception_escalation.html
- demo_console/human_review_routing.html
- demo_console/demo_site_scenario_engine.html
- demo_console/demo_seed_v07.json
- demo_console/V0_7_DEMO_CONSOLE_MANIFEST.md
- V0_7_PULL_REQUEST_BODY.md

## What v0.7 adds

v0.7 adds a runtime layer for Assurance-Sensed Regulated Operations.

It demonstrates how Platform B can evaluate whether an action may proceed now based on the current evidence state of:

- Person
- Room
- Equipment
- Procedure
- Environment
- Time
- Evidence
- Reviewer state
- Exception state
- Site readiness

## Runtime capabilities introduced

- Assurance-Sensed Site Runtime
- Runtime Context Witness Event Bus
- Device-Agnostic Witness Adapter
- Live Site Readiness Evaluation Loop
- Evidence Mesh Runtime Update Rules
- Passport Refresh and Expiry Model
- Runtime Exception Escalation Rules
- Human Review Routing Model
- Demo Site Scenario Engine
- v0.7 demo console scaffold

## Demo scenarios

- cleanroom_entry_readiness
- black_box_equipment_evidence
- lasair_ems_runtime_check
- dose_time_assurance
- endosafe_backup_guardian

## Relationship to v0.6

v0.6 defined the operational trust artifacts, including passports, evidence mesh, admissibility ledger, witness chain, reviewer packet, alert model, and site readiness trust state.

v0.7 defines the runtime that updates, refreshes, evaluates, routes, and records those artifacts as site context changes.

## Guardrails

This is a controlled non-production demonstrator.

This pull request does not claim:

- Validated GMP use
- Clinical use
- Patient use
- Batch release support
- Shipment release support
- Regulatory submission use
- Autonomous execution
- Production compliance
- Replacement of QMS, MES, LIMS, EMS, Lasair, validated systems, or human review

## Verification

The v0.7 file set and demo console scaffold were verified before creating the v0.7 release tag.

Release tag:

platform-b-v0.7-assurance-sensed-site-runtime
