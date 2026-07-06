# Platform B v0.7 Planning Lock

## Working title

Platform B v0.7 - Assurance-Sensed Site Runtime

## Purpose

Platform B v0.7 extends v0.6 from structured operational trust evidence into an assurance-sensed site runtime.

v0.7 focuses on how QR, NFC, BLE, wearable, IoT, EMS, Lasair, manual, upload, and system context witnesses can feed a runtime that continuously evaluates site readiness before action proceeds.

## Core doctrine

The future regulated site will not only be monitored. It will be assurance-sensed.

## Carry-forward doctrines

The device senses. Platform B assures.

A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.

The environment is part of the evidence.

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## v0.7 research positioning

v0.7 strengthens Platform B as a controlled demonstrator for Assurance Engineering and Controlled Environment Assurance Engineering.

It moves the project from static evidence artifacts toward an assurance-sensed regulated operations runtime.

## v0.7 planning scope

- Assurance-Sensed Site Runtime
- Runtime Context Witness Event Bus
- Device-Agnostic Witness Adapter Model
- Live Site Readiness Evaluation Loop
- Evidence Mesh Runtime Update Rules
- Passport Refresh and Expiry Model
- Runtime Exception Escalation Rules
- Human Review Routing Model
- Demo Site Scenario Engine
- v0.7 demo console runtime expansion

## v0.7 object model

| Object | Purpose |
|---|---|
| runtime_event | Captures a site signal or witness event at runtime |
| witness_adapter | Converts QR, NFC, BLE, wearable, IoT, EMS, Lasair, manual, upload, or system input into a common event shape |
| readiness_loop | Evaluates site readiness repeatedly as context changes |
| mesh_update | Updates evidence relationships as new signals arrive |
| passport_refresh | Refreshes operational trust passports when evidence changes |
| runtime_exception | Captures yellow, red, expired, or escalated runtime conditions |
| review_route | Routes reviewer action when runtime trust is at risk |
| scenario_engine | Runs controlled demo scenarios without patient data, GMP batch data, or confidential information |

## v0.7 expected deliverables

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
- v0.7 demo console scaffold or expansion

## v0.7 demo scenario candidates

| Scenario | Runtime focus |
|---|---|
| Cleanroom entry readiness | Room, person, environment, procedure, evidence, time, and review state |
| Black-box equipment evidence | Non-networked equipment witness, upload evidence, reviewer route, admissibility |
| Lasair / EMS runtime check | Environmental signals, stale evidence, alert suppression, yellow review |
| Dose-time assurance | Time-sensitive action window, evidence expiry, reviewer escalation |
| Endosafe backup guardian | Backup evidence, missing proof, runtime exception, closure route |

## Non-production boundary

v0.7 remains a controlled non-production demonstrator.

No patient data.

No real GMP batch data.

No confidential company information.

No validated GMP, clinical, batch release, shipment release, regulatory submission, autonomous execution, or production compliance claim.

v0.7 does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.

## Planning lock decision

Platform B v0.7 is locked as Assurance-Sensed Site Runtime.

The release should demonstrate how a regulated site can become assurance-sensed through device-agnostic witness events, runtime evidence mesh updates, passport refresh, exception-only alerting, and reviewer routing.
