# Runtime Context Witness Event Bus Schema

## Platform

Platform B v0.7 - Assurance-Sensed Site Runtime

## Purpose

The Runtime Context Witness Event Bus defines how Platform B v0.7 receives, normalizes, routes, and evaluates live context witness events from device-agnostic sources.

The event bus is the runtime pathway between sensed context and assurance decisioning.

It does not approve action by itself. It feeds the assurance-sensed runtime so evidence mesh updates, passport refresh, admissibility decisions, exception-only alerts, and reviewer routing can occur.

## Core doctrine

The future regulated site will not only be monitored. It will be assurance-sensed.

## Carry-forward doctrines

The device senses. Platform B assures.

A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.

The environment is part of the evidence.

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Event bus stages

| Stage | Purpose |
|---|---|
| event_received | Runtime receives a raw witness event |
| event_normalized | Event is converted into common Platform B event shape |
| context_bound | Event is bound to person, room, equipment, procedure, environment, time, action, or site context |
| evidence_linked | Event is linked to supporting evidence or evidence packet |
| mesh_routed | Event is routed to Ambient Evidence Mesh update logic |
| passport_routed | Event is routed to Operational Trust Passport refresh logic |
| admissibility_routed | Event is routed to Action Admissibility evaluation logic |
| exception_routed | Event is routed to Exception-Only Alert logic |
| reviewer_routed | Event triggers reviewer routing when human review is required |
| trace_recorded | Runtime trace is recorded for challenge review |

## Runtime witness source types

| Source type | Example |
|---|---|
| qr | Room, equipment, procedure, evidence packet, or station QR scan |
| nfc | NFC tap on controlled object or location point |
| ble | BLE beacon proximity, location, or asset presence signal |
| wearable | Glasses, badge, watch, phone, or body-worn context capture |
| iot | M5Stack, ESP32, Raspberry Pi, environmental node, or sensor gateway |
| ems | Environmental monitoring signal or exported EMS status |
| lasair | Particle counter export, observation, or demo reference |
| upload | CSV, PDF, image, screenshot, export, or USB evidence upload |
| manual | Operator or reviewer observation, attestation, or note |
| system | Platform B demo system event or simulated runtime event |

## Event categories

| Event category | Meaning |
|---|---|
| presence_event | Person, device, equipment, or object presence is observed |
| identity_event | Actor, object, room, equipment, or procedure identity is confirmed |
| environment_event | Environmental signal or status is received |
| evidence_event | Evidence file, record, export, screenshot, or packet is captured |
| procedure_event | Procedure version, step, checklist, or instruction context is observed |
| time_event | Time-window, expiry, sequence, or schedule condition is evaluated |
| exception_event | Yellow, red, expired, escalated, or closed condition is created or updated |
| review_event | Reviewer route, reviewer decision, or reviewer packet event is recorded |
| admissibility_event | Action admissibility is evaluated or updated |
| trace_event | Runtime trace, audit trail, or challenge record is written |

## Required event fields

| Field | Description |
|---|---|
| runtime_event_id | Unique runtime witness event identifier |
| runtime_id | Assurance-Sensed Site Runtime receiving the event |
| event_bus_id | Event bus identifier |
| source_type | QR, NFC, BLE, wearable, IoT, EMS, Lasair, upload, manual, or system |
| source_label | Human-readable event source label |
| raw_event_ref | Reference to original event payload, file, export, or demo signal |
| normalized_event_type | Common Platform B event type after normalization |
| event_category | Presence, identity, environment, evidence, procedure, time, exception, review, admissibility, or trace |
| event_status | received, normalized, bound, linked, routed, evaluated, rejected, expired, or archived |
| actor_context | Operator, reviewer, system, or demo actor linked to the event |
| room_context | Room, hood, cleanroom, suite, controlled area, or demo area context |
| equipment_context | Equipment, instrument, workstation, sensor, or black-box equipment context |
| procedure_context | Procedure, checklist, instruction, or step context |
| environment_context | EMS, Lasair, particle, temperature, humidity, pressure, cleaning, or certification context |
| time_context | Dose, cleaning, calibration, review, shipment, or action time-window context |
| action_context | Action being evaluated by the runtime |
| evidence_refs | Evidence records, exports, files, screenshots, logs, or packets linked to the event |
| mesh_refs | Ambient Evidence Mesh records updated or evaluated by the event |
| passport_refs | Operational Trust Passports refreshed or evaluated by the event |
| ledger_refs | Action Admissibility Ledger entries created or updated by the event |
| alert_refs | Exception-Only Alert records created or updated by the event |
| reviewer_packet_refs | Reviewer Evidence Packets created or updated by the event |
| routing_topic | Runtime topic used to route the event |
| routing_decision | accept, route, review, reject, expire, stop, or archive |
| runtime_decision_impact | none, proceed, review_required, stop, expired, or not_applicable |
| event_timestamp | Timestamp when the event occurred or was captured |
| received_at | Timestamp when Platform B received the event |
| normalized_at | Timestamp when the event was normalized |
| evaluated_at | Timestamp when the event was evaluated |
| generated_by | Source, user, or demo process that generated the event |
| guardrail_status | Demonstrator-only, non-production, no validated-use claim |

## Runtime routing topics

| Routing topic | Routed to |
|---|---|
| runtime.context.presence | Presence and identity checks |
| runtime.context.environment | Environmental readiness checks |
| runtime.context.evidence | Evidence binding and evidence packet logic |
| runtime.context.procedure | Procedure and step readiness logic |
| runtime.context.time | Time-window and expiry logic |
| runtime.context.mesh_update | Ambient Evidence Mesh runtime update logic |
| runtime.context.passport_refresh | Operational Trust Passport refresh logic |
| runtime.context.admissibility | Action Admissibility Ledger logic |
| runtime.context.exception | Exception-Only Alert logic |
| runtime.context.review | Reviewer routing and reviewer evidence packet logic |
| runtime.context.trace | Runtime trace and challenge record logic |

## Event status rules

| Condition | Event status | Routing decision |
|---|---|---|
| Event received and source can be interpreted | received | route |
| Event converted into common event shape | normalized | route |
| Event linked to site, object, action, and time context | bound | route |
| Evidence record is linked | linked | route |
| Event updates evidence mesh | routed | accept |
| Event produces admissibility impact | evaluated | accept |
| Event is outside valid time window | expired | expire |
| Event cannot be traced to source | rejected | reject |
| Event is informational only | archived | archive |

## Example runtime event

```json
{
  "runtime_event_id": "RTE-DEMO-0001",
  "runtime_id": "ASR-DEMO-0001",
  "event_bus_id": "RCWEB-DEMO-0001",
  "source_type": "qr",
  "source_label": "Demo cleanroom QR scan",
  "raw_event_ref": "RAW-DEMO-QR-0001",
  "normalized_event_type": "room_identity_observed",
  "event_category": "identity_event",
  "event_status": "evaluated",
  "actor_context": "Demo Operator 001",
  "room_context": "ROOM-DEMO-CLEANROOM-001",
  "equipment_context": "EQP-DEMO-SPEEDYGLOVE-001",
  "procedure_context": "PROC-DEMO-CLEANROOM-ENTRY-001",
  "environment_context": "ENV-DEMO-CLEANROOM-001",
  "time_context": "TIME-DEMO-WINDOW-001",
  "action_context": "pre_work_room_entry_review",
  "evidence_refs": ["EV-DEMO-ROOM-001"],
  "mesh_refs": ["AEM-DEMO-0002"],
  "passport_refs": ["OTP-DEMO-ROOM-001"],
  "ledger_refs": ["AAL-DEMO-0002"],
  "alert_refs": ["EOA-DEMO-0001"],
  "reviewer_packet_refs": ["REP-DEMO-0001"],
  "routing_topic": "runtime.context.mesh_update",
  "routing_decision": "accept",
  "runtime_decision_impact": "review_required",
  "event_timestamp": "2026-07-05T12:00:00Z",
  "received_at": "2026-07-05T12:00:02Z",
  "normalized_at": "2026-07-05T12:00:03Z",
  "evaluated_at": "2026-07-05T12:00:04Z",
  "generated_by": "Platform B v0.7 demo",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Relationship to v0.7 runtime

The Runtime Context Witness Event Bus feeds the Assurance-Sensed Site Runtime.

The runtime uses the event bus to update evidence mesh relationships, refresh operational trust passports, evaluate action admissibility, raise exception-only alerts, route reviewer packets, and record traceable runtime decisions.

## Guardrails

This schema is for a controlled non-production demonstrator.

It does not support patient use, batch release, shipment release, clinical use, regulatory submission use, validated GMP use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
