# Device-Agnostic Witness Adapter Schema

## Platform

Platform B v0.7 - Assurance-Sensed Site Runtime

## Purpose

The Device-Agnostic Witness Adapter defines how QR, NFC, BLE, wearable, phone, IoT, EMS, Lasair, upload, manual, and system inputs are converted into a common runtime witness event shape.

The adapter prevents Platform B from being locked to one device, vendor, sensor, or capture method.

The device senses. Platform B assures.

## Core doctrine

The future regulated site will not only be monitored. It will be assurance-sensed.

## Carry-forward doctrines

A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.

The environment is part of the evidence.

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Adapter objective

The adapter should answer one technical question:

How can different devices and evidence sources become comparable runtime witness events without claiming that any one device approves regulated work?

## Adapter source classes

| Source class | Example | Runtime meaning |
|---|---|---|
| qr_adapter | QR scan on room, equipment, procedure, evidence packet, or station | Identity and context witness |
| nfc_adapter | NFC tap on controlled object or location point | Identity, proximity, or context witness |
| ble_adapter | BLE beacon, iBeacon, asset tag, or proximity signal | Presence or proximity witness |
| wearable_adapter | Smart glasses, badge, watch, phone, or body-worn capture | Human-context witness |
| phone_adapter | Phone scan, photo, video, note, or upload | Mobile capture witness |
| iot_adapter | M5Stack, ESP32, Raspberry Pi, sensor node, or gateway | Runtime sensor witness |
| ems_adapter | Environmental monitoring system status or export | Environmental evidence witness |
| lasair_adapter | Particle counter status, export, or observation reference | Particle evidence witness |
| upload_adapter | CSV, PDF, image, screenshot, USB export, or evidence file | File evidence witness |
| manual_adapter | Operator or reviewer attestation, observation, or note | Human declaration witness |
| system_adapter | Simulated event, demo engine event, or internal runtime event | System witness |

## Adapter stages

| Stage | Purpose |
|---|---|
| source_detected | Adapter detects an incoming source event |
| source_classified | Adapter classifies the source type and trust boundary |
| payload_parsed | Adapter parses the source payload or reference |
| context_extracted | Adapter extracts actor, room, equipment, procedure, environment, time, and action context |
| evidence_mapped | Adapter maps source data to evidence references |
| witness_event_created | Adapter creates a normalized runtime witness event |
| event_bus_published | Adapter publishes the event to the Runtime Context Witness Event Bus |
| trace_recorded | Adapter records source, transformation, and routing trace |

## Required adapter fields

| Field | Description |
|---|---|
| adapter_id | Unique adapter identifier |
| adapter_name | Human-readable adapter name |
| adapter_class | QR, NFC, BLE, wearable, phone, IoT, EMS, Lasair, upload, manual, or system adapter |
| adapter_mode | demo, simulation, offline, review, or retired |
| source_type | Source event type handled by the adapter |
| source_label | Human-readable source label |
| source_trust_boundary | demo, external, manual, uploaded, simulated, device, system, or unknown |
| accepted_payload_types | JSON, CSV, PDF, image, screenshot, QR value, NFC value, BLE signal, sensor reading, text note, or system event |
| required_context_fields | Context fields required before publishing a witness event |
| optional_context_fields | Context fields that enrich the witness event but do not block publication |
| normalization_rule | Rule used to convert source input into common runtime event shape |
| evidence_mapping_rule | Rule used to bind input to evidence references |
| routing_topic | Runtime Context Witness Event Bus topic used after normalization |
| output_event_type | Normalized runtime witness event type created by the adapter |
| output_event_category | Presence, identity, environment, evidence, procedure, time, exception, review, admissibility, or trace |
| validation_state | accepted, accepted_with_warning, rejected, expired, unverifiable, or retired |
| rejection_reason | Human-readable reason for adapter rejection, when applicable |
| trace_required | True or false |
| generated_by | System, user, or demo process that owns the adapter record |
| guardrail_status | Demonstrator-only, non-production, no validated-use claim |

## Adapter validation states

| Validation state | Meaning |
|---|---|
| accepted | Source event is usable for demo runtime evaluation |
| accepted_with_warning | Source event is usable but needs review, confirmation, or context enrichment |
| rejected | Source event cannot be used by the demo runtime |
| expired | Source event is outside a valid time window |
| unverifiable | Source event cannot be traced to an acceptable demo source |
| retired | Adapter is no longer active |

## Adapter rule table

| Condition | Validation state | Runtime routing |
|---|---|---|
| Source type is recognized and required context is present | accepted | publish_to_event_bus |
| Source type is recognized but reviewer context is needed | accepted_with_warning | publish_to_event_bus_and_review |
| Required context is missing | rejected | do_not_publish |
| Payload is stale or outside valid time window | expired | publish_to_exception_topic |
| Source cannot be traced | unverifiable | publish_to_review_topic |
| Adapter is retired | retired | do_not_publish |

## Example adapter object

```json
{
  "adapter_id": "DWA-DEMO-QR-0001",
  "adapter_name": "Demo QR Room Witness Adapter",
  "adapter_class": "qr_adapter",
  "adapter_mode": "demo",
  "source_type": "qr",
  "source_label": "Demo cleanroom QR scan",
  "source_trust_boundary": "demo",
  "accepted_payload_types": ["QR value", "JSON"],
  "required_context_fields": ["actor_context", "room_context", "action_context", "event_timestamp"],
  "optional_context_fields": ["equipment_context", "procedure_context", "environment_context", "time_context"],
  "normalization_rule": "map_qr_value_to_room_identity_observed_event",
  "evidence_mapping_rule": "bind_qr_scan_to_room_evidence_reference",
  "routing_topic": "runtime.context.mesh_update",
  "output_event_type": "room_identity_observed",
  "output_event_category": "identity_event",
  "validation_state": "accepted_with_warning",
  "rejection_reason": null,
  "trace_required": true,
  "generated_by": "Platform B v0.7 demo",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Relationship to v0.7 runtime

The Device-Agnostic Witness Adapter converts source-specific signals into normalized runtime events.

The Runtime Context Witness Event Bus receives those events.

The Assurance-Sensed Site Runtime uses those events to update evidence mesh relationships, refresh passports, evaluate admissibility, raise exception-only alerts, route reviewer packets, and record traceable runtime decisions.

## Guardrails

This schema is for a controlled non-production demonstrator.

It does not support patient use, batch release, shipment release, clinical use, regulatory submission use, validated GMP use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
