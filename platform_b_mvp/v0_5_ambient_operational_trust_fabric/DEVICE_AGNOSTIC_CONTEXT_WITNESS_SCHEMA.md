# Device-Agnostic Context Witness Schema

## Document status

PLATFORM B V0.5 SCHEMA PLANNING

## Purpose

This schema defines the normalized event format for Platform B v0.5 Ambient Operational Trust Fabric.

The schema treats wearables, phones, QR tags, NFC tags, BLE beacons, ESP32/M5Stack nodes, sensors, cameras, EMS systems, particle counters, and manual uploads as context witnesses.

## Doctrine

The device senses. Platform B assures.

## Normalized context witness event

```json
{
  "event_id": "CTX-DEMO-001",
  "source_type": "glasses | phone | qr | nfc | ble | esp32 | sensor | camera | manual | ems | particle_counter",
  "device_vendor": "meta | vuzix | realwear | brilliant | android | m5stack | arduino | lasair | rees | vaisala | manual",
  "asset_id": "EQP-DEMO-ENDOSAFE-001",
  "operator_id": "Demo Operator 001",
  "location_signal": "Demo Endosafe Area",
  "workflow_context": "backup | cleanroom_readiness | batch_stage | compounding | irlt_dose_time | lab_walkdown",
  "event_type": "asset_scan | proximity_detected | evidence_capture | evidence_missing | backup_confirmed | sensor_trigger | environment_excursion",
  "evidence_reference": "EV-DEMO-001",
  "context_signal": "green | yellow | red",
  "action_admissibility": "proceed | review_required | stop",
  "trust_state": "assured | partially_assured | not_assured",
  "recommended_action": "continue | capture_evidence | assign_reviewer | escalate | stop"
}
```

## Field purpose

| Field | Purpose |
|---|---|
| event_id | Unique context witness event ID |
| source_type | Type of device or evidence source |
| device_vendor | Device, vendor, or source family |
| asset_id | Equipment, room, hood, system, or demo asset |
| operator_id | Demo operator or role |
| location_signal | Location, area, beacon, QR/NFC tag, or declared location |
| workflow_context | Operational context being assessed |
| event_type | Type of context witness event |
| evidence_reference | Linked Platform B evidence record |
| context_signal | Green / Yellow / Red context-assurance signal |
| action_admissibility | Proceed / review required / stop |
| trust_state | Assured / partially assured / not assured |
| recommended_action | What should happen next |

## Context witness principle

The witness does not approve.

The witness does not replace the validated system.

The witness provides a signal that Platform B can convert into evidence, assurance, admissibility, trust state, and exception-only alerts.

## Guardrail

This schema is for controlled non-production demonstration only.

It does not create validated GMP, clinical, patient, regulatory submission, batch release, or autonomous execution functionality.
