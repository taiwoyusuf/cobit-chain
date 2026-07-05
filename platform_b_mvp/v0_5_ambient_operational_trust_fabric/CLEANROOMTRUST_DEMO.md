# Demo 3 - CleanroomTrust

## Document status

PLATFORM B V0.5 DEMO TRACK

## Scenario

A cleanroom, room, suite, or compounding hood is scanned before action proceeds.

Platform B checks whether the environment, evidence, people, procedures, and equipment agree.

## Core doctrine

Cleanroom readiness is not a room state. It is an evidence state.

## Demo inputs

| Input | Demo value |
|---|---|
| Area | ROOM-DEMO-CLEANROOM-001 |
| Hood | HOOD-DEMO-001 |
| Operator | Demo Operator 001 |
| Workflow context | cleanroom_readiness |
| Context witness | QR / NFC / phone / glasses / sensor / M5Stack |
| Evidence type | cleaning, monitoring, certification, personnel, equipment, SOP context |

## Readiness checks

Platform B checks:

- cleaning evidence
- environmental monitoring status
- temperature signal
- humidity signal
- pressure signal
- room or hood certification
- personnel readiness
- equipment status
- SOP step
- reviewer requirement
- evidence gaps

## Decision logic

### Green state

Required readiness evidence is present, current, and aligned.

Recommended action:

Proceed.

### Yellow state

A readiness gap exists but may be resolved through review or evidence capture.

Recommended action:

Review required.

### Red state

Critical readiness evidence is missing, stale, contradictory, or not admissible for action.

Recommended action:

Stop and escalate.

## Context witness event example

```json
{
  "event_id": "CTX-CLEANROOM-001",
  "source_type": "sensor",
  "device_vendor": "m5stack",
  "asset_id": "ROOM-DEMO-CLEANROOM-001",
  "operator_id": "Demo Operator 001",
  "location_signal": "Demo Cleanroom 001",
  "workflow_context": "cleanroom_readiness",
  "event_type": "sensor_trigger",
  "evidence_reference": "EV-CLEANROOM-001",
  "context_signal": "yellow",
  "action_admissibility": "review_required",
  "trust_state": "partially_assured",
  "recommended_action": "assign_reviewer"
}
```

## Reviewer view

A reviewer should see:

- room or hood ID
- cleaning evidence status
- environmental monitoring status
- temperature / humidity / pressure signal
- personnel readiness
- certification status
- SOP context
- evidence gap list
- context signal
- action admissibility
- exportable evidence summary

## Demo route idea

A future local demo page can be called:

cleanroomtrust_demo.html

The page should simulate:

- scan cleanroom or hood
- check cleaning evidence
- check simulated environmental status
- check certification and personnel readiness
- generate Green / Yellow / Red readiness state
- export evidence summary

## Guardrail

This demo does not replace cleanroom certification, EMS, QMS, environmental monitoring systems, or validated release processes.

This demo is controlled, non-production, non-GMP, non-patient, and non-confidential.

## Protected phrase

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.
