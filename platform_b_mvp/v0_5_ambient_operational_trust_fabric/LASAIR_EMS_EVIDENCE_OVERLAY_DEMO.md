# Demo 4 - Lasair / EMS Evidence Overlay

## Document status

PLATFORM B V0.5 DEMO TRACK

## Scenario

Particle monitoring and environmental monitoring data may exist in separate systems.

Platform B does not replace Lasair or EMS.

Platform B ingests, references, or simulates evidence status and evaluates whether environmental evidence is sufficient for action.

## Core doctrine

Particle counters measure. EMS monitors. Platform B proves whether the environment is admissible for action.

## Demo inputs

| Input | Demo value |
|---|---|
| Area | AREA-DEMO-LAB-001 |
| Particle source | LASAIR-DEMO-001 |
| EMS source | EMS-DEMO-001 |
| Operator | Demo Operator 001 |
| Workflow context | lab_walkdown / environmental_admissibility |
| Context witness | particle counter / EMS / manual / M5Stack / QR |

## Evidence overlay checks

Platform B checks:

- particle counter status
- EMS status
- last reading age
- environmental excursion flag
- evidence availability
- evidence linkage to room or area
- reviewer requirement
- action admissibility

## Decision logic

### Green state

Environmental evidence is present, current, linked, and acceptable for the demo action.

Recommended action:

Proceed.

### Yellow state

Evidence exists but is stale, incomplete, or requires reviewer confirmation.

Recommended action:

Review required.

### Red state

Environmental evidence is missing, not linked, contradictory, or indicates a stop condition.

Recommended action:

Stop and escalate.

## Context witness event example

```json
{
  "event_id": "CTX-LASAIR-EMS-001",
  "source_type": "particle_counter",
  "device_vendor": "lasair",
  "asset_id": "AREA-DEMO-LAB-001",
  "operator_id": "Demo Operator 001",
  "location_signal": "Demo Lab Room",
  "workflow_context": "lab_walkdown",
  "event_type": "sensor_trigger",
  "evidence_reference": "EV-LASAIR-EMS-001",
  "context_signal": "yellow",
  "action_admissibility": "review_required",
  "trust_state": "partially_assured",
  "recommended_action": "assign_reviewer"
}
```

## Reviewer view

A reviewer should see:

- room or area ID
- particle counter source
- EMS source
- last reading age
- excursion status
- evidence reference
- evidence gaps
- context signal
- action admissibility
- recommended action
- exportable evidence summary

## Demo route idea

A future local demo page can be called:

lasair_ems_evidence_overlay.html

The page should simulate:

- choose room or lab area
- simulate particle counter status
- simulate EMS status
- identify environmental evidence gaps
- generate Green / Yellow / Red action admissibility
- export evidence summary

## Guardrail

Platform B does not replace Lasair, EMS, environmental monitoring procedure, QMS, validation, or release processes.

This demo is controlled, non-production, non-GMP, non-patient, and non-confidential.

## Protected phrase

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.
