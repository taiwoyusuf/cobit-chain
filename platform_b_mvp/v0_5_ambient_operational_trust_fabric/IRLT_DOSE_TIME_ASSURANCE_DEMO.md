# Demo 5 - IRLT Dose-Time Evidence Assurance

## Document status

PLATFORM B V0.5 DEMO TRACK

## Scenario

A radiopharma or IRLT workflow is time-sensitive.

Platform B checks whether timing-sensitive evidence is sufficient before the next action proceeds.

## Core doctrine

In radiopharma, time is part of product quality.

## Demo inputs

| Input | Demo value |
|---|---|
| Workflow | IRLT-DEMO-WORKFLOW-001 |
| Area | Demo IRLT Area |
| Operator | Demo Operator 001 |
| Workflow context | irlt_dose_time |
| Context witness | manual / QR / phone / wearable / system signal |
| Evidence type | dose timing, QC, release, chain of custody, reviewer, shipment window |

## Dose-time assurance checks

Platform B checks:

- isotope or dose timing
- QC evidence
- release evidence
- chain of custody
- room state
- equipment state
- human reviewer
- shipment or readiness window
- evidence age
- action admissibility

## Decision logic

### Green state

Dose-time window and required evidence are acceptable.

Recommended action: Proceed.

### Yellow state

Evidence gap, stale signal, reviewer requirement, or timing concern exists.

Recommended action: Review required.

### Red state

Dose-time window fails, required evidence is missing, or action is not admissible.

Recommended action: Stop and escalate.

## Context witness event example

```json
{
  "event_id": "CTX-IRLT-001",
  "source_type": "manual",
  "device_vendor": "manual",
  "asset_id": "IRLT-DEMO-WORKFLOW-001",
  "operator_id": "Demo Operator 001",
  "location_signal": "Demo IRLT Area",
  "workflow_context": "irlt_dose_time",
  "event_type": "asset_scan",
  "evidence_reference": "EV-IRLT-DOSETIME-001",
  "context_signal": "yellow",
  "action_admissibility": "review_required",
  "trust_state": "partially_assured",
  "recommended_action": "assign_reviewer"
}
```

## Reviewer view

A reviewer should see:

- workflow ID
- dose-time state
- QC evidence state
- release evidence state
- chain-of-custody state
- room/equipment readiness
- reviewer requirement
- shipment/readiness window
- context signal
- action admissibility
- exportable evidence summary

## Demo route idea

A future local demo page can be called:

irlt_dose_time_assurance.html

The page should simulate dose-time window, QC evidence, release evidence, chain-of-custody evidence, action admissibility, and exportable evidence summary.

## Guardrail

This demo does not support actual radiopharma release, patient use, batch release, shipment release, clinical use, or regulated decision-making.

This demo is controlled, non-production, non-GMP, non-patient, and non-confidential.

## Protected phrase

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.
