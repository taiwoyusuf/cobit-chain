# Demo 2 - Speedy Glove Black Box Evidence Gateway

## Document status

PLATFORM B V0.5 DEMO TRACK

## Scenario

Speedy Glove does not communicate directly across the network.

Platform B does not touch or control the equipment.

A QR tag, NFC tag, wearable photo or video, manual evidence upload, or external M5Stack evidence node makes the equipment assurance-visible.

## Core doctrine

The equipment does not need to be connected to be assurance-visible.

## Demo inputs

| Input | Demo value |
|---|---|
| Asset | EQP-DEMO-SPEEDY-GLOVE-1803 |
| Area | Demo Glovebox Area |
| Operator | Demo Operator 001 |
| Workflow context | black_box_evidence_gateway |
| Context witness | QR / NFC / glasses / phone / manual / M5Stack |
| Evidence type | photo, video, manual check, or external node signal |

## Assurance objective

The demo shows that Platform B can make a non-networked asset visible to assurance without controlling the asset.

Platform B does not need to modify the equipment.

Platform B does not need to network the equipment.

Platform B does not need to operate the equipment.

Platform B only captures or references external evidence that the equipment state was observed.

## Decision logic

### Green state

Evidence exists, is linked to the correct asset, and is recent enough for the demo context.

Recommended action:

Continue.

### Yellow state

Evidence exists but needs reviewer confirmation or asset linkage review.

Recommended action:

Assign reviewer.

### Red state

Evidence is missing, wrong-asset evidence is detected, or closure is attempted without required proof.

Recommended action:

Stop and escalate.

## Context witness event example

```json
{
  "event_id": "CTX-SG-001",
  "source_type": "manual",
  "device_vendor": "m5stack",
  "asset_id": "EQP-DEMO-SPEEDY-GLOVE-1803",
  "operator_id": "Demo Operator 001",
  "location_signal": "Demo Glovebox Area",
  "workflow_context": "lab_walkdown",
  "event_type": "evidence_capture",
  "evidence_reference": "EV-SG-BLACKBOX-001",
  "context_signal": "green",
  "action_admissibility": "proceed",
  "trust_state": "assured",
  "recommended_action": "continue"
}
```

## Reviewer view

A reviewer should see:

- Speedy Glove demo asset ID
- evidence source
- evidence reference
- observation time
- context signal
- action admissibility
- trust state
- reviewer requirement
- exportable evidence summary

## Demo route idea

A future local demo page can be called:

speedy_glove_black_box_gateway.html

The page should simulate:

- scan Speedy Glove asset
- capture wearable or manual evidence
- link evidence to asset
- generate Green / Yellow / Red signal
- create evidence record
- generate exportable summary

## Guardrail

Platform B does not control Speedy Glove.

Platform B does not replace validation, maintenance, calibration, SOP, QMS, or production records.

This demo is controlled, non-production, non-GMP, non-patient, and non-confidential.
