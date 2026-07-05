# Demo 1 - Endosafe Backup Guardian

## Document status

PLATFORM B V0.5 DEMO TRACK

## Scenario

An operator enters or scans the Endosafe area.

Platform B checks whether backup evidence is current.

If backup evidence is current, Quiet Assurance Mode remains silent.

If backup evidence is missing, Platform B creates a Yellow alert.

If closure is attempted without backup evidence, Platform B creates a Red action-not-admissible alert.

## Demo inputs

| Input | Demo value |
|---|---|
| Asset | EQP-DEMO-ENDOSAFE-001 |
| Area | Demo Endosafe Area |
| Operator | Demo Operator 001 |
| Workflow context | backup |
| Evidence type | backup evidence |
| Context witness | QR / NFC / phone / glasses / M5Stack |

## Decision logic

### Green state

Backup evidence is present and current.

Quiet Assurance Mode remains silent.

Recommended action:

Continue.

### Yellow state

Backup evidence is missing, stale, or not linked to the asset.

Yellow alert:

Endosafe backup evidence missing. Review required.

Recommended action:

Capture evidence or assign reviewer.

### Red state

Closure or completion is attempted without required backup evidence.

Red alert:

Action not admissible.

Recommended action:

Stop and escalate.

## Context witness event example

```json
{
  "event_id": "CTX-ENDOSAFE-001",
  "source_type": "qr",
  "device_vendor": "android",
  "asset_id": "EQP-DEMO-ENDOSAFE-001",
  "operator_id": "Demo Operator 001",
  "location_signal": "Demo Endosafe Area",
  "workflow_context": "backup",
  "event_type": "asset_scan",
  "evidence_reference": "EV-ENDOSAFE-BACKUP-001",
  "context_signal": "yellow",
  "action_admissibility": "review_required",
  "trust_state": "partially_assured",
  "recommended_action": "capture_evidence"
}
```

## Reviewer view

A reviewer should see:

- Endosafe asset ID
- backup evidence status
- last evidence reference
- context signal
- action admissibility
- recommended action
- trust state
- exportable evidence summary

## Demo route idea

A future local demo page can be called:

endosafe_backup_guardian.html

The page should simulate:

- scan Endosafe asset
- check backup evidence age
- generate Green / Yellow / Red signal
- create evidence record
- generate exportable summary

## Doctrine

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Guardrail

This demo does not connect to or control real Endosafe equipment.

This demo does not replace backup procedure, SOP, QMS, LIMS, or validated system controls.

This demo is controlled, non-production, non-GMP, non-patient, and non-confidential.
