# Ambient Evidence Mesh Schema

## Platform

Platform B v0.6 - Operational Trust Passport and Ambient Evidence Mesh

## Purpose

The Ambient Evidence Mesh connects context witness signals, evidence records, operational context, reviewer decisions, and action admissibility into one explainable trust state.

The mesh does not replace source systems.

The mesh explains why an action is trusted, partially trusted, not trusted, expired, or review-required.

## Core doctrine

A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.

## Continuity from v0.5

The device senses. Platform B assures.

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Mesh node types

| Node type | Meaning |
|---|---|
| person_node | Operator, reviewer, approver, or accountable human actor |
| room_node | Room, hood, cleanroom, suite, controlled area, or work zone |
| equipment_node | Equipment, instrument, non-networked device, workstation, or black-box asset |
| procedure_node | Procedure, step, version, checklist, instruction, or decision point |
| environment_node | EMS, Lasair, particle counter, temperature, humidity, pressure, cleaning, or certification signal |
| time_node | Dose time, cleaning window, calibration window, review window, shipment window, or evidence age |
| evidence_node | Log, export, screenshot, attestation, review packet, event, record, or linked file reference |
| action_node | Action being evaluated for admissibility |
| exception_node | Yellow, red, escalated, closed, or expired exception condition |

## Mesh relationship types

| Relationship | Meaning |
|---|---|
| observed_by | A context witness observed or captured the signal |
| belongs_to | Evidence belongs to a person, room, equipment item, procedure, or action |
| supports | Evidence supports a trust claim |
| contradicts | Evidence conflicts with a trust claim |
| requires_review | Action, evidence, or exception requires human review |
| reviewed_by | Human reviewer is linked to the review decision |
| expires_at | Evidence or context has a defined expiry point |
| blocks_action | Evidence gap or exception blocks action admissibility |
| allows_action | Evidence agreement allows action under the demo rule set |
| generates_passport | Mesh state generates or updates an Operational Trust Passport |

## Required mesh fields

| Field | Description |
|---|---|
| evidence_mesh_id | Unique mesh identifier |
| mesh_context | Workflow or operational context |
| action_context | Action being evaluated |
| mesh_nodes | People, rooms, equipment, procedures, environment, time, evidence, action, and exception nodes |
| mesh_relationships | Evidence and trust relationships between nodes |
| context_witness_events | Linked context witness events from QR, NFC, wearable, IoT, EMS, Lasair, manual, upload, or system source |
| evidence_bundle_refs | Linked evidence objects or references |
| trust_state | assured, partially_assured, not_assured, pending, expired, or retired |
| action_admissibility | proceed, review_required, stop, expired, or not_applicable |
| integrity_state | complete, incomplete, stale, conflicting, or unverifiable |
| exception_state | none, yellow, red, escalated, closed, or expired |
| passport_refs | Operational Trust Passports generated or updated by the mesh |
| reviewer_required | True or false |
| reviewer_decision | approved_to_proceed, rejected, escalated, or pending |
| generated_at | Mesh generation timestamp |
| generated_by | System, user, or demo process that generated the mesh |
| guardrail_status | Demonstrator-only, non-production, no validated-use claim |

## Evidence agreement rules

| Rule | Result |
|---|---|
| Required evidence is present, current, linked, and coherent | assured |
| Evidence exists but requires reviewer confirmation | partially_assured |
| Required evidence is missing | not_assured |
| Evidence is stale or outside its valid window | expired |
| Evidence sources conflict | not_assured or review_required |
| Reviewer decision is pending | pending or review_required |
| Red exception exists | stop |
| Yellow exception exists | review_required |

## Example mesh object

```json
{
  "evidence_mesh_id": "AEM-DEMO-0001",
  "mesh_context": "black_box_evidence_gateway",
  "action_context": "equipment_status_review",
  "mesh_nodes": [
    {"node_id": "EQP-DEMO-SPEEDYGLOVE-001", "node_type": "equipment_node"},
    {"node_id": "CTX-DEMO-QR-001", "node_type": "evidence_node"},
    {"node_id": "EV-DEMO-REVIEW-001", "node_type": "evidence_node"},
    {"node_id": "ACT-DEMO-STATUS-REVIEW", "node_type": "action_node"}
  ],
  "mesh_relationships": [
    {"from": "CTX-DEMO-QR-001", "to": "EQP-DEMO-SPEEDYGLOVE-001", "relationship": "observed_by"},
    {"from": "EV-DEMO-REVIEW-001", "to": "ACT-DEMO-STATUS-REVIEW", "relationship": "supports"},
    {"from": "ACT-DEMO-STATUS-REVIEW", "to": "OTP-DEMO-0001", "relationship": "generates_passport"}
  ],
  "context_witness_events": ["CTX-DEMO-QR-001"],
  "evidence_bundle_refs": ["EV-DEMO-REVIEW-001"],
  "trust_state": "partially_assured",
  "action_admissibility": "review_required",
  "integrity_state": "incomplete",
  "exception_state": "yellow",
  "passport_refs": ["OTP-DEMO-0001"],
  "reviewer_required": true,
  "reviewer_decision": "pending",
  "generated_at": "2026-07-04T12:00:00Z",
  "generated_by": "Platform B v0.6 demo",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Relationship to Operational Trust Passport

The Ambient Evidence Mesh explains the evidence relationships.

The Operational Trust Passport summarizes the resulting trust state for a person, room, equipment item, procedure, environment, time window, action, or site readiness state.

## Guardrails

This schema is for a controlled non-production demonstrator.

It does not support patient use, batch release, shipment release, clinical use, regulatory submission use, validated GMP use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
