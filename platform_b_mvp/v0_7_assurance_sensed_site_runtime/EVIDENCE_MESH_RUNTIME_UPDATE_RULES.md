# Evidence Mesh Runtime Update Rules

## Platform

Platform B v0.7 - Assurance-Sensed Site Runtime

## Purpose

The Evidence Mesh Runtime Update Rules define how Platform B v0.7 updates evidence relationships as new runtime witness events arrive.

These rules convert live context into evidence mesh changes that can refresh trust passports, update readiness states, write admissibility records, raise exception-only alerts, and route reviewer evidence packets.

## Core doctrine

The future regulated site will not only be monitored. It will be assurance-sensed.

## Carry-forward doctrines

The device senses. Platform B assures.

A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.

The environment is part of the evidence.

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Runtime mesh question

When a new witness event arrives, what evidence relationship changed, and does that change affect action admissibility now?

## Mesh update stages

| Stage | Purpose |
|---|---|
| receive_event | Receive normalized runtime event from the Runtime Context Witness Event Bus |
| identify_mesh_scope | Identify the evidence mesh affected by the event |
| map_event_to_node | Map event to person, room, equipment, procedure, environment, time, evidence, action, exception, or review node |
| create_or_update_relationship | Create or update supporting, contradicting, expired, missing, reviewer-required, or blocking relationship |
| evaluate_agreement | Evaluate whether the mesh agrees, partially agrees, conflicts, or is incomplete |
| update_mesh_state | Update mesh trust state and readiness impact |
| trigger_passport_refresh | Trigger affected Operational Trust Passport refresh |
| trigger_admissibility_update | Trigger Action Admissibility Ledger update |
| trigger_exception_logic | Trigger Exception-Only Alert logic when trust is at risk |
| trigger_review_route | Trigger reviewer route when human confirmation is required |
| record_mesh_trace | Record the runtime mesh update trace |

## Runtime mesh node types

| Node type | Runtime meaning |
|---|---|
| person_node | Operator, reviewer, approver, or accountable actor |
| room_node | Room, hood, cleanroom, suite, or controlled area |
| equipment_node | Equipment, instrument, workstation, black-box device, or sensor |
| procedure_node | Procedure, checklist, instruction, version, or step |
| environment_node | EMS, Lasair, particle, cleaning, temperature, humidity, pressure, or certification evidence |
| time_node | Dose, cleaning, calibration, review, shipment, or action time window |
| evidence_node | File, export, screenshot, log, attestation, or evidence packet |
| action_node | Action being evaluated by the runtime |
| exception_node | Yellow, red, expired, escalated, or closed condition |
| review_node | Reviewer route, reviewer packet, reviewer decision, or review state |

## Runtime relationship types

| Relationship | Meaning |
|---|---|
| supports | Evidence supports the trust state or action context |
| contradicts | Evidence conflicts with another signal or record |
| requires_review | Evidence exists but human confirmation is required |
| blocks_action | Evidence condition blocks action from proceeding |
| allows_action | Evidence condition supports action proceeding under demo rules |
| expires_action | Time or evidence expiry makes the action expired |
| updates_passport | Mesh change refreshes an Operational Trust Passport |
| writes_ledger | Mesh change writes or updates an Action Admissibility Ledger entry |
| raises_alert | Mesh change raises an Exception-Only Alert |
| routes_reviewer | Mesh change routes a Reviewer Evidence Packet |
| closes_exception | Mesh change supports closure of a prior exception |

## Required runtime update fields

| Field | Description |
|---|---|
| mesh_update_id | Unique runtime mesh update identifier |
| runtime_id | Assurance-Sensed Site Runtime linked to the update |
| evidence_mesh_id | Ambient Evidence Mesh being updated |
| trigger_event_id | Runtime event that triggered the update |
| source_node_id | Source node created or updated by the event |
| source_node_type | Person, room, equipment, procedure, environment, time, evidence, action, exception, or review |
| target_node_id | Target node affected by the relationship |
| target_node_type | Person, room, equipment, procedure, environment, time, evidence, action, exception, or review |
| relationship_type | supports, contradicts, requires_review, blocks_action, allows_action, expires_action, updates_passport, writes_ledger, raises_alert, routes_reviewer, or closes_exception |
| previous_relationship_state | Prior relationship state before the update |
| new_relationship_state | New relationship state after the update |
| mesh_agreement_state | agrees, partially_agrees, conflicts, incomplete, expired, or unverifiable |
| mesh_trust_state | assured, partially_assured, not_assured, pending, expired, or retired |
| readiness_impact | people, room, equipment, procedure, environment, time, evidence, review, exception, action, or site |
| admissibility_impact | none, proceed, review_required, stop, expired, or not_applicable |
| passport_refresh_required | True or false |
| ledger_update_required | True or false |
| alert_update_required | True or false |
| reviewer_route_required | True or false |
| update_reason | Human-readable explanation of the mesh update |
| updated_at | Runtime mesh update timestamp |
| generated_by | System, user, or demo process that generated the update |
| guardrail_status | Demonstrator-only, non-production, no validated-use claim |

## Runtime update rule table

| Condition | Relationship update | Mesh state | Runtime impact |
|---|---|---|---|
| New evidence supports existing context | supports | agrees | proceed or no change |
| Evidence supports context but reviewer confirmation is required | requires_review | partially_agrees | review_required |
| Evidence conflicts with existing context | contradicts | conflicts | stop or review_required |
| Required evidence is missing | blocks_action | incomplete | stop |
| Evidence or time window expired | expires_action | expired | expired |
| Reviewer approves pending evidence | allows_action | agrees | proceed |
| Reviewer rejects pending evidence | blocks_action | conflicts | stop |
| Exception is resolved with evidence | closes_exception | agrees or partially_agrees | proceed or review_required |
| Event is informational only | supports | agrees | not_applicable |

## Example mesh update object

```json
{
  "mesh_update_id": "EMRU-DEMO-0001",
  "runtime_id": "ASR-DEMO-0001",
  "evidence_mesh_id": "AEM-DEMO-0002",
  "trigger_event_id": "RTE-DEMO-0001",
  "source_node_id": "EV-DEMO-ROOM-001",
  "source_node_type": "evidence_node",
  "target_node_id": "ROOM-DEMO-CLEANROOM-001",
  "target_node_type": "room_node",
  "relationship_type": "requires_review",
  "previous_relationship_state": "missing",
  "new_relationship_state": "linked_pending_review",
  "mesh_agreement_state": "partially_agrees",
  "mesh_trust_state": "partially_assured",
  "readiness_impact": "room",
  "admissibility_impact": "review_required",
  "passport_refresh_required": true,
  "ledger_update_required": true,
  "alert_update_required": true,
  "reviewer_route_required": true,
  "update_reason": "Room identity evidence is linked but reviewer confirmation is required before action proceeds.",
  "updated_at": "2026-07-05T12:03:00Z",
  "generated_by": "Platform B v0.7 demo",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Relationship to v0.7 runtime

The Device-Agnostic Witness Adapter normalizes source signals.

The Runtime Context Witness Event Bus routes normalized events.

The Evidence Mesh Runtime Update Rules decide how evidence relationships change.

The Live Site Readiness Evaluation Loop uses those changes to determine runtime readiness and action admissibility.

## Guardrails

This schema is for a controlled non-production demonstrator.

It does not support patient use, batch release, shipment release, clinical use, regulatory submission use, validated GMP use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
