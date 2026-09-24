# RAMAT Watch–Cloud API Contract R1

## Purpose
Define the bounded interface between the portable RAMAT watch demonstration and a synthetic RAMAT gateway. This contract is for demonstration and engineering evaluation only. It does not grant clinical, QA, release, treatment, or other execution authority.

## Architectural boundary
- Watch: display / witness / request / review.
- COBIT-Chain / VSA: assurance evaluator.
- Accountable human authority: separate.
- Connectivity loss must never create a new SUPPORTED state.

## Request
A watch may request the current bounded assurance state for a synthetic mission.

Required fields:
- device_id
- demo_version
- mission_id
- request_time
- last_known_state
- last_sync_time
- connectivity_mode
- locally_available_witness_summary

## Response
A gateway response should contain:
- schema_version
- mission_id
- evaluation_id
- evaluated_state: SUPPORTED | HOLD | CONFLICTING | UNKNOWN
- reason_codes
- evaluated_at
- source_event_time, when applicable
- arrival_time
- historical_state_preserved
- evaluator = COBIT-Chain/VSA
- authority_binding_status
- sync_version

## Offline behavior
When network access is unavailable:
1. The watch keeps the last known state.
2. The watch marks the state as cached/offline.
3. The last successful synchronization time remains visible.
4. The watch must not infer SUPPORTED from loss of connectivity.
5. Locally observed evidence may be queued for later reconciliation.
6. Later arrival of evidence must not be treated as if it had been available at an earlier decision time.

## Non-retroactivity
EVENT OCCURRENCE != GOVERNED EVIDENCE AVAILABILITY

LATER EVIDENCE != EARLIER PREVENTIVE SUPPORT

A later response may restore current standing while preserving an earlier HOLD or CONFLICTING state in history.

## Authority
The watch can request reassessment and display results. It cannot unilaterally convert HOLD or CONFLICTING to SUPPORTED.

REQUEST != AUTHORIZATION

DISPLAYED STATE != WATCH-CREATED STANDING

## Synthetic-use ceiling
No production endpoint, patient data, employer system, validated GxP system, clinical workflow, or release decision is authorized by this contract.
