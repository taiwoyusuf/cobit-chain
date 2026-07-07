# WearableContextEvent Schema

## Purpose

Define the backlog event shape for wearable context submitted to Platform B.

## Object name

WearableContextEvent

## Required fields

- event_id
- device_family
- device_role
- device_id
- user_id
- user_role
- timestamp
- site_context
- zone_context
- task_context
- visual_candidate_id
- voice_intent_id
- human_confirmation_id
- device_readiness_passport_id
- evidence_packet_id
- confidence_score
- privacy_boundary_state
- platform_b_decision_state

## Device families

- ELSA 22.4
- OMA 5.4
- RAMAT Vision Pro
- JEFERY
- Halo
- Future context witness device

## Event states

- CAPTURED
- DISPLAYED
- RELAYED
- TRANSLATED
- REVIEWED
- ESCALATED
- BLOCKED
- STOP_LINE_RECORDED

## Guardrail

WearableContextEvent records context. It does not approve the regulated action.
