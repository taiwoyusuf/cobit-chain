# Platform B v0.8 - Admissibility Decision Record Schema

## Purpose

The Admissibility Decision Record Schema defines the minimum evidence record created when Platform B determines whether a regulated action may proceed.

## Core doctrine

A regulated action is defensible only when the decision, evidence, context, reviewer state, and exception state are recorded together.

## Primary question

What decision was made, why was it made, what evidence supported it, and what conditions applied at the time?

## Decision record purpose

The decision record creates a traceable evidence object for each admissibility decision.

It should preserve both the decision outcome and the evidence state that existed when the decision was made.

## Minimum record fields

Each admissibility decision record should include:

- decision_id
- action_id
- action_type
- decision_timestamp
- decision_status
- decision_reason
- eligibility_status
- evidence_sufficiency_status
- person_state_reference
- room_state_reference
- equipment_state_reference
- procedure_state_reference
- environment_state_reference
- time_state_reference
- site_readiness_reference
- reviewer_state_reference
- exception_state_reference
- evidence_packet_reference
- failed_conditions
- conditional_controls
- required_follow_up
- expiry_time
- challenge_readiness_status

## Decision statuses

- admissible
- conditionally_admissible
- not_admissible
- human_review_required
- exception_required
- evidence_packet_required
- expired_context
- insufficient_evidence

## Decision rationale requirements

The decision rationale should explain:

- why the action was allowed, blocked, paused, or escalated
- which evidence inputs were used
- which context states passed
- which context states failed
- whether human review was required
- whether exception routing was required
- whether the action decision has an expiry time

## Record immutability principle

A decision record should not be overwritten when later evidence arrives.

Later updates should create linked follow-up records, reviewer events, exception events, or challenge packets.

## Relationship to human override

If a human reviewer confirms, overrides, rejects, or defers the admissibility decision, the human event should be recorded separately in the Human Override and Justification Ledger.

The original admissibility decision record should remain traceable.

## Relationship to evidence packets

The decision record should link to pre-action evidence packets and post-action challenge packets when those packets are generated.

## Guardrails

This schema is part of a controlled non-production demonstrator.

It does not use patient data, real GMP batch data, confidential company information, or production system data.

It does not claim validated GMP use, clinical use, patient use, batch release support, shipment release support, regulatory submission use, autonomous execution, production compliance, or replacement of QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
