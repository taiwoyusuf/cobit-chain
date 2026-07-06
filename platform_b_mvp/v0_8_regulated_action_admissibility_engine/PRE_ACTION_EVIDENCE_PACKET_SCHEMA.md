# Platform B v0.8 - Pre-Action Evidence Packet Schema

## Purpose

The Pre-Action Evidence Packet Schema defines the evidence bundle that should exist before a regulated action proceeds.

## Core doctrine

Before action, evidence should prove readiness, not merely describe activity.

## Primary question

What evidence existed before the action, and was it sufficient to make the action admissible?

## Packet purpose

The pre-action evidence packet captures the evidence state before execution so the admissibility decision can be defended later.

The packet should be generated before the action proceeds, when required by the admissibility engine.

## Minimum packet fields

Each pre-action evidence packet should include:

- packet_id
- action_id
- action_type
- packet_timestamp
- admissibility_decision_id
- eligibility_status
- evidence_sufficiency_status
- person_evidence
- room_evidence
- equipment_evidence
- procedure_evidence
- environment_evidence
- time_evidence
- site_readiness_evidence
- reviewer_evidence
- exception_evidence
- evidence_gaps
- conditional_controls
- required_review
- expiry_time
- packet_status

## Packet statuses

- complete
- conditionally_complete
- incomplete
- expired
- conflicted
- reviewer_required
- exception_required

## Required evidence classes

A pre-action packet should include evidence for:

- the right person
- the right room
- the right equipment
- the right procedure
- the right environmental state
- the right time window
- the right site readiness state
- the right reviewer or exception path

## Evidence packet logic

A packet is complete when required evidence is present, current, attributable, traceable, consistent, and aligned to the action.

A packet is conditionally complete when required evidence exists but reviewer confirmation, additional justification, or conditional controls are required.

A packet is incomplete when evidence is missing, expired, conflicted, or not linked to the action context.

## Relationship to admissibility

The admissibility engine may require a pre-action evidence packet before an action can proceed.

The packet does not approve the action by itself.

The packet supports the decision record by preserving the evidence state before execution.

## Challenge-readiness

The pre-action packet should support later review by showing what was known before the action happened.

This preserves the distinction between evidence available before action and evidence discovered after action.

## Guardrails

This schema is part of a controlled non-production demonstrator.

It does not use patient data, real GMP batch data, confidential company information, or production system data.

It does not claim validated GMP use, clinical use, patient use, batch release support, shipment release support, regulatory submission use, autonomous execution, production compliance, or replacement of QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
