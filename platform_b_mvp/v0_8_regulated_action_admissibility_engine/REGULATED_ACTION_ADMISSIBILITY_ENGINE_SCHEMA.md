# Platform B v0.8 - Regulated Action Admissibility Engine Schema

## Purpose

The Regulated Action Admissibility Engine defines how Platform B determines whether a regulated action may proceed, pause, escalate, or require evidence packet generation.

## Core doctrine

A regulated action should not proceed because data exists. It should proceed only when the evidence state makes the action admissible.

## Primary question

Can this regulated action proceed now, and what evidence makes that decision defensible?

## Engine role

The engine receives the current trust state from the assurance-sensed runtime and converts it into an admissibility decision.

It does not execute the action.

It does not replace human review.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, or approved procedures.

## Required input classes

- action_context
- person_state
- room_state
- equipment_state
- procedure_state
- environment_state
- time_state
- evidence_state
- reviewer_state
- exception_state
- site_readiness_state
- prior_decision_state

## Output decision classes

- admissible
- conditionally_admissible
- not_admissible
- human_review_required
- exception_required
- evidence_packet_required
- expired_context
- insufficient_evidence

## Minimum decision record

Each admissibility decision should record:

- decision_id
- action_id
- action_type
- decision_timestamp
- decision_status
- decision_reason
- evidence_inputs
- failed_conditions
- conditional_controls
- reviewer_requirement
- exception_requirement
- evidence_packet_reference
- expiry_time
- challenge_readiness_status

## Decision logic

The engine evaluates whether the current evidence mesh supports the requested regulated action.

A decision is admissible only when all required context states are present, current, attributable, and consistent.

A decision is conditionally admissible when the action may proceed only with defined controls, reviewer confirmation, or documented justification.

A decision is not admissible when evidence is missing, expired, conflicted, failed, or outside the required procedural context.

## Evidence sufficiency

Evidence is sufficient only when it supports the person, place, equipment, procedure, environment, time, and review state required for the action.

Evidence sufficiency is not the same as data availability.

## Runtime relationship

v0.7 created the assurance-sensed runtime.

v0.8 uses that runtime state to decide whether a regulated action is admissible.

## Guardrails

This schema is part of a controlled non-production demonstrator.

It does not use patient data, real GMP batch data, confidential company information, or production system data.

It does not claim validated GMP use, clinical use, patient use, batch release support, shipment release support, regulatory submission use, autonomous execution, production compliance, or replacement of QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
