# Platform B v0.8 - Action Eligibility Rule Model

## Purpose

The Action Eligibility Rule Model defines the minimum rule structure used to decide whether a regulated action is eligible for admissibility evaluation.

Eligibility is the first gate before admissibility.

## Core doctrine

A regulated action cannot be admissible until it is first eligible to be evaluated.

## Primary question

Is this action eligible for admissibility evaluation under the current person, room, equipment, procedure, environment, time, evidence, and review context?

## Rule categories

- person_eligibility
- room_eligibility
- equipment_eligibility
- procedure_eligibility
- environment_eligibility
- time_eligibility
- evidence_eligibility
- reviewer_eligibility
- exception_eligibility
- site_readiness_eligibility

## Minimum rule fields

Each eligibility rule should include:

- rule_id
- rule_name
- rule_category
- action_type
- required_context
- pass_condition
- fail_condition
- conditional_condition
- evidence_required
- reviewer_required
- exception_path
- expiry_rule
- rule_owner
- rule_version
- rule_status

## Eligibility statuses

- eligible
- conditionally_eligible
- not_eligible
- expired_context
- insufficient_context
- reviewer_required
- exception_required

## Rule evaluation sequence

The eligibility model evaluates action context before the admissibility engine makes a decision.

The recommended sequence is:

1. Confirm the requested action type.
2. Confirm the required procedural context.
3. Confirm person eligibility.
4. Confirm room and site readiness eligibility.
5. Confirm equipment eligibility.
6. Confirm environmental eligibility.
7. Confirm evidence availability and freshness.
8. Confirm reviewer or exception routing requirements.
9. Return eligibility status to the admissibility engine.

## Example eligibility logic

An action is eligible only when the required action context exists and the minimum eligibility rules can be evaluated.

An action is conditionally eligible when required evidence exists but additional controls, reviewer confirmation, or exception handling are required.

An action is not eligible when the action lacks required context, relies on expired evidence, conflicts with site readiness state, or falls outside approved procedural conditions.

## Difference between eligibility and admissibility

Eligibility asks whether the action can be evaluated.

Admissibility asks whether the action can proceed.

## Runtime relationship

The Action Eligibility Rule Model receives runtime context from the assurance-sensed site runtime and passes an eligibility status to the Regulated Action Admissibility Engine.

## Guardrails

This model is part of a controlled non-production demonstrator.

It does not use patient data, real GMP batch data, confidential company information, or production system data.

It does not claim validated GMP use, clinical use, patient use, batch release support, shipment release support, regulatory submission use, autonomous execution, production compliance, or replacement of QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
