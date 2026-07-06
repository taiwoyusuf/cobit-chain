# Platform B v0.8 - Exception-to-Admissibility Mapping

## Purpose

The Exception-to-Admissibility Mapping defines how exceptions, gaps, conflicts, expired evidence, reviewer conditions, and environmental failures affect whether a regulated action may proceed.

## Core doctrine

An exception is not just a warning. It changes the admissibility state of the action.

## Primary question

How does this exception affect the action decision, evidence packet, reviewer requirement, and challenge readiness?

## Exception classes

- missing_evidence
- expired_evidence
- conflicted_evidence
- unattributable_evidence
- procedure_mismatch
- equipment_not_ready
- room_not_ready
- environmental_out_of_range
- reviewer_unavailable
- reviewer_authority_gap
- site_readiness_gap
- time_window_violation
- human_override_required
- post_action_challenge_gap

## Minimum mapping fields

Each exception mapping should include:

- mapping_id
- exception_type
- exception_severity
- action_type
- affected_context_state
- admissibility_impact
- eligibility_impact
- evidence_packet_impact
- reviewer_requirement
- exception_path
- allowed_conditional_controls
- blocking_conditions
- follow_up_required
- challenge_readiness_impact
- mapping_owner
- mapping_version
- mapping_status

## Admissibility impacts

- no_impact
- conditionally_admissible
- human_review_required
- exception_required
- evidence_packet_required
- not_admissible
- expired_context
- insufficient_evidence

## Mapping logic

The mapping determines whether an exception blocks the action, allows the action under defined controls, routes human review, requires an evidence packet, or creates a post-action challenge requirement.

An exception should not be ignored because other signals are green.

The exception must be evaluated against the action type, procedural context, evidence state, reviewer state, and site readiness state.

## Example mappings

- missing_evidence may create insufficient_evidence or evidence_packet_required.
- expired_evidence may create expired_context or not_admissible.
- environmental_out_of_range may create not_admissible or human_review_required.
- reviewer_authority_gap may create human_review_required or not_admissible.
- procedure_mismatch may create not_admissible.
- post_action_challenge_gap may create follow_up_required.

## Relationship to admissibility

The admissibility engine uses exception mapping to determine whether the current exception state changes the action decision.

A mapped exception may block the action, downgrade admissibility, require a reviewer, require a packet, or trigger challenge-readiness review.

## Relationship to human review

When an exception requires human review, the reviewer action should be recorded in the Human Override and Justification Ledger.

The exception should remain linked to the original decision record.

## Guardrails

This mapping is part of a controlled non-production demonstrator.

It does not use patient data, real GMP batch data, confidential company information, or production system data.

It does not claim validated GMP use, clinical use, patient use, batch release support, shipment release support, regulatory submission use, autonomous execution, production compliance, or replacement of QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
