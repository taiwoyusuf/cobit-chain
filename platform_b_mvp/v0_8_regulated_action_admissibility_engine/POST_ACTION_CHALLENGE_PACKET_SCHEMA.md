# Platform B v0.8 - Post-Action Challenge Packet Schema

## Purpose

The Post-Action Challenge Packet Schema defines the evidence bundle used to defend, review, challenge, or explain a regulated action after it has occurred.

## Core doctrine

After action, evidence should explain not only what happened, but why the action was admissible at the time it occurred.

## Primary question

Can the completed regulated action be defended using the evidence, context, decision record, reviewer state, and exception state that existed at the time?

## Packet purpose

The post-action challenge packet preserves the decision trail needed for audit, investigation, review, deviation triage, CAPA triage, or operational learning.

It should distinguish between evidence available before the action and evidence generated after the action.

## Minimum packet fields

Each post-action challenge packet should include:

- challenge_packet_id
- action_id
- action_type
- action_timestamp
- packet_generation_timestamp
- admissibility_decision_id
- pre_action_evidence_packet_id
- human_override_ledger_reference
- exception_reference
- action_outcome
- evidence_available_before_action
- evidence_generated_during_action
- evidence_generated_after_action
- failed_or_challenged_conditions
- reviewer_findings
- procedural_alignment_status
- environmental_alignment_status
- equipment_alignment_status
- site_readiness_alignment_status
- challenge_rationale
- follow_up_required
- packet_status

## Packet statuses

- challenge_ready
- conditionally_challenge_ready
- not_challenge_ready
- incomplete
- conflicted
- reviewer_required
- exception_required
- follow_up_required

## Challenge packet logic

A packet is challenge-ready when it can show what action occurred, what evidence existed before action, what decision was made, who reviewed or overrode it, what exceptions applied, and what outcome followed.

A packet is conditionally challenge-ready when the action can be explained but requires reviewer confirmation, additional linkage, or exception documentation.

A packet is not challenge-ready when evidence is missing, contradicted, unattributable, expired, or not linked to the decision record.

## Relationship to pre-action evidence

The pre-action evidence packet shows what was known before action.

The post-action challenge packet shows whether the action remains defensible after execution.

## Relationship to CAPA and deviation triage

This packet does not create CAPA or deviation records by itself.

It can support triage by showing whether the issue is an evidence gap, procedure gap, environment gap, reviewer gap, exception gap, or execution gap.

## Guardrails

This schema is part of a controlled non-production demonstrator.

It does not use patient data, real GMP batch data, confidential company information, or production system data.

It does not claim validated GMP use, clinical use, patient use, batch release support, shipment release support, regulatory submission use, autonomous execution, production compliance, or replacement of QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
