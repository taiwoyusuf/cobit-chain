# Platform B v0.8 - Action Gate Simulation Console

## Purpose

The Action Gate Simulation Console defines the non-production demo interface for showing how Platform B evaluates regulated action admissibility before an action proceeds.

## Core doctrine

A regulated action should not proceed because data exists. It should proceed only when the evidence state makes the action admissible.

## Primary question

Can this regulated action proceed now, and what evidence makes that decision defensible?

## Console role

The console simulates how an action request passes through eligibility, evidence sufficiency, admissibility, exception mapping, human review, and evidence packet generation.

The console does not execute regulated actions.

It is a teaching and demonstration artifact only.

## Planned console panels

- action_request_panel
- eligibility_rule_panel
- evidence_sufficiency_panel
- admissibility_decision_panel
- exception_mapping_panel
- human_override_panel
- pre_action_packet_panel
- post_action_challenge_panel
- decision_timeline_panel
- guardrail_notice_panel

## Simulated action states

- eligible
- conditionally_eligible
- not_eligible
- admissible
- conditionally_admissible
- not_admissible
- human_review_required
- exception_required
- evidence_packet_required
- challenge_ready

## Demo scenarios

- cleanroom_entry_action
- black_box_equipment_action
- lasair_ems_environmental_action
- dose_time_window_action
- endosafe_backup_action
- human_override_action
- post_action_challenge_action

## Demonstration flow

1. Select a regulated action scenario.
2. Load current runtime context.
3. Evaluate eligibility rules.
4. Score evidence sufficiency.
5. Map exceptions to admissibility impact.
6. Generate an admissibility decision.
7. Route human review when required.
8. Generate pre-action evidence packet when required.
9. Generate post-action challenge packet when required.
10. Display a challenge-ready decision trail.

## Console outputs

- action_gate_status
- admissibility_decision_status
- evidence_sufficiency_status
- failed_conditions
- required_reviewer_action
- required_exception_path
- evidence_packet_status
- challenge_readiness_status

## Relationship to v0.8 schemas

The console demonstrates the behavior of the Regulated Action Admissibility Engine, Action Eligibility Rule Model, Evidence Sufficiency Scoring Model, Human Override and Justification Ledger, Decision Record, Evidence Packets, and Exception-to-Admissibility Mapping.

## Guardrails

This console is part of a controlled non-production demonstrator.

It does not use patient data, real GMP batch data, confidential company information, or production system data.

It does not claim validated GMP use, clinical use, patient use, batch release support, shipment release support, regulatory submission use, autonomous execution, production compliance, or replacement of QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
