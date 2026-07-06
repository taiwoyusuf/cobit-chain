# Platform B v0.8 - Pull Request Body

## Title

Platform B v0.8 - Regulated Action Admissibility Engine

## Summary

This pull request adds Platform B v0.8, titled Regulated Action Admissibility Engine.

v0.8 extends Platform B from assurance-sensed runtime observation into structured admissibility logic for regulated actions.

## Core doctrine

A regulated action should not proceed because data exists. It should proceed only when the evidence state makes the action admissible.

## Primary runtime question

Can this regulated action proceed now, and what evidence makes that decision defensible?

## Carry-forward doctrines

- The device senses. Platform B assures.
- The future regulated site will not only be monitored. It will be assurance-sensed.
- A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.
- The environment is part of the evidence.
- Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Added v0.8 files

- PLATFORM_B_V0_8_PLANNING_LOCK.md
- REGULATED_ACTION_ADMISSIBILITY_ENGINE_SCHEMA.md
- ACTION_ELIGIBILITY_RULE_MODEL.md
- EVIDENCE_SUFFICIENCY_SCORING_MODEL.md
- HUMAN_OVERRIDE_AND_JUSTIFICATION_LEDGER.md
- ADMISSIBILITY_DECISION_RECORD_SCHEMA.md
- PRE_ACTION_EVIDENCE_PACKET_SCHEMA.md
- POST_ACTION_CHALLENGE_PACKET_SCHEMA.md
- EXCEPTION_TO_ADMISSIBILITY_MAPPING.md
- ACTION_GATE_SIMULATION_CONSOLE.md
- demo_console/index.html
- demo_console/regulated_action_admissibility_engine.html
- demo_console/action_eligibility_rule_model.html
- demo_console/evidence_sufficiency_scoring_model.html
- demo_console/human_override_and_justification_ledger.html
- demo_console/admissibility_decision_record.html
- demo_console/pre_action_evidence_packet.html
- demo_console/post_action_challenge_packet.html
- demo_console/exception_to_admissibility_mapping.html
- demo_console/action_gate_simulation_console.html
- demo_console/demo_seed_v08.json
- demo_console/V0_8_DEMO_CONSOLE_MANIFEST.md
- V0_8_PULL_REQUEST_BODY.md

## What v0.8 adds

v0.8 introduces a regulated action gate model that determines whether an action is:

- Admissible
- Conditionally admissible
- Not admissible
- Requires human review
- Requires exception handling
- Requires evidence packet generation

## v0.8 capabilities introduced

- Regulated Action Admissibility Engine
- Action Eligibility Rule Model
- Evidence Sufficiency Scoring Model
- Human Override and Justification Ledger
- Admissibility Decision Record
- Pre-Action Evidence Packet
- Post-Action Challenge Packet
- Exception-to-Admissibility Mapping
- Action Gate Simulation Console
- v0.8 demo console scaffold

## Demo scenarios

- cleanroom_entry_action
- black_box_equipment_action
- lasair_ems_environmental_action
- dose_time_window_action
- endosafe_backup_action
- human_override_action
- post_action_challenge_action

## Relationship to v0.7

v0.7 created the assurance-sensed site runtime.

v0.8 uses runtime evidence to determine whether a regulated action is admissible before, during, or after execution.

## Guardrails

This is a controlled non-production demonstrator.

This pull request does not claim:

- Validated GMP use
- Clinical use
- Patient use
- Batch release support
- Shipment release support
- Regulatory submission use
- Autonomous execution
- Production compliance
- Replacement of QMS, MES, LIMS, EMS, Lasair, validated systems, or human review

## Verification

The v0.8 file set and demo console scaffold were verified before creating the v0.8 release tag.

Release tag:

platform-b-v0.8-regulated-action-admissibility-engine
