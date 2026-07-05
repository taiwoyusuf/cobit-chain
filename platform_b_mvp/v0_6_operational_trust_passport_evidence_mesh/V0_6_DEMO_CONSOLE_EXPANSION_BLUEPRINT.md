# Platform B v0.6 Demo Console Expansion Blueprint

## Platform

Platform B v0.6 - Operational Trust Passport and Ambient Evidence Mesh

## Purpose

The v0.6 demo console expands the v0.5 Ambient Operational Trust Fabric console into a structured operational trust review experience.

The v0.6 console should show how evidence signals become an Ambient Evidence Mesh, Operational Trust Passport, Action Admissibility Ledger, Context Witness Chain, Reviewer Evidence Packet, Exception-Only Alert, and Site Readiness Trust State.

## Core doctrine

A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.

## Continuity from v0.5

The device senses. Platform B assures.

Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Console pages

| Page | Purpose |
|---|---|
| index.html | v0.6 console landing page and doctrine summary |
| operational_trust_passport.html | Displays person, room, equipment, procedure, environment, time, action, and site trust passports |
| ambient_evidence_mesh.html | Shows linked evidence nodes and relationships |
| action_admissibility_ledger.html | Shows why an action is proceed, review_required, stop, expired, or not_applicable |
| context_witness_chain.html | Shows ordered witness events from QR, NFC, BLE, wearable, IoT, EMS, Lasair, upload, manual, and system sources |
| reviewer_evidence_packet.html | Shows the packet a reviewer uses to make a traceable decision |
| exception_only_alerts.html | Shows quiet, informational, yellow, red, escalated, and closed alert states |
| site_readiness_trust_state.html | Shows overall readiness across people, rooms, equipment, procedures, environment, time, evidence, review, and exceptions |
| demo_seed_v06.json | Seed data for the v0.6 browser demo |

## Demo scenario set

| Scenario | v0.6 focus |
|---|---|
| Cleanroom readiness review | Room, environment, cleaning, procedure, reviewer, and readiness trust state |
| Speedy Glove black-box evidence review | Non-networked equipment evidence, QR witness, upload evidence, reviewer packet |
| Lasair / EMS evidence review | Environmental evidence admissibility, stale evidence, reviewer confirmation |
| IRLT dose-time review | Time window, QC evidence, release evidence, chain of custody, shipment window |
| Endosafe backup guardian review | Backup evidence, closure readiness, missing evidence, exception-only alert |

## Minimum demo behaviors

- Generate a demo Operational Trust Passport.
- Generate a demo Ambient Evidence Mesh.
- Generate a demo Action Admissibility Ledger entry.
- Generate a demo Context Witness Chain.
- Generate a demo Reviewer Evidence Packet.
- Generate a demo Exception-Only Alert.
- Generate a demo Site Readiness Trust State.
- Show Green, Yellow, Red, Pending, Expired, and Review Required states.
- Show why Platform B remains quiet when trusted.
- Show why Platform B alerts only when operational trust is at risk.
- Show export-ready evidence summaries without using confidential, patient, or GMP batch data.

## Demo data requirements

| Data object | Required in seed file |
|---|---|
| context_witness_events | yes |
| evidence_meshes | yes |
| operational_trust_passports | yes |
| action_admissibility_ledger | yes |
| witness_chains | yes |
| reviewer_evidence_packets | yes |
| exception_only_alerts | yes |
| site_readiness_trust_states | yes |

## Visual design direction

- Dark operational command-center style.
- Clear status cards.
- Evidence relationship tables.
- Reviewer-ready summaries.
- No confidential branding.
- No real facility names.
- No patient data.
- No real GMP batch data.

## v0.6 user story

A user opens the console, selects a scenario, sees the evidence mesh, reviews the operational trust passport, checks the action admissibility ledger, opens the witness chain, reviews the reviewer evidence packet, checks exception-only alerts, and sees the final site readiness trust state.

## Expected demo message

Platform B v0.6 demonstrates that operational trust is portable, reviewable, explainable, and evidence-linked.

## Relationship to v0.6 schemas

- Operational Trust Passport Schema
- Ambient Evidence Mesh Schema
- Action Admissibility Ledger Schema
- Context Witness Chain Schema
- Reviewer Evidence Packet Schema
- Exception-Only Alert Model Schema
- Site Readiness Trust State Schema

## Guardrails

This demo console expansion is for a controlled non-production demonstrator.

It does not support patient use, batch release, shipment release, clinical use, regulatory submission use, validated GMP use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.
