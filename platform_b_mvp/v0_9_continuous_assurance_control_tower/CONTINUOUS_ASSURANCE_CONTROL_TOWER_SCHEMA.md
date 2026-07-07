# Continuous Assurance Control Tower Schema

## Platform

Platform B v0.9 - Continuous Assurance Control Tower

## Purpose

The Continuous Assurance Control Tower is the v0.9 layer that aggregates operational trust state across regulated actions, rooms, equipment, people, procedures, environmental context, exceptions, evidence packets, reviewer decisions, and governance cadence.

It does not replace validated systems, quality systems, or human review.

It provides a controlled non-production demonstrator model for showing how a regulated site can become continuously trust-aware.

## Core doctrine

Assurance is not a one-time gate. It is a living operational state.

## Control tower question

Is the regulated operation continuously trustworthy, based on the current and recent state of evidence, exceptions, admissibility decisions, reviewers, and operational context?

## Carry-forward doctrines

- The device senses. Platform B assures.
- The future regulated site will not only be monitored. It will be assurance-sensed.
- A regulated action is not trusted because one signal is green. It is trusted when the evidence mesh agrees.
- The environment is part of the evidence.
- Quiet when trusted. Alert when trust is at risk. Evidence when action is challenged.

## Control tower layers

| Layer | Purpose |
|---|---|
| operational_trust_state | Shows current trust state across site, area, room, equipment, procedure, person, and action context |
| admissibility_trend | Tracks proceed, review_required, stop, expired, overridden, and not_applicable decision patterns |
| exception_control_room | Tracks open, yellow, red, expired, escalated, closed, and recurring exceptions |
| evidence_packet_queue | Tracks evidence packets ready for review, export, challenge, or archive |
| reviewer_workload | Tracks pending reviewer actions, escalation load, decision latency, and closure backlog |
| governance_cadence | Tracks daily, weekly, monthly, and release-level assurance review cadence |
| assurance_kpi_kri | Tracks assurance health indicators, risk indicators, and readiness signals |
| release_evidence_index | Tracks what evidence supports a release, milestone, demo, or governance review |

## Required control tower fields

| Field | Description |
|---|---|
| control_tower_id | Unique control tower record identifier |
| control_tower_name | Human-readable name |
| platform_version | Platform B version |
| site_context | Demo site, area, cleanroom, suite, workflow, or operational context |
| observation_window_start | Start of the assurance observation window |
| observation_window_end | End of the assurance observation window |
| current_trust_state | trusted, watch, review_required, degraded, blocked, expired, or retired |
| current_assurance_score | Demo assurance score for the observation window |
| admissibility_decision_summary | Summary of action admissibility decisions in the window |
| exception_summary | Summary of active and recently closed exceptions |
| evidence_packet_summary | Summary of packets created, pending, exported, challenged, or archived |
| reviewer_workload_summary | Summary of reviewer queue, overdue items, and escalations |
| kpi_kri_summary | Summary of assurance KPIs and KRIs |
| governance_review_status | pending, current, overdue, escalated, or closed |
| release_evidence_refs | References to evidence packages supporting release or governance review |
| last_runtime_refresh_at | Timestamp of last runtime refresh |
| generated_by | System, user, or demo process that generated the record |
| guardrail_status | controlled_non_production_demonstrator |

## Trust state model

| Trust state | Meaning |
|---|---|
| trusted | Evidence, admissibility, exception, and reviewer states support quiet operation |
| watch | No immediate stop condition exists, but a weak signal requires observation |
| review_required | Human review is required before confidence can be restored |
| degraded | Assurance state is weakened by missing, stale, conflicting, or unresolved evidence |
| blocked | One or more conditions prevent action or require stop state |
| expired | Evidence or time window is no longer current |
| retired | Control tower context is no longer active |

## Example control tower object

```json
{
  "control_tower_id": "CACT-DEMO-0001",
  "control_tower_name": "Demo Cleanroom Continuous Assurance Control Tower",
  "platform_version": "Platform B v0.9",
  "site_context": "Demo Cleanroom Area",
  "observation_window_start": "2026-07-06T08:00:00Z",
  "observation_window_end": "2026-07-06T12:00:00Z",
  "current_trust_state": "review_required",
  "current_assurance_score": 82,
  "admissibility_decision_summary": {
    "proceed": 14,
    "review_required": 3,
    "stop": 1,
    "expired": 1,
    "overridden": 0
  },
  "exception_summary": {
    "open": 2,
    "yellow": 2,
    "red": 0,
    "expired": 1,
    "closed": 5
  },
  "evidence_packet_summary": {
    "created": 9,
    "pending_review": 2,
    "export_ready": 4,
    "challenged": 1,
    "archived": 3
  },
  "reviewer_workload_summary": {
    "pending": 3,
    "overdue": 1,
    "escalated": 1
  },
  "governance_review_status": "pending",
  "release_evidence_refs": ["REP-DEMO-0001"],
  "last_runtime_refresh_at": "2026-07-06T12:00:00Z",
  "generated_by": "Platform B v0.9 demo",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Relationship to v0.8

v0.8 determines whether a regulated action is admissible.

v0.9 observes many admissibility decisions over time and converts them into a continuous assurance state for site governance.

## Guardrails

This schema is for a controlled non-production demonstrator only.

It does not use patient data, real GMP batch data, confidential company information, or regulated production data.

It does not claim validated GMP use, clinical use, patient use, batch release support, shipment release support, regulatory submission use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, quality review, regulatory review, cybersecurity review, legal review, or human approval.
