# Operational Trust State Aggregator Schema

## Platform

Platform B v0.9 - Continuous Assurance Control Tower

## Purpose

The Operational Trust State Aggregator converts many runtime signals into one current operational trust state for a site, room, workflow, equipment group, procedure set, or action family.

It aggregates admissibility decisions, exception states, evidence packet status, reviewer decisions, environmental context, passport freshness, and governance cadence into a control tower trust state.

## Core doctrine

Assurance is not a one-time gate. It is a living operational state.

## Aggregator question

What is the current trust state of the regulated operation after combining recent evidence, exceptions, admissibility decisions, reviewer activity, and context changes?

## Input signal families

| Signal family | Examples |
|---|---|
| admissibility_decisions | proceed, review_required, stop, expired, overridden, not_applicable |
| exception_states | none, informational, yellow, red, expired, escalated, closed |
| evidence_packets | created, pending_review, export_ready, challenged, archived |
| reviewer_actions | approved, rejected, requested_more_evidence, escalated, closed |
| site_readiness | trusted, partial, review_required, blocked, retired |
| passport_freshness | current, stale, expired, blocked, refreshed |
| environmental_context | within_demo_limits, warning, excursion, stale, missing |
| governance_cadence | current, due, overdue, escalated, closed |

## Aggregated trust states

| Trust state | Meaning |
|---|---|
| trusted | Current evidence supports quiet operation |
| watch | Weak signal exists but no immediate review or stop state exists |
| review_required | Human review is required before confidence is restored |
| degraded | Operation is weakened by stale, missing, conflicting, or unresolved evidence |
| blocked | One or more conditions prevent action from proceeding |
| expired | Evidence, passport, or time-window condition has expired |
| escalated | Higher-level review is required |
| retired | Operational context is no longer active |

## Required aggregator fields

| Field | Description |
|---|---|
| aggregator_id | Unique aggregator record identifier |
| platform_version | Platform B version |
| aggregation_scope | site, room, workflow, equipment_group, procedure_set, action_family, or custom_demo_scope |
| scope_reference | Identifier for the site, room, workflow, equipment, procedure, or action family being aggregated |
| observation_window_start | Start timestamp for aggregation window |
| observation_window_end | End timestamp for aggregation window |
| input_signal_refs | References to input signals used in aggregation |
| admissibility_summary | Summary of admissibility decision counts and states |
| exception_summary | Summary of active and recently closed exception states |
| evidence_packet_summary | Summary of evidence packet readiness and challenge state |
| reviewer_summary | Summary of reviewer queue, decision status, and escalation status |
| passport_summary | Summary of passport freshness and expiry state |
| environment_summary | Summary of environmental evidence status |
| governance_summary | Summary of governance cadence status |
| computed_trust_state | trusted, watch, review_required, degraded, blocked, expired, escalated, or retired |
| trust_state_reason | Human-readable reason for computed trust state |
| confidence_level | high, medium, low, insufficient, or not_applicable |
| refresh_frequency | manual, event_driven, hourly_demo, daily_demo, or release_demo |
| last_refreshed_at | Timestamp when aggregation was last refreshed |
| generated_by | System, user, or demo process that generated the record |
| guardrail_status | controlled_non_production_demonstrator |

## Aggregation rules

| Condition | Aggregated trust state |
|---|---|
| All critical signals are current and no exception is open | trusted |
| Minor weak signal exists but no review is required | watch |
| Evidence exists but qualified review is pending | review_required |
| Evidence is stale, incomplete, or conflicting | degraded |
| Red exception, stop decision, or blocking evidence exists | blocked |
| Evidence packet, passport, or time window expired | expired |
| Review is overdue or unresolved risk requires higher review | escalated |
| Scope is no longer active | retired |

## Example aggregator object

```json
{
  "aggregator_id": "OTSA-DEMO-0001",
  "platform_version": "Platform B v0.9",
  "aggregation_scope": "room",
  "scope_reference": "ROOM-DEMO-CLEANROOM-001",
  "observation_window_start": "2026-07-06T08:00:00Z",
  "observation_window_end": "2026-07-06T12:00:00Z",
  "input_signal_refs": ["ADR-DEMO-0001", "EXC-DEMO-0001", "EPP-DEMO-0001", "HRR-DEMO-0001"],
  "admissibility_summary": {
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
    "pending_review": 2,
    "export_ready": 4,
    "challenged": 1
  },
  "reviewer_summary": {
    "pending": 3,
    "overdue": 1,
    "escalated": 1
  },
  "passport_summary": {
    "current": 8,
    "stale": 1,
    "expired": 1
  },
  "environment_summary": {
    "within_demo_limits": 6,
    "warning": 1,
    "missing": 0
  },
  "governance_summary": {
    "status": "pending",
    "next_review_due": "2026-07-07T12:00:00Z"
  },
  "computed_trust_state": "review_required",
  "trust_state_reason": "Current operation is not blocked, but reviewer queue and one expired evidence condition require review before quiet trust is restored.",
  "confidence_level": "medium",
  "refresh_frequency": "event_driven",
  "last_refreshed_at": "2026-07-06T12:00:00Z",
  "generated_by": "Platform B v0.9 demo",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Relationship to the control tower

The Continuous Assurance Control Tower displays the site-level view.

The Operational Trust State Aggregator computes the trust state that feeds that view.

## Guardrails

This schema is for a controlled non-production demonstrator only.

It does not use patient data, real GMP batch data, confidential company information, or regulated production data.

It does not claim validated GMP use, clinical use, patient use, batch release support, shipment release support, regulatory submission use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, quality review, regulatory review, cybersecurity review, legal review, or human approval.
