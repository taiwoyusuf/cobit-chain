# Admissibility Decision Trend Model

## Platform

Platform B v0.9 - Continuous Assurance Control Tower

## Purpose

The Admissibility Decision Trend Model tracks patterns across regulated action decisions over time.

It converts individual v0.8 admissibility decisions into trend signals that help the v0.9 Continuous Assurance Control Tower understand whether the operation is becoming more trusted, stable, noisy, degraded, blocked, or review-heavy.

This model is not a validated GMP decision tool and does not replace human review, QMS, MES, LIMS, EMS, Lasair, or any validated system.

## Core doctrine

Assurance is not a one-time gate. It is a living operational state.

## Trend question

Are admissibility decisions improving, degrading, repeating, clustering, escalating, or showing a pattern that requires governance attention?

## Decision types tracked

| Decision type | Meaning |
|---|---|
| proceed | Evidence supports the action under demo rules |
| review_required | Action requires human review before confidence is restored |
| stop | Action should not proceed under demo rules |
| expired | Evidence or time window is no longer current |
| overridden | Human override was recorded with justification |
| not_applicable | Action does not require an admissibility decision in the current context |

## Trend dimensions

| Trend dimension | Purpose |
|---|---|
| decision_volume | Counts total decisions in the observation window |
| proceed_ratio | Measures percentage of decisions that quietly proceeded |
| review_ratio | Measures how often human review is required |
| stop_ratio | Measures stop or blocked action frequency |
| expired_ratio | Measures evidence or time-window expiry frequency |
| override_ratio | Measures override frequency and governance risk |
| repeat_review_patterns | Identifies repeated review-required conditions |
| recurring_stop_patterns | Identifies repeated stop conditions by room, equipment, procedure, person, environment, or time window |
| reviewer_latency_pattern | Identifies whether review decisions are becoming slower or overdue |
| evidence_failure_pattern | Identifies recurring missing, stale, conflicting, or insufficient evidence |

## Required trend fields

| Field | Description |
|---|---|
| trend_id | Unique trend record identifier |
| platform_version | Platform B version |
| trend_scope | site, room, workflow, equipment_group, procedure_set, action_family, reviewer_queue, or custom_demo_scope |
| scope_reference | Identifier for the trend scope |
| observation_window_start | Start timestamp for trend observation |
| observation_window_end | End timestamp for trend observation |
| decision_record_refs | References to admissibility decision records included in the trend |
| total_decisions | Total number of decisions in the window |
| proceed_count | Count of proceed decisions |
| review_required_count | Count of review_required decisions |
| stop_count | Count of stop decisions |
| expired_count | Count of expired decisions |
| overridden_count | Count of overridden decisions |
| not_applicable_count | Count of not_applicable decisions |
| trend_direction | improving, stable, watch, degrading, blocked, or insufficient_data |
| trend_signal | quiet, noisy, review_heavy, exception_heavy, expiry_heavy, override_heavy, blocked, or mixed |
| top_pattern_drivers | Main factors driving the trend |
| recurring_context_refs | Rooms, equipment, procedures, people, environment signals, or time windows recurring in trend |
| recommended_control_tower_action | monitor, review, escalate, refresh_evidence, close_exception, reduce_noise, or stop_demo_flow |
| confidence_level | high, medium, low, insufficient, or not_applicable |
| generated_by | System, user, or demo process that generated the trend record |
| generated_at | Timestamp when trend record was generated |
| guardrail_status | controlled_non_production_demonstrator |

## Trend interpretation rules

| Condition | Trend direction | Control tower meaning |
|---|---|---|
| Proceed ratio is high and exceptions are low | improving | Operation is becoming quieter and more trusted |
| Proceed ratio is stable and review load is manageable | stable | Operation remains under control |
| Review-required decisions are rising | watch | Weak signals require observation |
| Evidence failures or expired decisions are rising | degrading | Assurance state is weakening |
| Stop decisions or red exceptions are recurring | blocked | Control tower should escalate or stop demo flow |
| Override rate is rising | degrading | Governance attention is needed |
| Too few decisions exist | insufficient_data | Do not infer trend yet |

## Example trend object

```json
{
  "trend_id": "ADTM-DEMO-0001",
  "platform_version": "Platform B v0.9",
  "trend_scope": "room",
  "scope_reference": "ROOM-DEMO-CLEANROOM-001",
  "observation_window_start": "2026-07-06T08:00:00Z",
  "observation_window_end": "2026-07-06T12:00:00Z",
  "decision_record_refs": ["ADR-DEMO-0001", "ADR-DEMO-0002", "ADR-DEMO-0003"],
  "total_decisions": 19,
  "proceed_count": 14,
  "review_required_count": 3,
  "stop_count": 1,
  "expired_count": 1,
  "overridden_count": 0,
  "not_applicable_count": 0,
  "trend_direction": "watch",
  "trend_signal": "review_heavy",
  "top_pattern_drivers": [
    "Two repeated review-required decisions linked to room readiness",
    "One expired evidence condition linked to time window",
    "One stop decision linked to missing equipment evidence"
  ],
  "recurring_context_refs": [
    "ROOM-DEMO-CLEANROOM-001",
    "EQP-DEMO-SPEEDYGLOVE-001",
    "TIME-DEMO-WINDOW-001"
  ],
  "recommended_control_tower_action": "review",
  "confidence_level": "medium",
  "generated_by": "Platform B v0.9 demo",
  "generated_at": "2026-07-06T12:00:00Z",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Relationship to v0.8 and v0.9

v0.8 records whether a regulated action is admissible.

v0.9 observes those decisions over time and identifies patterns that affect continuous assurance.

The Site Assurance Scorecard can use this model to explain why a site is trusted, under watch, review-heavy, degraded, or blocked.

## Guardrails

This model is for a controlled non-production demonstrator only.

It does not use patient data, real GMP batch data, confidential company information, or regulated production data.

It does not claim validated GMP use, clinical use, patient use, batch release support, shipment release support, regulatory submission use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, quality review, regulatory review, cybersecurity review, legal review, or human approval.
