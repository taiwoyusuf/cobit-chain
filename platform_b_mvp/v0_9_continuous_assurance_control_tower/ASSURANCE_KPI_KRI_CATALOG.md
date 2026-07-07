# Assurance KPI and KRI Catalog

## Platform

Platform B v0.9 - Continuous Assurance Control Tower

## Purpose

The Assurance KPI and KRI Catalog defines controlled non-production indicators used by the Continuous Assurance Control Tower.

KPIs show whether assurance operations are performing well.

KRIs show whether assurance risk is increasing.

The catalog converts admissibility decisions, evidence packets, exceptions, reviewer workload, scorecards, governance reviews, and release evidence readiness into measurable assurance signals.

## Core doctrine

Assurance is not a one-time gate. It is a living operational state.

## Catalog question

Which indicators show whether the regulated operation is becoming more trusted, more review-heavy, more exception-heavy, more evidence-ready, or more at risk?

## KPI categories

| KPI category | Purpose |
|---|---|
| admissibility_health | Measures proceed, review_required, stop, expired, and override decision performance |
| evidence_readiness | Measures evidence packet completeness, freshness, export readiness, and archive readiness |
| reviewer_performance | Measures review timeliness, closure throughput, and escalation handling |
| exception_closure | Measures open exception reduction, closure readiness, and recurrence reduction |
| governance_cadence | Measures completion of daily, weekly, monthly, release, and challenge-response reviews |
| control_tower_freshness | Measures whether control tower views are current and synchronized |
| release_evidence_readiness | Measures whether release evidence package index is complete and reviewable |

## KRI categories

| KRI category | Purpose |
|---|---|
| evidence_gap_risk | Tracks missing, stale, expired, conflicting, or insufficient evidence |
| exception_risk | Tracks red, recurring, overdue, and escalated exceptions |
| reviewer_bottleneck_risk | Tracks overdue review, reviewer overload, and blocked review routes |
| override_risk | Tracks frequency and quality of override justifications |
| trend_degradation_risk | Tracks worsening admissibility trends and recurring weak signals |
| governance_overdue_risk | Tracks missed governance reviews and unresolved follow-up actions |
| control_tower_staleness_risk | Tracks stale dashboards, old refresh windows, and outdated evidence views |

## Required catalog fields

| Field | Description |
|---|---|
| indicator_id | Unique KPI or KRI identifier |
| platform_version | Platform B version |
| indicator_type | KPI or KRI |
| indicator_category | Category of indicator |
| indicator_name | Human-readable indicator name |
| indicator_question | Question the indicator answers |
| source_records | Source records used to calculate the indicator |
| numerator_definition | Numerator used in calculation, if applicable |
| denominator_definition | Denominator used in calculation, if applicable |
| calculation_method | count, ratio, percentage, average_age, threshold_check, trend_check, or custom_demo_method |
| observation_window | Time window used for calculation |
| current_value | Current indicator value |
| target_value | Demo target value |
| warning_threshold | Threshold that moves indicator to watch |
| critical_threshold | Threshold that moves indicator to degraded, blocked, or escalated |
| current_state | trusted, watch, review_required, degraded, blocked, escalated, or insufficient_data |
| interpretation | Human-readable meaning of the current value |
| linked_control_tower_refs | Linked control tower records |
| linked_scorecard_refs | Linked scorecard records |
| linked_governance_review_refs | Linked governance review records |
| generated_by | System, user, or demo process that generated the indicator |
| generated_at | Timestamp when indicator was generated |
| guardrail_status | controlled_non_production_demonstrator |

## Example KPI set

| KPI | Meaning | Example target |
|---|---|---|
| Proceed Decision Ratio | Percentage of admissibility decisions that quietly proceed | 80 percent or higher |
| Evidence Packet Export Readiness | Percentage of packets ready for review or export | 85 percent or higher |
| Reviewer Closure Timeliness | Percentage of review items closed within demo window | 90 percent or higher |
| Exception Closure Readiness | Percentage of closure-ready exceptions reviewed | 90 percent or higher |
| Governance Review Completion | Percentage of scheduled governance reviews completed | 95 percent or higher |
| Control Tower Refresh Currency | Percentage of views refreshed within expected window | 95 percent or higher |

## Example KRI set

| KRI | Meaning | Example critical threshold |
|---|---|---|
| Expired Evidence Rate | Percentage of evidence packets with expired evidence | Greater than 10 percent |
| Red Exception Count | Number of red exceptions in observation window | Greater than 0 |
| Overdue Reviewer Count | Number of overdue review items | Greater than 2 |
| Override Frequency | Percentage of actions using human override | Greater than 5 percent |
| Recurring Exception Pattern | Repeated exception across windows | Any recurring red condition |
| Governance Overdue Count | Number of overdue governance reviews | Greater than 0 |

## Example indicator object

```json
{
  "indicator_id": "AKK-DEMO-0001",
  "platform_version": "Platform B v0.9",
  "indicator_type": "KRI",
  "indicator_category": "reviewer_bottleneck_risk",
  "indicator_name": "Overdue Reviewer Count",
  "indicator_question": "How many reviewer actions are overdue in the current observation window?",
  "source_records": ["RWEB-DEMO-0001", "GCRM-DEMO-0001"],
  "numerator_definition": "count_of_overdue_reviewer_items",
  "denominator_definition": "not_applicable",
  "calculation_method": "count",
  "observation_window": "2026-07-06T08:00:00Z/2026-07-06T12:00:00Z",
  "current_value": 1,
  "target_value": 0,
  "warning_threshold": 1,
  "critical_threshold": 3,
  "current_state": "watch",
  "interpretation": "One overdue reviewer action exists and should be reviewed before the control tower can return to quiet trust.",
  "linked_control_tower_refs": ["CACT-DEMO-0001"],
  "linked_scorecard_refs": ["SAS-DEMO-0001"],
  "linked_governance_review_refs": ["GCRM-DEMO-0001"],
  "generated_by": "Platform B v0.9 demo",
  "generated_at": "2026-07-06T12:00:00Z",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Indicator interpretation rules

| State | Meaning |
|---|---|
| trusted | Indicator supports quiet assurance |
| watch | Indicator shows weak signal requiring observation |
| review_required | Indicator requires human review |
| degraded | Indicator shows weakening assurance state |
| blocked | Indicator shows stop or blocking condition |
| escalated | Indicator requires higher-level governance review |
| insufficient_data | Indicator cannot support a conclusion yet |

## Relationship to v0.9 control tower

The Continuous Assurance Control Tower displays operational assurance state.

The KPI and KRI Catalog defines the measurable signals that explain whether the control tower is trusted, watch, review_required, degraded, blocked, or escalated.

## Guardrails

This catalog is for a controlled non-production demonstrator only.

It does not use patient data, real GMP batch data, confidential company information, or regulated production data.

It does not claim validated GMP use, clinical use, patient use, batch release support, shipment release support, regulatory submission use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, quality review, regulatory review, cybersecurity review, legal review, or human approval.
