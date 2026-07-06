# Site Assurance Scorecard Model

## Platform

Platform B v0.9 - Continuous Assurance Control Tower

## Purpose

The Site Assurance Scorecard converts continuous assurance signals into a readable site-level scorecard for controlled non-production demonstration.

It summarizes operational trust state, admissibility trends, evidence readiness, exception posture, reviewer load, governance cadence, and release evidence readiness.

The scorecard is not a validated GMP score, not a release decision, and not a replacement for QMS, MES, LIMS, EMS, Lasair, validated systems, or human review.

## Core doctrine

Assurance is not a one-time gate. It is a living operational state.

## Scorecard question

How trustworthy is the regulated operation right now, and what evidence explains that trust state?

## Scorecard dimensions

| Dimension | Meaning |
|---|---|
| operational_trust_state | Current trust state from the Operational Trust State Aggregator |
| admissibility_health | Pattern of proceed, review_required, stop, expired, and overridden decisions |
| evidence_readiness | Availability, freshness, traceability, and export readiness of evidence packets |
| exception_posture | Open, yellow, red, expired, escalated, recurring, and closed exception state |
| reviewer_load | Reviewer queue, overdue decisions, escalations, and closure latency |
| environment_assurance | Environmental witness state, stale signals, warnings, and missing evidence |
| passport_freshness | Current, stale, expired, blocked, and refreshed passport state |
| governance_cadence | Review cadence status, overdue governance actions, and release readiness |

## Score scale

| Score band | Assurance meaning |
|---|---|
| 90-100 | trusted |
| 75-89 | watch |
| 60-74 | review_required |
| 40-59 | degraded |
| 1-39 | blocked |
| 0 | insufficient_evidence |

## Required scorecard fields

| Field | Description |
|---|---|
| scorecard_id | Unique scorecard identifier |
| platform_version | Platform B version |
| site_context | Demo site, area, suite, room, cleanroom, or workflow context |
| observation_window_start | Start timestamp for scorecard window |
| observation_window_end | End timestamp for scorecard window |
| overall_assurance_score | Demo assurance score from 0 to 100 |
| overall_assurance_state | trusted, watch, review_required, degraded, blocked, insufficient_evidence, or retired |
| operational_trust_state_score | Score for operational trust state |
| admissibility_health_score | Score for admissibility decision pattern |
| evidence_readiness_score | Score for evidence packet state |
| exception_posture_score | Score for exception posture |
| reviewer_load_score | Score for reviewer queue and escalation load |
| environment_assurance_score | Score for environmental witness state |
| passport_freshness_score | Score for passport freshness |
| governance_cadence_score | Score for governance review cadence |
| top_trust_drivers | Factors improving the assurance score |
| top_risk_drivers | Factors lowering the assurance score |
| recommended_review_actions | Human-readable review actions for demo governance |
| linked_aggregator_refs | References to Operational Trust State Aggregator records |
| linked_exception_refs | References to exceptions affecting scorecard state |
| linked_evidence_packet_refs | References to evidence packets supporting the scorecard |
| generated_by | System, user, or demo process that generated the scorecard |
| generated_at | Timestamp when scorecard was generated |
| guardrail_status | controlled_non_production_demonstrator |

## Example scorecard object

```json
{
  "scorecard_id": "SAS-DEMO-0001",
  "platform_version": "Platform B v0.9",
  "site_context": "Demo Cleanroom Area",
  "observation_window_start": "2026-07-06T08:00:00Z",
  "observation_window_end": "2026-07-06T12:00:00Z",
  "overall_assurance_score": 82,
  "overall_assurance_state": "watch",
  "operational_trust_state_score": 84,
  "admissibility_health_score": 86,
  "evidence_readiness_score": 78,
  "exception_posture_score": 74,
  "reviewer_load_score": 70,
  "environment_assurance_score": 88,
  "passport_freshness_score": 81,
  "governance_cadence_score": 83,
  "top_trust_drivers": [
    "Most admissibility decisions are proceed",
    "Environmental witnesses are mostly current",
    "Evidence packets are available for review"
  ],
  "top_risk_drivers": [
    "One expired evidence condition",
    "Reviewer queue contains one overdue item",
    "Two yellow exceptions remain open"
  ],
  "recommended_review_actions": [
    "Review overdue reviewer item",
    "Close or escalate yellow exceptions",
    "Refresh expired evidence packet"
  ],
  "linked_aggregator_refs": ["OTSA-DEMO-0001"],
  "linked_exception_refs": ["EXC-DEMO-0001", "EXC-DEMO-0002"],
  "linked_evidence_packet_refs": ["EPP-DEMO-0001", "EPP-DEMO-0002"],
  "generated_by": "Platform B v0.9 demo",
  "generated_at": "2026-07-06T12:00:00Z",
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Score interpretation

| Score result | Control tower interpretation |
|---|---|
| trusted | Continue quiet observation and retain evidence |
| watch | Continue operation but monitor weak signals |
| review_required | Route scorecard to human reviewer |
| degraded | Escalate for evidence refresh or exception closure |
| blocked | Stop or prevent action under demo rules |
| insufficient_evidence | Do not infer trust; request more evidence |

## Relationship to v0.9 control tower

The Continuous Assurance Control Tower displays the site-level control view.

The Operational Trust State Aggregator computes the current trust state.

The Site Assurance Scorecard converts that trust state into a scorecard that explains site health, risk drivers, review actions, and evidence support.

## Guardrails

This model is for a controlled non-production demonstrator only.

It does not use patient data, real GMP batch data, confidential company information, or regulated production data.

It does not claim validated GMP use, clinical use, patient use, batch release support, shipment release support, regulatory submission use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, quality review, regulatory review, cybersecurity review, legal review, or human approval.
