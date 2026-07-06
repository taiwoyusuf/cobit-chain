# Evidence Packet Export Queue Schema

## Platform

Platform B v0.9 - Continuous Assurance Control Tower

## Purpose

The Evidence Packet Export Queue tracks evidence packets that are ready, pending, challenged, archived, or blocked from export in a controlled non-production demonstration.

It supports the Continuous Assurance Control Tower by showing which evidence packets can support review, challenge response, governance cadence, release documentation, and audit-style traceability.

This queue does not submit regulatory content, release batches, replace validated systems, or automate GMP decisions.

## Core doctrine

Assurance is not a one-time gate. It is a living operational state.

## Export queue question

Which evidence packets are ready to be reviewed, exported, challenged, archived, refreshed, or blocked?

## Queue states

| Queue state | Meaning |
|---|---|
| draft | Packet is being assembled |
| pending_review | Packet requires human review before export |
| export_ready | Packet has enough demo evidence for export |
| exported | Packet has been exported in the controlled demo record |
| challenged | Packet has been challenged and requires explanation or supplemental evidence |
| refresh_required | Packet contains stale, expired, missing, or conflicting evidence |
| blocked | Packet cannot be exported under demo rules |
| archived | Packet has been retained for demo recordkeeping |
| retired | Packet no longer applies to active context |

## Required export queue fields

| Field | Description |
|---|---|
| export_queue_id | Unique export queue record identifier |
| platform_version | Platform B version |
| packet_id | Evidence packet identifier |
| packet_type | pre_action, post_action_challenge, exception_closure, governance_review, release_evidence, or custom_demo_packet |
| packet_title | Human-readable packet title |
| source_context | Site, room, workflow, equipment, procedure, action, exception, reviewer, or release context |
| queue_state | draft, pending_review, export_ready, exported, challenged, refresh_required, blocked, archived, or retired |
| evidence_refs | Evidence records included in the packet |
| admissibility_decision_refs | Linked admissibility decision records |
| exception_refs | Linked exceptions affecting the packet |
| reviewer_refs | Linked reviewer route or reviewer decision records |
| scorecard_refs | Linked Site Assurance Scorecard records |
| export_reason | Human-readable reason for export or retention |
| export_block_reason | Reason packet cannot be exported, if blocked |
| challenge_reason | Reason packet was challenged, if challenged |
| refresh_reason | Reason packet requires evidence refresh |
| export_format | markdown, json, csv, pdf_placeholder, html_placeholder, or custom_demo_format |
| export_destination | demo_archive, reviewer_packet, governance_review, release_package, or local_demo_folder |
| requested_by | System, user, reviewer, or demo process requesting export |
| reviewed_by | Reviewer or demo reviewer role |
| created_at | Packet creation timestamp |
| reviewed_at | Review timestamp, if reviewed |
| exported_at | Export timestamp, if exported |
| archived_at | Archive timestamp, if archived |
| guardrail_status | controlled_non_production_demonstrator |

## Export readiness rules

| Condition | Queue state |
|---|---|
| Evidence packet is incomplete | draft |
| Evidence exists but reviewer confirmation is required | pending_review |
| Evidence is complete and no blocking exception exists | export_ready |
| Packet was exported for demo review | exported |
| Packet is questioned after review | challenged |
| Evidence is stale, expired, missing, or conflicting | refresh_required |
| Red exception, stop condition, or missing critical evidence exists | blocked |
| Packet is retained after closure | archived |
| Packet no longer applies | retired |

## Example export queue object

```json
{
  "export_queue_id": "EPEQ-DEMO-0001",
  "platform_version": "Platform B v0.9",
  "packet_id": "EPP-DEMO-0001",
  "packet_type": "governance_review",
  "packet_title": "Demo Cleanroom Assurance Review Packet",
  "source_context": "Demo Cleanroom Area",
  "queue_state": "pending_review",
  "evidence_refs": ["EV-DEMO-0001", "EV-DEMO-0002", "EV-DEMO-0003"],
  "admissibility_decision_refs": ["ADR-DEMO-0001"],
  "exception_refs": ["EXC-DEMO-0001"],
  "reviewer_refs": ["HRR-DEMO-0001"],
  "scorecard_refs": ["SAS-DEMO-0001"],
  "export_reason": "Support demo governance review of current assurance state.",
  "export_block_reason": "not_applicable",
  "challenge_reason": "not_applicable",
  "refresh_reason": "Reviewer confirmation is required before export.",
  "export_format": "markdown",
  "export_destination": "governance_review",
  "requested_by": "Platform B v0.9 demo",
  "reviewed_by": "demo_reviewer",
  "created_at": "2026-07-06T12:00:00Z",
  "reviewed_at": null,
  "exported_at": null,
  "archived_at": null,
  "guardrail_status": "controlled_non_production_demonstrator"
}
```

## Relationship to v0.9 control tower

The Continuous Assurance Control Tower shows the governance view.

The Evidence Packet Export Queue shows which evidence packets are ready for review, export, challenge response, archive, or refresh.

The Site Assurance Scorecard and Exception Control Room can reference this queue to explain whether the site has enough evidence to support its current trust state.

## Guardrails

This schema is for a controlled non-production demonstrator only.

It does not use patient data, real GMP batch data, confidential company information, or regulated production data.

It does not claim validated GMP use, clinical use, patient use, batch release support, shipment release support, regulatory submission use, autonomous execution, or production compliance.

It does not replace QMS, MES, LIMS, EMS, Lasair, validated systems, quality review, regulatory review, cybersecurity review, legal review, or human approval.
