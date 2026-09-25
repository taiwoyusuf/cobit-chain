# Accountability Continuity Standing R1 — Research Lane

## Status

`RESEARCH_CANDIDATE / NOT_CANONICAL / NOT_FROZEN / NOT_MERGED`

## Research question

Can accountable ownership for a declared consequence scope remain identifiable,
current, accepted, evidenced, and continuous across organizational, system,
vendor, or agent handoffs without being confused with responsibility, authority,
or capability?

## Core distinctions

- `RESPONSIBILITY != ACCOUNTABILITY`
- `ACCOUNTABILITY != AUTHORITY`
- `AUTHORITY != CAPABILITY`
- `SHARED_RESPONSIBILITY != ACCOUNTABILITY_DILUTION`
- `ACTION_TRACEABILITY != ACCOUNTABILITY_TRACEABILITY`

## Proposed continuity invariant

`ACCOUNTABILITY_HANDOFF -> IDENTIFIED_SUCCESSOR + ACCEPTED_SCOPE + CURRENT_MANDATE + PRESERVED_OBLIGATIONS + TRACEABLE_TRANSFER`

A positive accountability result remains non-binding and requires separate current
Authority Standing and Action Admissibility before any new consequence-producing
action.

## Why this is a research lane

The repository already contains substantial RACI, decision-rights, ownership,
handoff, release, stop-use, rollback, monitoring, and escalation controls. This
research lane does not create another RACI engine. It tests whether there is a
materially distinct assurance property: continuity of accountable ownership across
seams where responsibility may be distributed and execution may cross teams,
systems, vendors, agents, or shifts.

## External challenge signal

The Sept. 2026 public AI-governance discussion supplied a challenge signal around
shared responsibility, explicit accountability, decision rights, execution-time
governance, and accountability gaps between organizational seams.

Provenance rules:

- `EXTERNAL_CHALLENGE_SIGNAL != COBIT_CHAIN_IMPLEMENTATION_EVIDENCE`
- `CONCEPTUAL_SIMILARITY != DERIVATION`
- `CHRONOLOGY != DERIVATION != AUTHORSHIP != OWNERSHIP`

The evaluator and test contract in this lane are COBIT-Chain research artifacts.

## Non-authority boundary

Every result preserves:

- `binding_authority_granted = False`
- `physical_action_executed_by_evaluator = False`
- `regulated_release_or_disposition_authorized = False`
- `accountability_manufactured_by_evaluator = False`
- `irlt_mag_state_changed = False`

## Initial adversarial coverage

The R1 research suite challenges:

- many responsible parties with no accountable owner;
- unresolvable or unnamed accountable owner;
- undefined consequence scope;
- stale mandate or unaccepted accountability;
- orphaned or ambiguous accountability;
- conflicting accountability claims;
- material change after assignment without revalidation;
- handoff without successor identification/acceptance;
- handoff with scope or obligation loss;
- untraceable transfer;
- predecessor scope not dispositioned;
- mismatch between current owner and handoff successor;
- execution traceability without accountability traceability;
- stale or incomplete accountability evidence;
- strict non-authority/no-bind behavior.

## Promotion rule

Do not assign a canonical Step number solely because this research lane exists.
Canonical promotion requires:

1. material distinctness from existing RACI, authority, handoff, and ownership controls;
2. adversarial test success;
3. static review for fail-open conditions and duplicated semantics;
4. explicit architecture-placement decision;
5. separate governed promotion/freeze decision.

## Protected boundaries

This lane must not modify:

- frozen Step 184 R1;
- frozen Step 184 R2;
- PR #95;
- PR #96;
- PR #97;
- PR #98;
- IRLT-MAG controlled-stop state.
