# COBIT-Chain™ Three-Person Integrated Refinement Contract R3 — 14 August 2026

Status: `ROADMAP / CHALLENGE-CONTRACT LAYER ONLY`

This contract reconciles the accepted deltas associated with Greggory Don Butler, Greg Malpass, and Ravi Shankar NRK into existing COBIT-Chain architecture without creating a ninth integrated family or Capability #78.

## Control boundary

- Frozen Canonical Audit R3-E05: `UNCHANGED`.
- R3-E05 runtime acceptance: `NOT_ESTABLISHED`.
- R3-E06: `NOT_AUTHORIZED`.
- Shared-engine implementation from this contract: `NOT_AUTHORIZED`.
- External publications: `NOT_IMPLEMENTATION_EVIDENCE`.

## Contract 1 — Revocation Effectiveness

Preserve a measurable distinction between revocation decision, propagation, credential/authority invalidation, and actual protected-surface rejection.

Invariant:

`REVOCATION_REQUESTED != REVOCATION_EFFECTIVE`

`CONTROL_PLANE_REVOKED != CAPABILITY_UNAVAILABLE_AT_ALL_EXECUTION_SURFACES`

Minimum evidence includes decision time, signal issue/receive time, invalidation time, last accepted action, first rejected action, affected surfaces, unresolved surfaces, and consequence reconciliation state.

## Contract 2 — Delegation Scope Monotonicity

Invariant:

`DELEGATED_AUTHORITY_CHILD ⊆ EFFECTIVE_AUTHORITY_PARENT`

unless an independently valid and separately attributable authority source explicitly grants additional scope.

Handoff must not silently expand authority.

## Contract 3 — Independent Mechanical / Out-of-Band Restraint

A restraint path must remain outside the governed agent's discretionary authority to reinterpret, suppress, or override it.

Invariant:

`REVOCATION_INSTRUCTION_PRESENT != INDEPENDENT_REVOCATION_ENFORCEMENT_PRESENT`

This is an authority-boundary requirement; it does not require a physically separate network in every implementation.

## Contract 4 — Graduated Containment

Containment must support consequence-sensitive levels rather than only binary shutdown.

Candidate levels:

- NORMAL
- RATE_LIMITED
- SENSITIVE_ACTIONS_BLOCKED
- READ_ONLY
- FULL_CONTAINMENT
- ISOLATED_PENDING_REVIEW

Invariant:

`AGENT_STATE_CONTAINED != CONSEQUENCE_SURFACE_ACTUALLY_CONTAINED`

## Contract 5 — Assumption / Basis Standing

Rules, controls, validation states, and authorities may remain syntactically current while their real-world assumptions have degraded.

Invariant:

`CONTROL_OPERATES_AS_DESIGNED != CONTROL_STILL_GOVERNS_THE_RIGHT_WORLD`

`RULE_CURRENT != JUSTIFYING_ASSUMPTION_CURRENT`

`NO_TRIGGER_FIRED != ASSUMPTION_STILL_VALID`

## Contract 6 — Memory Revocation Effectiveness & Descendant Invalidation

Revocation must traverse canonical memory, replicas, caches, embeddings, retrieval indexes, summaries, agent-local state, derived claims, decisions, committed objects, and downstream reliance where applicable.

Invariant:

`CANONICAL_MEMORY_REVOKED != MEMORY_REVOCATION_EFFECTIVE`

`MEMORY_REVOKED != DERIVED_CLAIMS_AUTOMATICALLY_INVALIDATED`

## Contract 7 — Epistemic Independence

A human reviewer is not meaningfully independent merely because a human is present, authorized, or timely. The reviewer must be able to independently inspect material source evidence, provenance, uncertainty, contradiction, transformations, criteria, authority basis, and consequence alternatives.

Invariant:

`HUMAN_REVIEW_OCCURRED != HUMAN_COULD_INDEPENDENTLY_EVALUATE_THE_BASIS`

## Contract 8 — Trigger Evidence vs Continuing Standing

A requalification or reassessment trigger does not itself prove standing loss, and absence of a trigger does not prove current standing.

Invariant:

`REQUALIFICATION_TRIGGERED != AUTHORITY_INVALID != VALIDATION_STANDING_LOST != ACTION_DENIED`

`NO_TRIGGER_DETECTED != STANDING_CURRENT`

## Contract 9 — Post-Revocation Consequence Reconciliation

Stopping future authority does not automatically undo consequences already created.

Invariant:

`REVOCATION_EFFECTIVE != CONSEQUENCES_RECONCILED`

`STATE_REVERSED != CONSEQUENCE_REVERSED != RELIANCE_REVERSED != STANDING_RESTORED`

Required future dispositions may include UNAFFECTED, REVIEW_REQUIRED, QUARANTINED, ROLLBACK_CANDIDATE, RECONCILIATION_REQUIRED, REVALIDATION_REQUIRED, IRREVERSIBLE_CONSEQUENCE, and HUMAN_DISPOSITION_REQUIRED.

## Integrated route

`REALITY / SOURCE QUALIFICATION`
→ `RULE / CRITERIA / BASIS / ASSUMPTION STANDING`
→ `PERSISTENT MEMORY / AGENT STATE STANDING`
→ `PRE-INFERENCE CONTEXT ADMISSIBILITY`
→ `EVIDENCE-TO-CLAIM RELIANCE`
→ `RUNTIME AUTHORITY / DELEGATION SCOPE`
→ `DECISION-T0`
→ `CONTINUITY`
→ `BIND-T2`
→ `REVOCATION / RESTRAINT EFFECTIVENESS`
→ `ACTION ADMISSIBILITY`
→ `ATOMIC COMMIT`
→ `EXECUTION`
→ `OUTCOME`
→ `POST-REVOCATION / POST-OUTCOME CONSEQUENCE RECONCILIATION`
→ `RESIDENCY / CONTINUING RELIANCE`
→ `RECOVERY / RE-CLOSURE`
→ `FUTURE REQUALIFICATION`

Cross-cutting requirements:

- governance-determination meta-assurance;
- independent epistemic reviewability;
- independent route reconstruction;
- non-resettable route burden / duty horizon;
- memory and authority descendant propagation;
- supplier / sovereignty dependency assurance.

## Implementation gate

Before coding any contract, authoritative current first-party repository evidence must classify it as one of:

- `ALREADY_COVERED`
- `PRESENT_NOT_WIRED`
- `PARTIAL`
- `COMPATIBLE_EXTENSION`
- `ROADMAP_ONLY`
- `CONFLICTING_AUTHORITY`

No implementation status is inferred from this contract.

`CAPABILITY_78 = NOT_JUSTIFIED`

`NEW_TOP_LEVEL_FAMILY = NO`

`IMPLEMENTATION_STATUS_CHANGE = NONE`
