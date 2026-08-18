# External Corpus Structural Standing R1

Date: 2026-08-17

Status: FIRST-PARTY NON-BINDING CONTRACT / CHALLENGE IMPLEMENTATION

## Purpose

Implement only the materially sharper deltas identified in the newly supplied external architecture corpus, without creating duplicate COBIT-Chain capability families or rewriting frozen historical evidence.

## Difference-first disposition

### Implemented now

1. `STRUCTURAL_OPERATING_ENVELOPE_STANDING`
   - Native home: Operational Fitness / Intended-Use Drift + Probabilistic Standing + Execution-Substrate Standing + VSA.
   - Core distinction: individually acceptable values do not prove that the qualified operating regime itself remains unchanged.
   - Structural/topology change or bifurcation requires requalification.

2. `REPLAY_LEGITIMACY_AND_PROMOTION_STANDING`
   - Native home: Chain Verifiability + SERAPH + Continuing Reliance + Action Admissibility.
   - Core distinctions:
     - `REPLAY_SUCCEEDED != CURRENT_LEGITIMACY_ESTABLISHED`
     - `PROOF_PRESENT != CUSTODY_COMPLETE`
     - `PERSISTENCE != PROMOTION_TO_CONSEQUENCE`

3. `INTERACTING_DECISION_CONDITION_STANDING`
   - Native home: Composed Operational Claim + Shared-Condition / Systemic Network Stability + Action Admissibility.
   - Core distinction: individually valid governed decisions can create an incompatible combined operating condition.
   - `ALL_COMPONENT_DECISIONS_VALID != COMBINED_OPERATING_CONDITION_VALID`

### Not duplicated

- RAG/source authority is not added as a new capability. COBIT-Chain already contains source-system authority implementation and validators. The external `retrieval != authority` formulation is treated as reinforcement/challenge input.
- Automation-bias/human-oversight concepts are not duplicated. Existing Human Oversight Effectiveness / Automation Bias controls already occupy that space.
- Generic runtime action authority, revocation, replay, outcome correspondence, no-bind, and agent tool capability boundaries remain in their existing families.

## No new top-level capability

`NEW_TOP_LEVEL_CAPABILITY = NO`

The prior roadmap ceiling is preserved. This tranche strengthens existing families only.

## Boundaries

- `AUTHORITY = NONE`
- `NO_BIND = TRUE`
- `EXTERNAL_SOURCE_MATERIAL != COBIT_CHAIN_IMPLEMENTATION_EVIDENCE`
- `FIRST_PARTY_CODE_EXISTS != LIVE_OPERATIONAL_ENFORCEMENT`
- `CONTRACT_PASS != GXP_VALIDATED`
- `INTERNAL_IMPLEMENTATION != REGULATORY_ACCEPTANCE`
- No Canonical Audit / frozen R3 artifact is rewritten.

## Verification

The exact first-party evaluator logic was exercised locally before commit against 12 deterministic adversarial cases. Result: `12/12 PASS`.

The committed repository test file preserves those scenarios for repeatable verification. No GitHub CI run is claimed by this document.
