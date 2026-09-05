# Residual-Consequence R1 Challenge Suite

Status: `RESEARCH_BOUNDED_CHALLENGE_SUITE`

## Purpose

This package adversarially challenges residual-consequence assurance across four bounded controls without creating a new authority, execution, disposition, release, radiation-safety, clinical, compounding, or IRLT-MAG control engine.

The central proposition is:

> Historical permission, historical evidence, or historical success does not establish that a consequence remains governable now.

The suite tests whether the architecture preserves uncertainty, contradiction, revocation, residual effects, and current-world correspondence through the consequence boundary.

## Four controls under challenge

1. **Proposition-Bound Witness Standing**
   - A witness may support only the proposition it was qualified to observe.
   - Sensor health, authentication, timestamp correctness, or generic witness presence must not be silently promoted into evidence for a different proposition.

2. **Observability / Negative-Evidence Boundary**
   - `NOT_OBSERVED`, `NOT_DETECTED`, missing telemetry, unavailable evidence service, or insufficient detection capability must not be converted into `ABSENT` or `NO_CONTRADICTION`.
   - Negative conclusions require established opportunity and capability to observe the relevant proposition.

3. **Contradiction + Failure-Domain Independence**
   - Conflicting evidence must remain visible and must not be averaged away into false confidence.
   - Apparent corroboration from channels that share a material dependency must not be treated as independent corroboration.
   - A contradiction service failure must not be represented as a clean contradiction result.

4. **Physical Outcome Correspondence / Re-closure**
   - Permission, commit, execution, and outcome remain distinct propositions.
   - A successful execution receipt does not establish the intended physical outcome.
   - Recovery does not erase the disturbed historical event.
   - Return to reliance requires current-world correspondence, current criteria, current evidence, current authority, closure of blocking residual obligations, and independent re-verification where required.

## Existing controls reused, not reimplemented

This package is intentionally a research challenge layer over existing controls, including:

- Step 176 Physical Evidence Standing;
- Step 180 Execution-Time Revalidation;
- Step 182 Commit / Execution / Outcome Correspondence; and
- Step 183 Recovery / Re-closure / Return-to-Reliance Standing.

Those shared controls remain authoritative for their respective semantics. This package exists to pressure-test cross-control composition and failure handling.

## Architectural invariants

- `AUTHORITY = NONE`
- `NO_BIND = TRUE`
- `HISTORICAL_PERMISSION != CURRENT_STANDING`
- `CAPABILITY != AUTHORITY`
- `NOT_OBSERVED != ABSENT`
- `NOT_DETECTED != ABSENT`
- `EVIDENCE_SERVICE_UNAVAILABLE != NO_CONTRADICTION_FOUND`
- `EXECUTION_SUCCESS != INTENDED_OUTCOME_ESTABLISHED`
- `RECOVERY != RECLOSURE`
- `RECLOSURE != RETURN_TO_RELIANCE`
- Shared failure domains must remain explicit.
- Contradictions must be preserved as evidence, not normalized away.
- Historical failure or divergence must never be rewritten by later success.
- No challenge result here grants regulated, legal, clinical, radiation, quality, release, or product-disposition authority.

## Challenge posture

The suite is designed to fail closed. A PASS means only that the bounded challenge behaved as declared. It does not establish production readiness, certification, regulator acceptance, or real-world validation.

## Explicit exclusions

- PR #95 is not modified by this package.
- IRLT-MAG is not read, changed, reclassified, or advanced by this package.
- No controlled-stop state is altered.
- No external architecture is treated as implementation evidence.
- No novelty or patentability conclusion is asserted by these tests.
