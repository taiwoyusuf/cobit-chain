# Step 180 — Execution-Time Revalidation R1

Status: `IMPLEMENTED_BOUNDED_CANDIDATE`

This step adds execution-time revalidation for a previously admissible assurance result. It does not create a new VSA, authority, release, clinical, radiation, compounding, laboratory, environmental, or product-disposition engine.

## Core invariant

`PRIOR_ADMISSIBLE != CURRENT_EXECUTION_STANDING`

A prior admissibility result is preserved as historical evidence of what was supportable at evaluation time. Before commitment, current authority, object identity, evidence basis, criteria version, configuration, environmental/context state, and decision freshness must still support execution.

## Implemented behavior

1. Prior `NOT_ADMISSIBLE` cannot be promoted by revalidation.
2. A stale prior decision fails closed after its declared maximum age.
3. Authority withdrawal before commit produces `NOT_ADMISSIBLE`.
4. Evaluated-object substitution is always blocked and cannot be declared immaterial.
5. Changed evidence, criteria, configuration, or environmental/context state requires explicit materiality classification.
6. Material change produces `REASSESSMENT_REQUIRED` and `NO_BIND`.
7. Unclassified change fails closed rather than being silently treated as immaterial.
8. Declared immaterial change can preserve current standing within this bounded evaluator.
9. Historical prior standing is preserved and not rewritten by later withdrawal.

## Reuse / non-duplication

- Step 175 remains authoritative for Control-Basis Standing, Partial-Evidence Examination and Authorized Trust-Anchor Succession.
- Step 176 remains authoritative for physical/context standing including time-indexed standing and operating-envelope behavior.
- Step 178 remains authoritative for Boundary Assurance Capsule and other boundary invariants.
- Step 179 remains authoritative for downstream non-bypassability of failed assurance determinations.
- Step 180 adds only the missing evaluation-to-commit revalidation boundary.

## Boundary

Outputs are non-binding assurance-routing determinations. This step does not grant regulatory authority, execute physical actions, release/disposition product, authorize radiation work, make clinical decisions, or replace authorized human/institutional decision pathways.

## Test command

```bash
python -m unittest -v test_revalidation.py
```

Expected test count: 12.

## Maturity boundary

The implementation and deterministic tests are present. Until CI executes and preserved evidence supports promotion, this step must not be represented as operationally validated, independently reproduced, regulator-approved, or production-ready.
