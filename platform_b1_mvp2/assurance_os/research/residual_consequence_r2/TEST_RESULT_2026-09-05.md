# Residual-Consequence R2 Reproducibility Lane — Test Result

**Date:** 2026-09-05  
**Branch:** `research/residual-consequence-r2-reproducibility`  
**PR:** `#97`  
**Status:** `RESEARCH_ONLY_NOT_CANONICAL`  
**Result:** `PASS 17/17`

## Native GitHub Actions evidence

### Dedicated R2 workflow

- Workflow: `Residual-Consequence R2 Reproducibility Suite`
- Run ID: `33945631314`
- Job: `reproducibility-suite`
- Result: `SUCCESS`
- Frozen Step 184 R1 evaluator compilation: `SUCCESS`
- R2 harness/test compilation: `SUCCESS`
- R2 reproducibility/metamorphic suite: `SUCCESS`

### Combined residual-consequence workflow

- Workflow: `Residual-Consequence R1 Challenge Suite`
- Run ID: `33945631360`
- Job: `bounded-challenge-suite`
- Result: `SUCCESS`
- Research R1.1 compile/tests: `SUCCESS`
- Canonical frozen Step 184 R1 compile/tests: `SUCCESS`
- R2 reproducibility compile/tests: `SUCCESS`

## R2 test classes exercised

1. baseline closure remains non-binding;
2. pre-STOP observation becomes stale;
3. post-STOP observation can establish a fresh basis;
4. material change after observation invalidates freshness;
5. re-observation after material change restores a current basis;
6. open latent-consequence window blocks closure;
7. contradiction cannot improve standing;
8. failure-domain collapse blocks independence;
9. competing-claim order does not change the race-control result;
10. retry with unknown prior consequence state fails closed across all declared example domains;
11. equivalent cross-domain vectors produce equivalent consequence standing;
12. domain labels do not manufacture authority;
13. partial irreversible consequence remains open after STOP;
14. incomplete negative-evidence basis blocks absence/closure inference;
15. forged upstream binding-authority state is rejected;
16. undeclared domain input is rejected by the R2 harness; and
17. duplicate event sequence is rejected by the R2 harness.

## Cross-domain labels exercised

- Radiopharma
- GMP / Compounding
- Environmental / BMS
- AI / Payment
- Cybersecurity
- Clinical Trial

These labels are scenario fixtures only. They do not establish domain validation or domain-specific authority.

## Frozen R1 identity preserved

R2 exercised the existing frozen Step 184 R1 evaluator rather than copying it into a new authority engine.

Frozen R1 identity remains:

- evaluator blob `607694656829b294b7d9d1b5cd742eebce5dd0b5`;
- regression harness blob `2d0d4d9e6d3edf14ad3e98973db0cc5aaece0711`;
- tested/frozen R1 code-test commit `d22455efa35177f6e2375867edf77ded7ba5ff7e`.

## Finding

`NO_MATERIAL_R1_DEFECT_ESTABLISHED_BY_R2_REPRODUCIBILITY_SUITE`

The current R2 results strengthen confidence that the frozen R1 consequence semantics remain stable under the declared temporal, contradiction, race/retry, witness-dependence, and cross-domain metamorphic vectors.

This does **not** justify a canonical Step 184 R2 successor by itself. The promotion rule remains: a successor should be created only if a material reproducible delta is found that cannot be handled as documentation or test-only challenge evidence around frozen R1.

## Maturity boundary

This result does not establish:

- production readiness;
- field validation;
- independent third-party reproduction;
- certification;
- regulator acceptance;
- domain-specific clinical/radiological/quality authority;
- complete integration/non-bypassability; or
- novelty/patentability.

PR #95 and IRLT-MAG remain outside this research lane.
