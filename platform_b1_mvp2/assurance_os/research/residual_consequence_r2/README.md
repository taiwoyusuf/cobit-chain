# Residual-Consequence R2 — Reproducibility / Cross-Domain Challenge Lane

Status: `RESEARCH_ONLY_NOT_CANONICAL`

## Purpose

R2 does **not** modify or supersede the frozen Step 184 R1 executable payload. It is an isolated challenge lane that tests whether the frozen R1 consequence boundary behaves consistently when fed stronger temporal, witness-dependence, replay, race, and cross-domain scenario vectors.

Frozen R1 executable identity remains:

- evaluator blob: `607694656829b294b7d9d1b5cd742eebce5dd0b5`
- regression harness blob: `2d0d4d9e6d3edf14ad3e98973db0cc5aaece0711`
- tested commit: `d22455efa35177f6e2375867edf77ded7ba5ff7e`

R2 may expose defects or motivate a later successor revision. It must never silently rewrite R1.

## R2 questions

1. **Temporal ordering** — does stale or pre-STOP observation fail closed?
2. **Material-change freshness** — does a change after observation invalidate a prior termination observation?
3. **Latent-window closure** — can reliance remain blocked until the declared delayed-consequence window actually closes?
4. **Contradiction monotonicity** — can adding an independent contradiction ever improve standing? It must not.
5. **Failure-domain collapse** — can two apparently separate witnesses become one effective failure domain? If so, independence must fail closed.
6. **Claim-order invariance** — should reordering equivalent competing-claim records alter the result? It must not.
7. **Retry/replay safety** — does retry with unknown prior consequence state remain blocked regardless of domain label?
8. **Cross-domain consistency** — do the same assurance semantics hold across radiopharma, GMP/compounding, environmental/BMS, AI/payment, cybersecurity, and clinical-trial examples?
9. **Domain-label non-authority** — changing a scenario label must never manufacture a different authority result.
10. **Frozen-interface discipline** — R2 imports and exercises the frozen R1 evaluator; it does not copy it into a competing implementation engine.

## Architecture

`Scenario vector -> R2 trace/evidence derivation -> frozen Step 184 R1 evaluator -> R2 metamorphic assertions`

R2 therefore tests composition and reproducibility around the frozen boundary rather than creating a new authoritative consequence engine.

## Non-claims

- No production validation.
- No independent third-party reproduction.
- No regulator acceptance.
- No certification.
- No field validation.
- No novelty/patentability determination.
- No new binding authority.
- No IRLT-MAG state change.
- No modification of PR #95.

## Promotion rule

A future Step 184 R2 canonical successor is justified only if this lane establishes a material, reproducible delta that cannot be represented as documentation or test-only hardening around frozen R1. Until then this remains `RESEARCH_ONLY_NOT_CANONICAL`.
