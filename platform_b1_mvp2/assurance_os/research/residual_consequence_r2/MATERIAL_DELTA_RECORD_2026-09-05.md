# Residual-Consequence R2 — Material Delta Record

**Date:** 2026-09-05  
**Status:** `MATERIAL_SUCCESSOR_DELTA_ESTABLISHED`  
**Frozen R1 status:** `APPROVED_AND_FROZEN / UNCHANGED`

## Summary

Second-wave R2 differential testing reproduced two bounded conditions in which the frozen Step 184 R1 evaluator can return `RESIDUAL_CONSEQUENCE_CLOSED_WITHIN_DECLARED_SCOPE` even though a stricter successor condition is not established.

R2 preserves the raw frozen R1 result and applies research-only guards. No frozen R1 executable or test blob is modified.

## RC2-TERM-01 — Explicit termination evidence required independent of STOP

Frozen R1 checks `consequence_termination_observed` only when `stop_command_succeeded=True`.

Reproduced vector:
- current observation present;
- no STOP event;
- `consequence_termination_observed=False`;
- all other R1 closure prerequisites supportable.

Observed frozen R1 result:
- `RESIDUAL_CONSEQUENCE_CLOSED_WITHIN_DECLARED_SCOPE`
- `return_to_reliance_supportable=True`

R2 successor guard:
- `CONSEQUENCE_TERMINATION_NOT_OBSERVED`
- standing narrowed to `RESIDUAL_CONSEQUENCE_STANDING_NOT_ESTABLISHED`
- return to reliance blocked.

Successor invariant:

`CONSEQUENCE_CLOSURE -> EXPLICIT_TERMINATION_EVIDENCE`

This requirement applies whether consequence termination follows a STOP command, natural completion, timeout, external interruption, or another execution path.

## RC2-TEMP-01 — Re-closure basis must remain current across later material change

Frozen R1 validates the supplied Step 183 re-closure result structurally but does not temporally bind that result to later material change events.

Reproduced vector:
1. Step 183 re-closure evaluated and supportable;
2. material change occurs;
3. fresh physical observation occurs;
4. the old Step 183 re-closure result is supplied unchanged.

Observed frozen R1 result:
- `RESIDUAL_CONSEQUENCE_CLOSED_WITHIN_DECLARED_SCOPE`

R2 successor guard:
- `RECLOSURE_BASIS_STALE_AFTER_MATERIAL_CHANGE`
- standing narrowed to `RESIDUAL_CONSEQUENCE_STANDING_NOT_ESTABLISHED`.

A later `RECLOSURE_EVALUATED` event after the material change restores the temporal basis in the bounded R2 trace model.

Successor invariant:

`MATERIAL_CHANGE_AFTER_RECLOSURE -> RECLOSURE_REEVALUATION_REQUIRED`

## Verification evidence

Differential head: `d9a1f60afbc9eca298560440654f6c0e33d96eed`

GitHub Actions:
- `Residual-Consequence R2 Reproducibility Suite` run `33945922658`: `SUCCESS`
- `Residual-Consequence R1 Challenge Suite` run `33945922675`: `SUCCESS`

The R2 suite now contains **21 deterministic/metamorphic tests**. The combined workflow also re-ran the original R1.1 research challenge suite and frozen canonical Step 184 R1 suite successfully.

## Interpretation

This is now more than additional reproduction pressure. R2 has established bounded successor semantics not enforced by frozen R1.

Accordingly:

`R2_RESEARCH_ONLY -> FORMAL_R2_CANDIDATE_DESIGN_JUSTIFIED`

This does **not** authorize modification of R1, production deployment, merge, certification, regulator acceptance, or independent assurance.

## R1 preservation

Frozen R1 remains historical and unchanged:
- evaluator blob `607694656829b294b7d9d1b5cd742eebce5dd0b5`
- test blob `2d0d4d9e6d3edf14ad3e98973db0cc5aaece0711`

Any canonical R2 successor must be a new revision with explicit chronology and must not rewrite the frozen R1 record.

## Protected boundaries

- PR #95 untouched.
- PR #96 remains draft/not merged.
- IRLT-MAG untouched.
- No controlled-stop state change.
- RAMAT remains witness/context only.
- `AUTHORITY = NONE`.
