# Step 184 — Residual-Consequence Assurance R2 Candidate

Status: `IMPLEMENTED_BOUNDED_CANDIDATE`

Promotion posture: `R2_CANDIDATE_NOT_FROZEN`

## Why R2 exists

R2 is a successor candidate to the frozen Step 184 R1 configuration. R1 remains preserved and unchanged.

R2 is justified by two reproduced material deltas established in the isolated research lane:

1. `RC2-TERM-01` — closure must always require explicit consequence termination evidence, independently of whether a STOP command occurred;
2. `RC2-TEMP-01` — a Step 183 re-closure proposition that predates a later material change cannot support current consequence closure until re-closure is evaluated again after the latest material change.

## Added candidate contract

R2 retains the R1 inputs and adds:

`temporal_state`

with two explicit fail-closed propositions:

- `material_change_after_reclosure`
- `reclosure_reevaluated_after_latest_material_change`

This deliberately avoids rewriting Step 183 history. Step 183 may have been valid when evaluated; R2 asks whether that re-closure proposition is still temporally usable for current consequence closure.

## Successor invariants

`CONSEQUENCE_CLOSURE -> EXPLICIT_TERMINATION_EVIDENCE`

`MATERIAL_CHANGE_AFTER_RECLOSURE -> RECLOSURE_REEVALUATION_REQUIRED`

These are additive to the frozen R1 invariants:

- `AUTHORITY_WITHDRAWN != EXECUTION_TERMINATED`
- `EXECUTION_TERMINATED != CONSEQUENCE_TERMINATED`
- `STOP_SUCCESS != CONSEQUENCE_TERMINATION`
- `EXECUTION_SUCCESS != INTENDED_OUTCOME_ESTABLISHED`
- `RECOVERY != RECLOSURE`
- `RECLOSURE != RETURN_TO_RELIANCE`
- `NOT_DETECTED != ABSENT`

## Non-authority boundary

- `AUTHORITY = NONE`
- no binding authority is granted;
- no physical action is executed;
- no regulated release/disposition is authorized;
- positive closure still requires separate current Authority Standing and Action Admissibility before any next consequence-producing action;
- RAMAT remains witness/context capability only;
- IRLT-MAG is not read, modified, reclassified, advanced, or merged.

## R1 preservation

Frozen R1 executable/test identities remain unchanged:

- evaluator blob `607694656829b294b7d9d1b5cd742eebce5dd0b5`
- regression blob `2d0d4d9e6d3edf14ad3e98973db0cc5aaece0711`

R2 is a successor revision, not an in-place edit or unfreeze of R1.

## Verification posture

The candidate includes a dedicated deterministic regression suite. Passing that suite establishes only the declared software behavior of the R2 candidate. It does not establish production readiness, operational validation, independent third-party assurance, certification, regulator acceptance, or field validation.

## Protected isolation

- PR #95 remains untouched.
- PR #96 remains frozen/draft and not merged.
- PR #97 remains the research delta lane and is not treated as canonical implementation.
- this R2 candidate must remain draft/unfrozen until its dedicated review and freeze gate is separately completed.
