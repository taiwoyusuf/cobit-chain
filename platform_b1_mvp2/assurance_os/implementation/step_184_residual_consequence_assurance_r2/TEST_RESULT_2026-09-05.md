# Step 184 Residual-Consequence Assurance R2 — Candidate Test Result

**Date:** 2026-09-05  
**Status:** `SYNTHETICALLY_VERIFIED_CANDIDATE`  
**Freeze status:** `NOT_FROZEN`

## Candidate under test

Branch: `candidate/step-184-residual-consequence-r2`

Candidate CI head: `6951b7510e618c260b85510cb566d17440aa82a6`

## Verification evidence

Dedicated R2 workflow run:

- workflow: `Residual-Consequence R2 Reproducibility Suite`
- run ID: `33946114082`
- candidate job: `reproducibility-suite`
- candidate job result: `SUCCESS`

The job successfully completed all of the following:

1. compile frozen Step 184 R1 evaluator;
2. compile R2 research harness and tests;
3. run R2 research reproducibility/metamorphic suite;
4. compile Step 184 R2 candidate evaluator and tests; and
5. run Step 184 R2 candidate regression suite.

Candidate regression coverage: **21 deterministic tests**.

## Successor behaviors verified

### RC2-TERM-01

The R2 candidate blocks positive consequence closure when:

`consequence_termination_observed = False`

whether or not a STOP command occurred.

Invariant:

`CONSEQUENCE_CLOSURE -> EXPLICIT_TERMINATION_EVIDENCE`

### RC2-TEMP-01

The R2 candidate blocks positive closure when:

- `material_change_after_reclosure = True`; and
- `reclosure_reevaluated_after_latest_material_change != True`.

Invariant:

`MATERIAL_CHANGE_AFTER_RECLOSURE -> RECLOSURE_REEVALUATION_REQUIRED`

Re-evaluation after the latest material change restores only the temporal prerequisite; all other R1/R2 closure conditions must still hold.

## R1 regression preservation

Candidate testing also preserves the bounded R1 controls for:

- non-authority / No-Bind;
- authority standing at irreversible boundary;
- STOP versus consequence termination;
- partial irreversible consequence;
- residual propagation;
- latent consequence window;
- contradiction preservation;
- witness failure-domain independence;
- race / competing execution claims;
- retry / replay / duplicate prevention;
- negative-evidence basis; and
- Step 180 / 182 / 183 upstream history and non-authority contracts.

Frozen R1 executable identities remain unchanged:

- evaluator blob `607694656829b294b7d9d1b5cd742eebce5dd0b5`
- regression blob `2d0d4d9e6d3edf14ad3e98973db0cc5aaece0711`

## Boundaries

- `AUTHORITY = NONE`
- no physical action executed;
- no regulated release/disposition authorized;
- no IRLT-MAG state changed;
- RAMAT remains witness/context only;
- PR #95 untouched;
- PR #96 remains frozen/draft and not merged;
- PR #97 remains research-only/draft and not merged.

## Non-claims

This result does not establish production readiness, operational validation, independent third-party assurance, certification, regulator acceptance, field validation, novelty, or patentability.

**Current posture:** `IMPLEMENTED_BOUNDED_CANDIDATE / SYNTHETICALLY_VERIFIED_CANDIDATE / NOT_FROZEN`
