# 08 — Independent Replay Protocol

## Goal

A reviewer should be able to reconstruct the standing sequence without trusting an unstated participant judgment.

## Replay steps

1. Read `02_BASELINE_EVIDENCE.json`.
2. Confirm T0 conditions and the propositions covered by E1.
3. Read `02A_QUALIFICATION_BASIS_AND_REQUIREMENTS.json` and `03_PROPOSITION_GRAPH.json`.
4. Read `04_MATERIALITY_AND_TRANSITION_RULES.json`, `04A_MATERIALITY_MATRIX.json`, and `05A_EVIDENCE_REGISTRY.json`.
5. Apply C1 at T1 and preserve all proposition standings.
6. Apply C2 at T2:
   - preserve P1/P2/P4;
   - move P3/P5/P6/P7 to `REASSESSMENT_REQUIRED`.
7. At T3, because no new evidence is admitted:
   - move P3/P5/P6/P7 to `NOT_ESTABLISHED`.
8. Admit E2 at T4:
   - restore P3 and P5 only;
   - keep P6 `NOT_ESTABLISHED`;
   - keep P7 `NOT_ESTABLISHED` because P6 is required.
9. Admit E3 at T5:
   - restore P6;
   - with P4/P5/P6 supportable, restore P7.
10. Verify that T0 historical P7 remains `SUPPORTABLE` throughout the record.
11. Compare the result with `06_EXPECTED_STANDING_TRANSITIONS.json`.

## Reproduction invariants

- `HISTORICAL_QUALIFICATION != CURRENT_VALIDATION_STANDING`
- `CALIBRATED != REPRESENTATIVE`
- `WITHIN_LIMITS != CURRENT_STANDING`
- `AUTHENTIC_EVIDENCE != CURRENTLY_APPLICABLE_EVIDENCE`
- `CHANGE_DETECTED != CHANGE_MATERIAL_TO_EVERY_PROPOSITION`
- `ROOT_OR_PARENT_RESTORED != ALL_DEPENDENTS_RESTORED`
- `SAME_NUMERICAL_VALUE != SAME_EVIDENTIARY_STANDING`

## Failure criteria

The replay fails if:

- C1 causes standing withdrawal.
- T0 historical standing is rewritten.
- C2 leaves P3/P5/P6/P7 supportable without new evidence.
- C2 incorrectly withdraws P1/P2/P4.
- E2 restores P6 or P7.
- E3 fails to permit P6/P7 restoration under the declared rules.
- in-limit values are treated as sufficient proof of representativeness.

## R2 additional replay checks

- Confirm M1 values at T2/T3 are identical to baseline and remain in range.
- Confirm I1 confidence is 0.97 but its class is `INFERRED`; it cannot satisfy P3.
- Confirm C2 materiality differs by proposition rather than globally.
- Confirm P7 restoration uses exactly P4 AND P5 AND P6.
