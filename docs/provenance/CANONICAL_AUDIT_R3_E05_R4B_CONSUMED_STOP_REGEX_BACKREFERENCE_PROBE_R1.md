# Canonical Audit R3 — E05
# R4B Consumed Construction Stop and Regex Backreference Probe R1

Evidence time: 14 August 2026 approximately 22:27–22:29 -04:00.

This record is documentary/provenance evidence only. It does not authorize any execution.

## R4B one-time construction execution

Exact frozen R4B:

- SHA-256: `E17994782814BFBFCBC497AD5C62DB08C9E8D1F147BA0F5EAE76BB3DB4179F6D`
- size: `83286`

Independent Control had authorized exactly one R4B construction-harness execution only.

The one authorized execution started and is therefore consumed.

Observed result:

- Windows PowerShell 5.1 exact: `TRUE`
- exact R4B frozen identity: `PASS`
- all three successor target paths absent before construction: `TRUE`
- Launch Gate R7 in-memory static contract: passed
- `REVERSE_NORMALIZED_LAUNCH_GATE_R7_EQUALS_FROZEN_LAUNCH_GATE_R6_EXACTLY = TRUE`
- Launch Gate R7 in-memory SHA-256: `755871E44FF762FCDB814FDE44EC8FE852FDDA568084FEEE56A20CF5E16C87BC`
- Launch Gate R7 in-memory size: `25486`
- Operator R7 REV1 in-memory static contract: passed
- `REVERSE_NORMALIZED_OPERATOR_R7_REV1_EQUALS_FROZEN_OPERATOR_R6_REV1_EXACTLY = TRUE`
- Operator R7 REV1 in-memory SHA-256: `EA56F513DBAFFC46D6EF249F8A441463FBCF591AD8506469F98D1FA857FEF513`
- Operator R7 REV1 in-memory size: `36446`
- wrapper operator-size source anchor matched once
- wrapper Launch Gate-size source anchor matched zero times
- wrapper Runner-size source anchor matched zero times
- R7 wrapper parser/static contract passed through the inspected surface
- terminal construction stop: `REVERSE_NORMALIZED_R7_WRAPPER_EQUALS_FROZEN_CONSUMED_R6_WRAPPER_EXACTLY = FALSE`
- successor candidate files written: `0`
- Runner R10 executed: `FALSE`
- T001-T052 executed: `0`
- E05 R7 executed: `FALSE`
- R3-E06 executed: `FALSE`

Controlling execution state:

`R4B_CONSTRUCTION_HARNESS_EXECUTION = EXECUTED_AND_CONSUMED`

`R4B_CONSTRUCTION_HARNESS_EXECUTION_RETRY = NOT_AUTHORIZED`

`R4B_CONSTRUCTION_HARNESS_EXECUTION_RERUN = NOT_AUTHORIZED`

`SUCCESSOR_CANDIDATE_FILE_COUNT = 0`

`R3_E05_RUNTIME_ACCEPTANCE = NOT_ESTABLISHED`

The separate console `finally` and `else` command errors occurred because those clauses were submitted after their preceding compound statements had already completed. They are operator-console errors, not Canonical Audit construction-harness or Runner defects.

## Read-only regex replacement semantics probe

A subsequent read-only probe used the exact frozen R6 wrapper:

- SHA-256: `4C55648E61B4D477EC4978F6E2F8183775398B95D6DAD844E787492A513E8846`
- size: `16611`
- identity gate: `PASS`
- exact source `$ExpectedOperatorSize = 36403` anchor count: `1`

The probe established the exact construction-harness defect.

Current ambiguous forward replacement expression produced replacement literal:

`$136446`

Observed consequence:

- expected `$ExpectedOperatorSize = 36446` count: `0`
- original `$ExpectedOperatorSize = 36403` count: `0`
- literal `$136446` count: `1`

Safe replacement expression produced:

`${1}36446`

Observed consequence:

- expected `$ExpectedOperatorSize = 36446` count: `1`
- residual predecessor size count: `0`

Safe forward/reverse round trip:

`SAFE_OPERATOR_SIZE_FORWARD_REVERSE_EQUALS_EXACT_R6 = TRUE`

Current ambiguous reverse replacement produced replacement literal:

`$136403`

and:

`AMBIGUOUS_OPERATOR_SIZE_REVERSE_EQUALS_EXACT_R6 = FALSE`

Therefore the R4B wrapper reverse-normalization stop is explained by ambiguous .NET regex replacement backreference syntax. The cardinality repair itself remains supported by the frozen R6 source inventory.

## Narrow successor implication

A replacement construction-harness candidate may be engineered only as a new candidate, not as a rerun of R4B.

The bounded functional repair is to disambiguate the affected wrapper operator-size regex replacement backreference:

- forward: `'$1' + $OperatorR7Size` -> `'${1}' + $OperatorR7Size`
- reverse: `'$1' + '36403'` -> `'${1}' + '36403'`

The already-established wrapper source-cardinality contract remains:

- operator-size expected source count: `1`
- Launch Gate-size expected source count: `0`
- Runner-size expected source count: `0`

No new Runner, E05, routing, execution, R3-E06, network, Azure, hardware, firmware, or real-repository authority is created by this finding.

## Controlling boundary

`R4B_RERUN = NOT_AUTHORIZED`

`R4B_RETRY = NOT_AUTHORIZED`

`RUNNER_R10_EXECUTION = NOT_AUTHORIZED`

`T001_T052_EXECUTION = NOT_AUTHORIZED`

`E05_R7_EXECUTION = NOT_AUTHORIZED`

`SUCCESSOR_GOVERNED_EXECUTION = NOT_AUTHORIZED`

`R3_E06_EXECUTION = NOT_AUTHORIZED`

`R3_E05_RUNTIME_ACCEPTANCE = NOT_ESTABLISHED`

`R3_E06 = NOT_AUTHORIZED`

`INDEPENDENT_CONTROL_LAYER_ROLE = PRESERVED`
