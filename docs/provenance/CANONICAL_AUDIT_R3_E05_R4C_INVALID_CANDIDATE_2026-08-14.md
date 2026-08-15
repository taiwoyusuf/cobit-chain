# Canonical Audit R3 — E05 — R4C Invalid Candidate Record

Evidence date: 14 August 2026 (America/Indiana/Indianapolis).

This record documents the attempted R4C construction-harness candidate creation following the consumed R4B governed stop. It does not authorize or execute R4C, Runner R10, T001-T052, E05 R7, any successor candidate, R3-E06, hardware, Azure, network, or firmware activity.

## Predecessor state

- Exact frozen/consumed R4B SHA-256: `E17994782814BFBFCBC497AD5C62DB08C9E8D1F147BA0F5EAE76BB3DB4179F6D`.
- R4B size: `83286`.
- R4B one-time construction-harness execution: `EXECUTED_AND_CONSUMED`.
- R4B rerun/retry: `NOT_AUTHORIZED`.
- R4B final successor candidate files written: `0`.
- Post-stop read-only regex probe established that numeric replacement strings using `$1` are ambiguous, while `${1}` reproduces the intended operator-size forward/reverse transformation exactly.

## R4C attempted repair

R4C attempted to replace six ambiguous size-replacement forms globally with `${1}` forms while preserving the established wrapper source-cardinality contract `1 / 0 / 0`.

Observed during construction:

- R4C source loaded as `System.String`.
- source designation promotion count: `1`.
- runtime-title promotion count: `1`.
- history/scope insertion count: `1`.
- forward operator-size backreference source count: `1`.
- forward Launch Gate-size backreference source count: `1`.
- forward Runner-size backreference source count: `1`.
- reverse operator-size backreference source count: `1`.
- reverse Launch Gate-size backreference source count: `2`.

The candidate builder therefore stopped at:

`R4C_REVERSE_LAUNCH_SIZE_BACKREFERENCE expected exactly one source occurrence; observed 2. STOP.`

The failure shows that the literal `'$1' + '25451'` is not globally unique in the construction-harness source. A global string replacement is therefore not a valid bounded repair strategy for that reverse transformation. The wrapper reverse occurrence must be selected by contextual structure rather than by global literal cardinality.

## Interactive-shell consequence

The construction commands were pasted interactively. After the terminating error, later pasted commands continued executing in the shell. As a result, a partial file was written even though required validation had already failed.

Written partial file identity:

- SHA-256: `7AE73EFD7A3FC465C3875C95AD87D5BF1CCFA5D85949501D02FC07C51F6130FA`.
- size: `83553`.

Subsequent literal output included `R4C_CONSTRUCTION_SELF_CHECK = PASS`, but that text is not a valid governed PASS because earlier mandatory checks had already failed, including:

- reverse Launch Gate-size repair uniqueness;
- complete six-repair application;
- reverse-normalization loop;
- exact reverse-normalization to R4B (`FALSE`).

Therefore:

`R4C = INVALID_CONSTRUCTION_HARNESS_CANDIDATE_DO_NOT_EXECUTE`

`R4C_EXECUTION_AUTHORITY = NOT_CREATED`

`R4C_RERUN = NOT_AUTHORIZED`

No R7 successor candidate was created by this attempt.

## Preserved boundary

- `R4B_EXECUTION = EXECUTED_AND_CONSUMED`
- `R4B_RERUN = NOT_AUTHORIZED`
- `R4C_EXECUTION = FALSE`
- `SUCCESSOR_CANDIDATE_FILES_CREATED = 0`
- `RUNNER_R10_EXECUTED = FALSE`
- `T001_T052_EXECUTED = 0`
- `E05_R7_EXECUTED = FALSE`
- `SUCCESSOR_GOVERNED_EXECUTION = NOT_AUTHORIZED`
- `R3_E05_RUNTIME_ACCEPTANCE = NOT_ESTABLISHED`
- `R3_E06 = NOT_AUTHORIZED`
- `HARDWARE_ACCESS = FALSE`
- `AZURE_ACCESS = FALSE`
- `NETWORK_ACCESS = FALSE`
- `INDEPENDENT_CONTROL_LAYER_ROLE = PRESERVED`

## Next bounded engineering action

Construct a new development candidate from exact frozen/consumed R4B using context-bound replacement of only the wrapper dependency-size regex replacement expressions. Preserve the already-established `1 / 0 / 0` source-cardinality contract. Do not derive the next candidate from the invalid R4C file.
