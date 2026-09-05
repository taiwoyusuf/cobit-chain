# Residual-Consequence R1 Challenge Matrix

| ID | Control | Adversarial condition | Required safe result |
|---|---|---|---|
| RC1-WIT-01 | Proposition-Bound Witness Standing | Witness is healthy but qualified for a different proposition | `NOT_ESTABLISHED` |
| RC1-WIT-02 | Proposition-Bound Witness Standing | Observation is stale | `REASSESSMENT_REQUIRED` |
| RC1-NEG-01 | Observability / Negative Evidence | Relevant item is not detected | Preserve `UNKNOWN`; never infer absence |
| RC1-NEG-02 | Observability / Negative Evidence | Claimed absence but detection capability is not established | `NOT_ESTABLISHED` |
| RC1-NEG-03 | Observability / Negative Evidence | Evidence service unavailable | Preserve `UNKNOWN`; never infer contradiction-free state |
| RC1-CON-01 | Contradiction + Independence | One witness supports and another contradicts | `CONTRADICTED`, preserve both records |
| RC1-CON-02 | Contradiction + Independence | Two supporting witnesses share one material failure domain | Count as one independent support domain |
| RC1-CON-03 | Contradiction + Independence | Failure-domain lineage missing | `DEPENDENCY_UNCERTAIN` |
| RC1-CON-04 | Contradiction + Independence | Contradiction service unavailable | `UNKNOWN`; never report clean contradiction state |
| RC1-OUT-01 | Outcome Correspondence / Re-closure | Execution succeeds but no physical outcome is observed | `RECLOSURE_NOT_ESTABLISHED` |
| RC1-OUT-02 | Outcome Correspondence / Re-closure | Earlier permission is no longer current | `RECLOSURE_NOT_ESTABLISHED` |
| RC1-OUT-03 | Outcome Correspondence / Re-closure | Intended outcome occurred but residual effect remains | `RECLOSURE_NOT_ESTABLISHED` |
| RC1-OUT-04 | Outcome Correspondence / Re-closure | Independent re-verification required but missing | `RECLOSURE_NOT_ESTABLISHED` |
| RC1-OUT-05 | Outcome Correspondence / Re-closure | All bounded closure conditions supportable | `RECLOSURE_SUPPORTABLE`, but separate authority/action-admissibility remains required |
| RC1-TRN-01 | Outcome Correspondence / Re-closure | Authority revoked after commit but before irreversible consequence; stop is too late | `RESIDUAL_CONSEQUENCE_REVIEW_REQUIRED` |
| RC1-RACE-01 | Outcome Correspondence / Re-closure | Agent A and Agent B are both eligible for the same consequence with no serialized winner | `RACE_UNRESOLVED`; No-Bind active |
| RC1-RPL-01 | Outcome Correspondence / Re-closure | Retry requested while prior consequence state is unknown | `RETRY_NOT_SUPPORTABLE` |
| RC1-OUT-06 | Outcome Correspondence / Re-closure | STOP/failed completion leaves a partial irreversible consequence | `RECLOSURE_NOT_ESTABLISHED` |
| RC1-OUT-07 | Outcome Correspondence / Re-closure | Latent consequence remains possible and observation window is incomplete | `RECLOSURE_NOT_ESTABLISHED` |
| RC1-CON-05 | Contradiction + Independence | Digital log and RAMAT/other witness share the same PTP clock failure domain | Apparent 2 supports = 1 independent domain |
| RC1-CON-06 | Contradiction + Independence | Digital execution receipt says success; independent physical witness contradicts | `CONTRADICTED`, preserve both |
| RC1-OUT-08 | Outcome Correspondence / Re-closure | STOP is established but consequence continues propagating | `RECLOSURE_NOT_ESTABLISHED`; preserve residual consequence |

## R1.1 hardening interpretation

The added attacks test whether assurance survives the interval between authorization and physical consequence rather than only evaluating point-in-time permission. They deliberately distinguish:

`AUTHORITY CURRENT AT START`

from

`AUTHORITY CURRENT AT COMMIT`

from

`AUTHORITY CURRENT AT IRREVERSIBLE BOUNDARY`.

They also distinguish:

`EXECUTION STOPPED != CONSEQUENCE STOPPED`.

A successful stop can therefore coexist with an unresolved residual consequence when the physical, financial, information, radiological, environmental, or other effect is already propagating.

## Non-substitution rules

- A PASS is evidence only for the declared test proposition.
- Test success does not establish real-world validation, production readiness, certification, regulatory acceptance, or independent assurance.
- No result authorizes action.
- IRLT-MAG state is outside this package and must remain unchanged.
- PR #95 is outside this package and must remain unchanged.

## External watch interpretation

The recent Gary Williams / Elias Keystone posts reinforce a useful challenge condition already represented here: historical authorization is not current execution standing. This suite does **not** treat Keystone as implementation evidence and does not merge architectures. It uses the public claim only as a watch-derived adversarial prompt against existing COBIT-Chain controls.

The Ravi Shankar post reinforces a different boundary: a locally complete control stack does not prove downstream governance propagation across disconnected institutions. That issue is recorded as a future network-propagation challenge and is deliberately **not** collapsed into Residual-Consequence R1, which remains scoped to current standing, observation, contradiction/independence, physical outcome, and re-closure.
