def build_reconstruction(
    track_id,
    scenario_id,
    evidence_result,
    dependency_result,
    authority_result,
    admissibility_result,
    timestamp,
    recovery_context=None,
):
    result = {
        "schema_version": "1.0",
        "track_id": track_id,
        "scenario_id": scenario_id,
        "reconstructed_at": timestamp,
        "timeline": [
            {
                "sequence": 1,
                "event": "SOURCE_STATE_OBSERVED",
            },
            {
                "sequence": 2,
                "event": evidence_result["state"],
            },
            {
                "sequence": 3,
                "event": dependency_result["state"],
            },
            {
                "sequence": 4,
                "event": authority_result[
                    "authority_state"
                ],
            },
            {
                "sequence": 5,
                "event": (
                    "NO_BIND_" +
                    admissibility_result[
                        "no_bind_state"
                    ]
                ),
            },
            {
                "sequence": 6,
                "event": admissibility_result[
                    "decision"
                ],
            },
        ],
        "decision_reasons": (
            admissibility_result.get(
                "reasons",
                [],
            )
        ),
        "fail_closed": (
            admissibility_result.get(
                "fail_closed",
                False,
            )
        ),
        "history_preserved": True,
    }

    if recovery_context:
        result["recovery_context"] = (
            recovery_context
        )
        result[
            "prior_failure_history_preserved"
        ] = True

    return result
