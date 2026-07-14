def build_display_contract(
    track_id,
    scenario_id,
    authority_result,
    admissibility_result,
):
    return {
        "schema_version": "1.0",
        "track_id": track_id,
        "scenario_id": scenario_id,
        "display_only": True,
        "can_approve": False,
        "can_bind": False,
        "can_release": False,
        "binding_authority": (
            "IDENTIFIED_ACCOUNTABLE_HUMAN"
        ),
        "authority_state": authority_result[
            "authority_state"
        ],
        "no_bind_state": admissibility_result[
            "no_bind_state"
        ],
        "action_held": admissibility_result[
            "action_held"
        ],
        "escalation_required": (
            admissibility_result[
                "escalation_required"
            ]
        ),
        "documented_pause_created": (
            admissibility_result[
                "documented_pause_created"
            ]
        ),
        "decision": admissibility_result[
            "decision"
        ],
    }
