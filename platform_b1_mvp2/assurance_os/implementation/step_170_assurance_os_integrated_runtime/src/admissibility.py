def determine_admissibility(
    evidence_result,
    dependency_result,
    authority_result,
):
    reasons = []

    if not evidence_result.get("valid", False):
        reasons.append(
            "EVIDENCE_INTEGRITY_NOT_VERIFIED"
        )

    if not dependency_result.get("valid", False):
        reasons.append(
            "WORKFLOW_DEPENDENCIES_NOT_VERIFIED"
        )

    if not authority_result.get(
        "authority_valid",
        False,
    ):
        reasons.append(
            "HUMAN_AUTHORITY_NOT_VERIFIED"
        )

    admissible = not reasons
    no_bind_active = not admissible

    return {
        "decision": (
            "ADMISSIBLE"
            if admissible
            else "NOT_ADMISSIBLE"
        ),
        "no_bind_state": (
            "INACTIVE"
            if admissible
            else "ACTIVE"
        ),
        "action_held": no_bind_active,
        "escalation_required": no_bind_active,
        "documented_pause_created": no_bind_active,
        "release_authorized": False,
        "binding_decision_made": False,
        "reasons": reasons,
        "fail_closed": no_bind_active,
    }
