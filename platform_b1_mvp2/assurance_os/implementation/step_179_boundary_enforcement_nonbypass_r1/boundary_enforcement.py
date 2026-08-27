"""Step 179 boundary-enforcement integration gateway.

This bounded adapter composes existing Step 170 authority/NO_BIND outputs with
Step 178 boundary-assurance determinations. It does not replace either engine
and it does not execute regulated or physical actions.
"""

REQUIRED_BOUNDARY_RESULTS = (
    "control_capacity",
    "epistemic_class",
    "processing_authority",
    "disposition",
)


def enforce_boundary_decision(*, authority_result: dict, boundary_results: dict,
                              capsule: dict, requested_object_hash: str,
                              caller_requested_decision: str,
                              consequence_mode: str = "EXECUTE",
                              recovery_result: dict | None = None) -> dict:
    """Fail closed when an upstream assurance determination is not supportable.

    A downstream caller cannot convert a failed or missing assurance
    determination into an admissible action merely by requesting ADMISSIBLE.
    """
    reasons = []

    if authority_result.get("authority_valid") is not True:
        reasons.append("AUTHORITY_NOT_VERIFIED")
    if authority_result.get("no_bind_state") != "INACTIVE":
        reasons.append("UPSTREAM_AUTHORITY_NO_BIND_ACTIVE")

    for name in REQUIRED_BOUNDARY_RESULTS:
        result = boundary_results.get(name)
        if not isinstance(result, dict):
            reasons.append(name.upper() + "_RESULT_MISSING")
            continue
        if result.get("fail_closed") is True:
            reasons.append(name.upper() + "_FAIL_CLOSED")

    if not isinstance(capsule, dict):
        reasons.append("BOUNDARY_CAPSULE_MISSING")
    else:
        if capsule.get("fail_closed") is True or capsule.get("capsule_state") != "SUPPORTABLE":
            reasons.append("BOUNDARY_CAPSULE_NOT_SUPPORTABLE")
        if not requested_object_hash:
            reasons.append("REQUESTED_OBJECT_HASH_MISSING")
        elif capsule.get("object_hash") != requested_object_hash:
            reasons.append("REQUESTED_OBJECT_DIFFERS_FROM_EVALUATED_OBJECT")
        committed = capsule.get("committed_object_hash")
        if committed is not None and committed != requested_object_hash:
            reasons.append("COMMITTED_OBJECT_DIFFERS_FROM_REQUESTED_OBJECT")

    if consequence_mode == "RECOVERY":
        if not isinstance(recovery_result, dict):
            reasons.append("RECOVERY_RESULT_MISSING")
        elif recovery_result.get("recovery_standing") != "RECOVERED_WITHIN_DECLARED_SCOPE":
            reasons.append("RECOVERY_STANDING_NOT_ESTABLISHED")
    elif consequence_mode != "EXECUTE":
        reasons.append("UNKNOWN_CONSEQUENCE_MODE")

    blocked = bool(reasons)
    decision = "NOT_ADMISSIBLE" if blocked else "ADMISSIBLE"
    no_bind_state = "ACTIVE" if blocked else "INACTIVE"
    caller_override_rejected = blocked and caller_requested_decision == "ADMISSIBLE"

    return {
        "enforcement_decision": decision,
        "no_bind_state": no_bind_state,
        "action_held": blocked,
        "escalation_required": blocked,
        "caller_requested_decision": caller_requested_decision,
        "caller_override_rejected": caller_override_rejected,
        "requested_object_hash": requested_object_hash,
        "consequence_mode": consequence_mode,
        "reasons": sorted(set(reasons)),
        "binding_authority_granted": False,
        "physical_action_executed": False,
        "non_bypassability_enforced": True,
    }
