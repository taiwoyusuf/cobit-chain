REQUIRED_TRUE_FIELDS = (
    "authority_present",
    "authority_valid",
    "authority_current",
    "authority_delegated",
    "approver_available",
    "escalation_available",
    "evidence_sufficient",
    "timing_valid",
    "human_accountability_identified",
)


def evaluate_authority(authority):
    reasons = []

    for field in REQUIRED_TRUE_FIELDS:
        if authority.get(field) is not True:
            reasons.append(
                field.upper() +
                "_NOT_CONFIRMED"
            )

    insufficient = bool(reasons)

    return {
        "authority_state": (
            "AUTHORITY_VERIFIED"
            if not insufficient
            else "AUTHORITY_INSUFFICIENT"
        ),
        "authority_valid": not insufficient,
        "no_bind_state": (
            "ACTIVE"
            if insufficient
            else "INACTIVE"
        ),
        "action_held": insufficient,
        "escalation_required": insufficient,
        "documented_pause_created": insufficient,
        "reasons": reasons,
        "binding_authority": (
            "IDENTIFIED_ACCOUNTABLE_HUMAN"
        ),
        "silence_is_not_consent": True,
    }
