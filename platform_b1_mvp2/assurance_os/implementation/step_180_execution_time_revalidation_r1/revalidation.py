"""Step 180 execution-time revalidation.

This bounded evaluator rechecks whether a previously admissible assurance result
still supports execution at the commitment boundary. It does not grant binding
regulatory authority and it does not execute physical or regulated actions.
"""

REVALIDATED_DIMENSIONS = (
    "evidence_digest",
    "criteria_version",
    "configuration_hash",
    "environment_context_hash",
)

ALLOWED_MATERIALITY = {"MATERIAL", "IMMATERIAL"}


def evaluate_execution_time_revalidation(*,
                                         prior_enforcement_result: dict,
                                         evaluated_snapshot: dict,
                                         current_snapshot: dict,
                                         materiality_by_dimension: dict,
                                         decision_age_ms: int,
                                         max_decision_age_ms: int) -> dict:
    """Revalidate standing immediately before consequence commitment.

    A prior ADMISSIBLE result is historical evidence of an earlier evaluation,
    not a perpetual execution token. Changed conditions are evaluated at the
    dimension level; material or unclassified changes fail closed.
    """
    reasons = []
    changed = []
    immaterial_changes = []
    material_changes = []
    unclassified_changes = []

    if not isinstance(prior_enforcement_result, dict):
        reasons.append("PRIOR_ENFORCEMENT_RESULT_MISSING")
    elif prior_enforcement_result.get("enforcement_decision") != "ADMISSIBLE":
        reasons.append("PRIOR_DECISION_NOT_ADMISSIBLE")

    if decision_age_ms < 0 or max_decision_age_ms < 0:
        raise ValueError("decision age values must be non-negative")
    if decision_age_ms > max_decision_age_ms:
        reasons.append("PRIOR_DECISION_STALE")

    required_current = (
        "object_hash",
        "authority_current",
        "evidence_digest",
        "criteria_version",
        "configuration_hash",
        "environment_context_hash",
    )
    for field in required_current:
        if field not in evaluated_snapshot or field not in current_snapshot:
            reasons.append(field.upper() + "_SNAPSHOT_MISSING")

    if current_snapshot.get("authority_current") is not True:
        reasons.append("AUTHORITY_NOT_CURRENT_AT_COMMIT")

    evaluated_object = evaluated_snapshot.get("object_hash")
    current_object = current_snapshot.get("object_hash")
    if evaluated_object != current_object:
        reasons.append("OBJECT_CHANGED_AFTER_EVALUATION")

    for dimension in REVALIDATED_DIMENSIONS:
        before = evaluated_snapshot.get(dimension)
        now = current_snapshot.get(dimension)
        if before == now:
            continue

        changed.append(dimension)
        classification = materiality_by_dimension.get(dimension)
        if classification not in ALLOWED_MATERIALITY:
            unclassified_changes.append(dimension)
            reasons.append(dimension.upper() + "_CHANGE_MATERIALITY_NOT_ESTABLISHED")
        elif classification == "MATERIAL":
            material_changes.append(dimension)
            reasons.append(dimension.upper() + "_MATERIAL_CHANGE_REQUIRES_REASSESSMENT")
        else:
            immaterial_changes.append(dimension)

    blocked = bool(reasons)
    standing = "REASSESSMENT_REQUIRED" if blocked else "SUPPORTABLE"
    decision = "NOT_ADMISSIBLE" if blocked else "ADMISSIBLE"

    return {
        "execution_time_standing": standing,
        "execution_time_decision": decision,
        "no_bind_state": "ACTIVE" if blocked else "INACTIVE",
        "action_held": blocked,
        "escalation_required": blocked,
        "changed_dimensions": sorted(changed),
        "immaterial_changes": sorted(immaterial_changes),
        "material_changes": sorted(material_changes),
        "unclassified_changes": sorted(unclassified_changes),
        "decision_age_ms": decision_age_ms,
        "max_decision_age_ms": max_decision_age_ms,
        "reasons": sorted(set(reasons)),
        "prior_decision_preserved_as_history": True,
        "binding_authority_granted": False,
        "physical_action_executed": False,
        "commit_revalidation_performed": True,
    }
