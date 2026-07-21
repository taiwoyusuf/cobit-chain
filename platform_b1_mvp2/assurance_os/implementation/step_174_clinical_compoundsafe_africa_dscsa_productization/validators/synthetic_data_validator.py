"""
Static local deterministic validator for synthetic_data_validator.

Planning assumption only. Synthetic data only.
No network, cloud, remote, production, process-execution, or hardware access.
Generated evidence is reserved for Step 174D.
"""

VALIDATOR_ID = 'synthetic_data_validator'
PLANNING_ASSUMPTION = True
SYNTHETIC_ONLY = True
NETWORK_ALLOWED = False
CLOUD_ALLOWED = False
REMOTE_SYSTEM_ALLOWED = False
PRODUCTION_DATA_ALLOWED = False
PROCESS_EXECUTION_ALLOWED = False
HARDWARE_ALLOWED = False

EXPECTED_OUTCOMES = (
    "ALLOW",
    "HOLD",
    "NO-BIND",
    "DENY",
    "FAIL-CLOSED",
)

EXPECTED_PRECEDENCE = (
    "DENY",
    "FAIL-CLOSED",
    "NO-BIND",
    "HOLD",
    "ALLOW",
)

RAMAT_ALLOWED = (
    "display",
    "witness",
    "request",
    "review",
)

RAMAT_PROHIBITED = (
    "approve",
    "release",
    "override",
    "write_back",
    "reconcile_source_states",
    "resolve_holds",
    "bind_regulated_action",
    "replace_official_record",
    "replace_accountable_human",
)


def validator_metadata():
    return {
        "validator_id": VALIDATOR_ID,
        "planning_assumption": PLANNING_ASSUMPTION,
        "synthetic_only": SYNTHETIC_ONLY,
        "network_allowed": NETWORK_ALLOWED,
        "cloud_allowed": CLOUD_ALLOWED,
        "remote_system_allowed": REMOTE_SYSTEM_ALLOWED,
        "production_data_allowed": PRODUCTION_DATA_ALLOWED,
        "process_execution_allowed": PROCESS_EXECUTION_ALLOWED,
        "hardware_allowed": HARDWARE_ALLOWED,
        "generated_evidence_step": "174D",
    }


def validate(document, context=None):
    errors = []

    if not isinstance(document, dict):
        return {
            "validator_id": VALIDATOR_ID,
            "valid": False,
            "errors": ("document_must_be_mapping",),
        }

    if document.get("planning_assumption") is not True:
        errors.append("planning_assumption_required")

    if document.get("synthetic_only") is not True:
        errors.append("synthetic_only_required")

    decision_outcomes = document.get("decision_outcomes")

    if decision_outcomes is not None:
        if tuple(decision_outcomes) != EXPECTED_OUTCOMES:
            errors.append("decision_outcomes_changed")

    decision_precedence = document.get("decision_precedence")

    if decision_precedence is not None:
        if tuple(decision_precedence) != EXPECTED_PRECEDENCE:
            errors.append("decision_precedence_changed")

    ramat_vision = document.get("ramat_vision")

    if isinstance(ramat_vision, dict):
        allowed = tuple(
            ramat_vision.get("allowed_functions", ())
        )

        prohibited = tuple(
            ramat_vision.get("prohibited_actions", ())
        )

        if allowed and allowed != RAMAT_ALLOWED:
            errors.append("ramat_allowed_functions_changed")

        if prohibited and prohibited != RAMAT_PROHIBITED:
            errors.append("ramat_prohibited_actions_changed")

        if ramat_vision.get("binding_authority") is True:
            errors.append("ramat_binding_authority_prohibited")

    if document.get("official_records") == "replaced":
        errors.append("official_record_replacement_prohibited")

    if document.get("accountable_human_replaced") is True:
        errors.append("accountable_human_replacement_prohibited")

    return {
        "validator_id": VALIDATOR_ID,
        "valid": not errors,
        "errors": tuple(errors),
        "context_used": context is not None,
    }
