"""Step 182 commit / execution / outcome correspondence.

This bounded evaluator distinguishes an admissible commit route from evidence that
a commit occurred, execution succeeded, and the intended outcome was established.
It does not execute regulated or physical actions and does not grant authority.
"""


def _base_result(*, standing: str, reasons: list[str], commit_occurred=None,
                 execution_succeeded=None, intended_outcome_established=None,
                 no_bind_state: str = "ACTIVE") -> dict:
    return {
        "correspondence_standing": standing,
        "commit_occurred": commit_occurred,
        "execution_succeeded": execution_succeeded,
        "intended_outcome_established": intended_outcome_established,
        "historical_facts": {
            "commit_occurred": commit_occurred,
            "execution_succeeded": execution_succeeded,
        },
        "no_bind_state": no_bind_state,
        "reasons": sorted(set(reasons)),
        "binding_authority_granted": False,
        "physical_action_executed_by_evaluator": False,
        "causal_attribution_established": False,
    }


def _mismatches(record: dict, expected: dict, fields: tuple[str, ...], prefix: str) -> list[str]:
    reasons = []
    for field in fields:
        expected_value = expected.get(field)
        if expected_value is not None and record.get(field) != expected_value:
            reasons.append(f"{prefix}_{field.upper()}_MISMATCH")
    return reasons


def evaluate_commit_execution_outcome_correspondence(
        *, prior_commit_result: dict, commit_receipt: dict | None,
        execution_receipt: dict | None, outcome_evidence: dict | None,
        expected: dict) -> dict:
    """Evaluate staged evidence without inferring later-stage success from silence.

    `expected` carries the bounded identifiers and intended outcome against which
    caller-supplied records are compared. A later-stage failure or uncertainty does
    not rewrite an already-established earlier historical fact.
    """
    required_expected = ("action_id", "transaction_id", "object_hash")
    missing_expected = [f"EXPECTED_{field.upper()}_MISSING"
                        for field in required_expected if not expected.get(field)]
    if missing_expected:
        return _base_result(
            standing="CORRESPONDENCE_BASIS_INCOMPLETE",
            reasons=missing_expected,
        )

    if (not isinstance(prior_commit_result, dict)
            or prior_commit_result.get("commit_decision") != "COMMIT_ROUTE_ADMISSIBLE"
            or prior_commit_result.get("atomic_commit_standing") != "SUPPORTABLE"
            or prior_commit_result.get("no_bind_state") != "INACTIVE"):
        return _base_result(
            standing="PRIOR_COMMIT_ROUTE_NOT_ADMISSIBLE",
            reasons=["STEP181_COMMIT_ROUTE_NOT_SUPPORTABLE"],
        )

    if not isinstance(commit_receipt, dict):
        return _base_result(
            standing="COMMIT_NOT_ESTABLISHED",
            reasons=["COMMIT_RECEIPT_NOT_PRESENT"],
        )

    commit_reasons = _mismatches(
        commit_receipt, expected, ("transaction_id", "object_hash"), "COMMIT_RECEIPT")
    if commit_reasons:
        return _base_result(
            standing="COMMIT_CORRESPONDENCE_MISMATCH",
            reasons=commit_reasons,
        )

    if commit_receipt.get("commit_status") != "COMMITTED":
        return _base_result(
            standing="COMMIT_NOT_ESTABLISHED",
            reasons=["COMMIT_STATUS_NOT_COMMITTED"],
            commit_occurred=False if commit_receipt.get("commit_status") == "FAILED" else None,
        )

    # At this point the supplied receipt supports the bounded historical commit fact.
    if not isinstance(execution_receipt, dict):
        return _base_result(
            standing="COMMITTED_EXECUTION_NOT_ESTABLISHED",
            reasons=["EXECUTION_RECEIPT_NOT_PRESENT"],
            commit_occurred=True,
        )

    execution_reasons = _mismatches(
        execution_receipt, expected,
        ("action_id", "transaction_id", "object_hash", "target", "destination"),
        "EXECUTION_RECEIPT")
    if execution_reasons:
        return _base_result(
            standing="EXECUTION_CORRESPONDENCE_MISMATCH",
            reasons=execution_reasons,
            commit_occurred=True,
        )

    execution_status = execution_receipt.get("execution_status")
    if execution_status == "FAILED":
        return _base_result(
            standing="COMMITTED_EXECUTION_FAILED",
            reasons=["EXECUTION_EXPLICITLY_FAILED"],
            commit_occurred=True,
            execution_succeeded=False,
        )
    if execution_status != "SUCCEEDED":
        return _base_result(
            standing="COMMITTED_EXECUTION_NOT_ESTABLISHED",
            reasons=["EXECUTION_SUCCESS_NOT_ESTABLISHED"],
            commit_occurred=True,
        )

    # Execution success is now a preserved historical fact even if outcome is absent
    # or later found to have diverged.
    if not isinstance(outcome_evidence, dict):
        return _base_result(
            standing="EXECUTED_OUTCOME_NOT_ESTABLISHED",
            reasons=["OUTCOME_EVIDENCE_NOT_PRESENT"],
            commit_occurred=True,
            execution_succeeded=True,
        )

    outcome_reasons = _mismatches(
        outcome_evidence, expected,
        ("action_id", "transaction_id", "object_hash", "target", "destination"),
        "OUTCOME_EVIDENCE")
    if outcome_reasons:
        return _base_result(
            standing="OUTCOME_CORRESPONDENCE_MISMATCH",
            reasons=outcome_reasons,
            commit_occurred=True,
            execution_succeeded=True,
        )

    if outcome_evidence.get("outcome_status") != "OBSERVED":
        return _base_result(
            standing="EXECUTED_OUTCOME_NOT_ESTABLISHED",
            reasons=["OBSERVED_OUTCOME_NOT_ESTABLISHED"],
            commit_occurred=True,
            execution_succeeded=True,
        )

    expected_outcome = expected.get("intended_outcome")
    if expected_outcome is None:
        return _base_result(
            standing="CORRESPONDENCE_BASIS_INCOMPLETE",
            reasons=["EXPECTED_INTENDED_OUTCOME_MISSING"],
            commit_occurred=True,
            execution_succeeded=True,
        )

    if outcome_evidence.get("observed_outcome") != expected_outcome:
        return _base_result(
            standing="OUTCOME_DIVERGED",
            reasons=["OBSERVED_OUTCOME_DIFFERS_FROM_INTENDED_OUTCOME"],
            commit_occurred=True,
            execution_succeeded=True,
            intended_outcome_established=False,
        )

    return _base_result(
        standing="OUTCOME_CORRESPONDENCE_SUPPORTABLE",
        reasons=[],
        commit_occurred=True,
        execution_succeeded=True,
        intended_outcome_established=True,
        no_bind_state="INACTIVE",
    )
