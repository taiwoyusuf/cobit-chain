"""Step 189 — Accountability Continuity Execution Outcome Non-Bypass R1.

This bounded composition layer binds frozen Step 188 accountability-aware atomic
commit prerequisites to existing Step 182 commit/execution/outcome correspondence.

It reproduces Step 182 from the exact supplied input bundle and requires that the
Step 181 prior-commit result consumed by Step 182 is the exact result already bound
inside the Step 188 atomic binding record.

It does not replace Steps 188 or 182, grant authority, authorize commit/execution,
prove token consumption, execute physical action, authorize outcome disposition,
or modify IRLT-MAG.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping


SUPPORTABLE = "ACCOUNTABILITY_EXECUTION_OUTCOME_BINDING_SUPPORTABLE"
NOT_ESTABLISHED = "ACCOUNTABILITY_EXECUTION_OUTCOME_BINDING_NOT_ESTABLISHED"

STEP188_STANDING = "ACCOUNTABILITY_ATOMIC_COMMIT_BINDING_SUPPORTABLE"
STEP188_DECISION = "ACCOUNTABILITY_ATOMIC_COMMIT_PREREQUISITES_SUPPORTABLE"
STEP188_NO_BIND = "SEPARATE_AUTHORIZED_COMMIT_EXECUTION_AND_TOKEN_CONSUMPTION_REQUIRED"

STEP188_EVALUATOR_BLOB = "e75ef018802c7ca2370fd54ee9864709c50a81d7"
STEP188_TEST_BLOB = "1946c4763ecdf0a56e2ed8cc998308aefdac803f"
STEP182_EVALUATOR_BLOB = "b2c999b9dd5f3528a851646871dafc08d8bda5a3"
STEP182_TEST_BLOB = "4acf9a219278b7a31c55df8ab78e916405d71741"


def _valid_nonempty(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def canonical_payload_digest(record: Mapping[str, object]) -> str | None:
    """Reproduce Step 188 canonical payload digest shape."""
    try:
        payload = json.dumps(dict(record), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError):
        return None
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _step182_base_result(
    *,
    standing: str,
    reasons: list[str],
    commit_occurred=None,
    execution_succeeded=None,
    intended_outcome_established=None,
    no_bind_state: str = "ACTIVE",
) -> dict[str, object]:
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


def _step182_mismatches(record: dict, expected: dict, fields: tuple[str, ...], prefix: str) -> list[str]:
    reasons: list[str] = []
    for field in fields:
        expected_value = expected.get(field)
        if expected_value is not None and record.get(field) != expected_value:
            reasons.append(f"{prefix}_{field.upper()}_MISMATCH")
    return reasons


def reproduce_step182(
    *,
    prior_commit_result: dict,
    commit_receipt: dict | None,
    execution_receipt: dict | None,
    outcome_evidence: dict | None,
    expected: dict,
) -> dict[str, object]:
    """Exact bounded reproduction of frozen-ancestry Step 182 semantics."""
    required_expected = ("action_id", "transaction_id", "object_hash")
    missing_expected = [
        f"EXPECTED_{field.upper()}_MISSING" for field in required_expected if not expected.get(field)
    ]
    if missing_expected:
        return _step182_base_result(standing="CORRESPONDENCE_BASIS_INCOMPLETE", reasons=missing_expected)

    if (
        not isinstance(prior_commit_result, dict)
        or prior_commit_result.get("commit_decision") != "COMMIT_ROUTE_ADMISSIBLE"
        or prior_commit_result.get("atomic_commit_standing") != "SUPPORTABLE"
        or prior_commit_result.get("no_bind_state") != "INACTIVE"
    ):
        return _step182_base_result(
            standing="PRIOR_COMMIT_ROUTE_NOT_ADMISSIBLE",
            reasons=["STEP181_COMMIT_ROUTE_NOT_SUPPORTABLE"],
        )

    if not isinstance(commit_receipt, dict):
        return _step182_base_result(standing="COMMIT_NOT_ESTABLISHED", reasons=["COMMIT_RECEIPT_NOT_PRESENT"])

    commit_reasons = _step182_mismatches(
        commit_receipt, expected, ("transaction_id", "object_hash"), "COMMIT_RECEIPT"
    )
    if commit_reasons:
        return _step182_base_result(standing="COMMIT_CORRESPONDENCE_MISMATCH", reasons=commit_reasons)

    if commit_receipt.get("commit_status") != "COMMITTED":
        return _step182_base_result(
            standing="COMMIT_NOT_ESTABLISHED",
            reasons=["COMMIT_STATUS_NOT_COMMITTED"],
            commit_occurred=False if commit_receipt.get("commit_status") == "FAILED" else None,
        )

    if not isinstance(execution_receipt, dict):
        return _step182_base_result(
            standing="COMMITTED_EXECUTION_NOT_ESTABLISHED",
            reasons=["EXECUTION_RECEIPT_NOT_PRESENT"],
            commit_occurred=True,
        )

    execution_reasons = _step182_mismatches(
        execution_receipt,
        expected,
        ("action_id", "transaction_id", "object_hash", "target", "destination"),
        "EXECUTION_RECEIPT",
    )
    if execution_reasons:
        return _step182_base_result(
            standing="EXECUTION_CORRESPONDENCE_MISMATCH",
            reasons=execution_reasons,
            commit_occurred=True,
        )

    execution_status = execution_receipt.get("execution_status")
    if execution_status == "FAILED":
        return _step182_base_result(
            standing="COMMITTED_EXECUTION_FAILED",
            reasons=["EXECUTION_EXPLICITLY_FAILED"],
            commit_occurred=True,
            execution_succeeded=False,
        )
    if execution_status != "SUCCEEDED":
        return _step182_base_result(
            standing="COMMITTED_EXECUTION_NOT_ESTABLISHED",
            reasons=["EXECUTION_SUCCESS_NOT_ESTABLISHED"],
            commit_occurred=True,
        )

    if not isinstance(outcome_evidence, dict):
        return _step182_base_result(
            standing="EXECUTED_OUTCOME_NOT_ESTABLISHED",
            reasons=["OUTCOME_EVIDENCE_NOT_PRESENT"],
            commit_occurred=True,
            execution_succeeded=True,
        )

    outcome_reasons = _step182_mismatches(
        outcome_evidence,
        expected,
        ("action_id", "transaction_id", "object_hash", "target", "destination"),
        "OUTCOME_EVIDENCE",
    )
    if outcome_reasons:
        return _step182_base_result(
            standing="OUTCOME_CORRESPONDENCE_MISMATCH",
            reasons=outcome_reasons,
            commit_occurred=True,
            execution_succeeded=True,
        )

    if outcome_evidence.get("outcome_status") != "OBSERVED":
        return _step182_base_result(
            standing="EXECUTED_OUTCOME_NOT_ESTABLISHED",
            reasons=["OBSERVED_OUTCOME_NOT_ESTABLISHED"],
            commit_occurred=True,
            execution_succeeded=True,
        )

    expected_outcome = expected.get("intended_outcome")
    if expected_outcome is None:
        return _step182_base_result(
            standing="CORRESPONDENCE_BASIS_INCOMPLETE",
            reasons=["EXPECTED_INTENDED_OUTCOME_MISSING"],
            commit_occurred=True,
            execution_succeeded=True,
        )

    if outcome_evidence.get("observed_outcome") != expected_outcome:
        return _step182_base_result(
            standing="OUTCOME_DIVERGED",
            reasons=["OBSERVED_OUTCOME_DIFFERS_FROM_INTENDED_OUTCOME"],
            commit_occurred=True,
            execution_succeeded=True,
            intended_outcome_established=False,
        )

    return _step182_base_result(
        standing="OUTCOME_CORRESPONDENCE_SUPPORTABLE",
        reasons=[],
        commit_occurred=True,
        execution_succeeded=True,
        intended_outcome_established=True,
        no_bind_state="INACTIVE",
    )


def evaluate_accountability_execution_outcome_nonbypass(
    *,
    step188_result: Mapping[str, object],
    step188_atomic_binding_record: Mapping[str, object],
    step182_result: Mapping[str, object],
    step182_prior_commit_result: Mapping[str, object],
    commit_receipt: Mapping[str, object],
    execution_receipt: Mapping[str, object],
    outcome_evidence: Mapping[str, object],
    step182_expected: Mapping[str, object],
    outcome_binding_record: Mapping[str, object],
    expected_scope_id: str,
    expected_action_id: str,
    expected_object_hash: str,
    expected_transaction_id: str,
    expected_commit_nonce: str,
    caller_requested_outcome: str,
) -> dict[str, object]:
    """Fail closed unless the supportable Step 182 outcome is bound to frozen Step 188."""
    reasons: list[str] = []

    for name, value in (
        ("EXPECTED_SCOPE_ID", expected_scope_id),
        ("EXPECTED_ACTION_ID", expected_action_id),
        ("EXPECTED_OBJECT_HASH", expected_object_hash),
        ("EXPECTED_TRANSACTION_ID", expected_transaction_id),
        ("EXPECTED_COMMIT_NONCE", expected_commit_nonce),
    ):
        if not _valid_nonempty(value):
            reasons.append(name + "_MISSING_OR_INVALID")

    scope = expected_scope_id.strip() if _valid_nonempty(expected_scope_id) else None
    action = expected_action_id.strip() if _valid_nonempty(expected_action_id) else None
    obj = expected_object_hash.strip() if _valid_nonempty(expected_object_hash) else None
    transaction = expected_transaction_id.strip() if _valid_nonempty(expected_transaction_id) else None
    nonce = expected_commit_nonce.strip() if _valid_nonempty(expected_commit_nonce) else None

    # Frozen Step 188 favorable result contract.
    if not isinstance(step188_result, Mapping):
        reasons.append("STEP_188_RESULT_MISSING_OR_INVALID")
    else:
        checks = (
            (step188_result.get("integration_revision") == "STEP_188_R1", "STEP_188_REVISION_NOT_ESTABLISHED"),
            (step188_result.get("atomic_accountability_standing") == STEP188_STANDING, "STEP_188_STANDING_NOT_SUPPORTABLE"),
            (step188_result.get("atomic_accountability_decision") == STEP188_DECISION, "STEP_188_DECISION_NOT_SUPPORTABLE"),
            (step188_result.get("no_bind_state") == STEP188_NO_BIND, "STEP_188_NO_BIND_CONTRACT_INVALID"),
            (step188_result.get("action_held") is False, "STEP_188_ACTION_HOLD_NOT_CLEARED"),
            (step188_result.get("step_187_result_consumed") is True, "STEP_188_STEP_187_RESULT_CONSUMPTION_NOT_ESTABLISHED"),
            (step188_result.get("step_187_binding_record_consumed") is True, "STEP_188_STEP_187_BINDING_CONSUMPTION_NOT_ESTABLISHED"),
            (step188_result.get("step_187_current_snapshot_consumed") is True, "STEP_188_STEP_187_SNAPSHOT_CONSUMPTION_NOT_ESTABLISHED"),
            (step188_result.get("step_181_token_consumed_as_evidence") is True, "STEP_188_STEP_181_TOKEN_EVIDENCE_NOT_ESTABLISHED"),
            (step188_result.get("step_181_commit_result_consumed") is True, "STEP_188_STEP_181_RESULT_CONSUMPTION_NOT_ESTABLISHED"),
            (step188_result.get("commit_snapshot_consumed") is True, "STEP_188_COMMIT_SNAPSHOT_CONSUMPTION_NOT_ESTABLISHED"),
            (step188_result.get("step_181_commit_result_reproduced") is True, "STEP_188_STEP_181_REPRODUCTION_NOT_ESTABLISHED"),
            (step188_result.get("cross_snapshot_state_equality_checked") is True, "STEP_188_CROSS_STATE_EQUALITY_NOT_ESTABLISHED"),
            (step188_result.get("atomic_cross_binding_checked") is True, "STEP_188_ATOMIC_CROSS_BINDING_NOT_ESTABLISHED"),
            (step188_result.get("source_identity_checked") is True, "STEP_188_SOURCE_IDENTITY_NOT_ESTABLISHED"),
            (step188_result.get("payload_digest_binding_checked") is True, "STEP_188_PAYLOAD_BINDING_NOT_ESTABLISHED"),
            (step188_result.get("atomic_temporal_currentness_checked") is True, "STEP_188_TEMPORAL_CURRENTNESS_NOT_ESTABLISHED"),
            (step188_result.get("token_consumption_required_on_authorized_commit") is True, "STEP_188_TOKEN_CONSUMPTION_REQUIREMENT_NOT_ESTABLISHED"),
            (step188_result.get("binding_provenance_manufactured") is False, "STEP_188_PROVENANCE_BOUNDARY_INVALID"),
            (step188_result.get("binding_authority_granted") is False, "STEP_188_AUTHORITY_BOUNDARY_INVALID"),
            (step188_result.get("action_admissibility_granted") is False, "STEP_188_ADMISSIBILITY_BOUNDARY_INVALID"),
            (step188_result.get("commit_authorized") is False, "STEP_188_COMMIT_BOUNDARY_INVALID"),
            (step188_result.get("execution_authorized") is False, "STEP_188_EXECUTION_BOUNDARY_INVALID"),
            (step188_result.get("commit_token_consumed_by_evaluator") is False, "STEP_188_TOKEN_CONSUMPTION_BOUNDARY_INVALID"),
            (step188_result.get("physical_action_executed") is False, "STEP_188_PHYSICAL_ACTION_BOUNDARY_INVALID"),
            (step188_result.get("regulated_release_or_disposition_authorized") is False, "STEP_188_RELEASE_BOUNDARY_INVALID"),
            (step188_result.get("historical_facts_rewritten") is False, "STEP_188_HISTORY_BOUNDARY_INVALID"),
            (step188_result.get("irlt_mag_state_changed") is False, "STEP_188_IRLT_BOUNDARY_INVALID"),
        )
        for ok, reason in checks:
            if not ok:
                reasons.append(reason)
        if type(step188_result.get("reasons")) is not list or step188_result.get("reasons"):
            reasons.append("STEP_188_SUPPORTABLE_RESULT_REASONS_INVALID")
        for field, expected_value, reason in (
            ("expected_scope_id", scope, "STEP_188_SCOPE_MISMATCH"),
            ("expected_action_id", action, "STEP_188_ACTION_MISMATCH"),
            ("expected_object_hash", obj, "STEP_188_OBJECT_MISMATCH"),
            ("expected_transaction_id", transaction, "STEP_188_TRANSACTION_MISMATCH"),
            ("expected_commit_nonce", nonce, "STEP_188_NONCE_MISMATCH"),
        ):
            if expected_value is not None and step188_result.get(field) != expected_value:
                reasons.append(reason)

    # Exact Step 188 atomic binding record, including currentness and upstream Step 181 result digest.
    if not isinstance(step188_atomic_binding_record, Mapping):
        reasons.append("STEP_188_ATOMIC_BINDING_RECORD_MISSING_OR_INVALID")
    else:
        for field in (
            "declared_scope_id",
            "action_id",
            "object_hash",
            "transaction_id",
            "commit_nonce",
            "commit_point_id",
            "binding_evidence_ref",
            "binding_basis_version",
            "step187_result_digest",
            "step187_commit_binding_record_digest",
            "step187_current_snapshot_digest",
            "step181_token_digest",
            "step181_commit_result_digest",
            "commit_snapshot_digest",
            "step181_verification_input_digest",
            "step187_evaluator_blob",
            "step187_primary_test_blob",
            "step187_hardening_test_blob",
            "step181_evaluator_blob",
            "step181_test_blob",
        ):
            if not _valid_nonempty(step188_atomic_binding_record.get(field)):
                reasons.append("STEP_188_BINDING_" + field.upper() + "_MISSING_OR_INVALID")

        for field, expected_value, reason in (
            ("declared_scope_id", scope, "STEP_188_BINDING_SCOPE_MISMATCH"),
            ("action_id", action, "STEP_188_BINDING_ACTION_MISMATCH"),
            ("object_hash", obj, "STEP_188_BINDING_OBJECT_MISMATCH"),
            ("transaction_id", transaction, "STEP_188_BINDING_TRANSACTION_MISMATCH"),
            ("commit_nonce", nonce, "STEP_188_BINDING_NONCE_MISMATCH"),
        ):
            if expected_value is not None and step188_atomic_binding_record.get(field) != expected_value:
                reasons.append(reason)

        if step188_atomic_binding_record.get("binding_traceable") is not True:
            reasons.append("STEP_188_BINDING_NOT_TRACEABLE")
        if step188_atomic_binding_record.get("binding_current") is not True:
            reasons.append("STEP_188_BINDING_NOT_CURRENT")
        if step188_atomic_binding_record.get("binding_ambiguity_present") is not False:
            reasons.append("STEP_188_BINDING_AMBIGUOUS_OR_INVALID")
        if step188_atomic_binding_record.get("binding_temporal_ordering_established") is not True:
            reasons.append("STEP_188_BINDING_TEMPORAL_ORDERING_NOT_ESTABLISHED")
        if step188_atomic_binding_record.get("binding_change_assessment_complete") is not True:
            reasons.append("STEP_188_BINDING_CHANGE_ASSESSMENT_INCOMPLETE")
        material_change = step188_atomic_binding_record.get("material_change_after_atomic_binding")
        revalidated = step188_atomic_binding_record.get("atomic_binding_revalidated_after_latest_material_change")
        if type(material_change) is not bool:
            reasons.append("STEP_188_BINDING_MATERIAL_CHANGE_STATE_INVALID")
        if type(revalidated) is not bool:
            reasons.append("STEP_188_BINDING_REVALIDATION_STATE_INVALID")
        if material_change is True and revalidated is not True:
            reasons.append("STEP_188_BINDING_STALE_AFTER_MATERIAL_CHANGE")

    # Step 182 exact identifiers and exact Step 181 favorable prior-commit payload.
    if not isinstance(step182_expected, Mapping):
        reasons.append("STEP_182_EXPECTED_BASIS_MISSING_OR_INVALID")
    else:
        for field, expected_value, reason in (
            ("action_id", action, "STEP_182_EXPECTED_ACTION_MISMATCH"),
            ("transaction_id", transaction, "STEP_182_EXPECTED_TRANSACTION_MISMATCH"),
            ("object_hash", obj, "STEP_182_EXPECTED_OBJECT_MISMATCH"),
        ):
            if expected_value is not None and step182_expected.get(field) != expected_value:
                reasons.append(reason)
        if not _valid_nonempty(step182_expected.get("intended_outcome")):
            reasons.append("STEP_182_EXPECTED_INTENDED_OUTCOME_MISSING_OR_INVALID")

    if not isinstance(step182_prior_commit_result, Mapping):
        reasons.append("STEP_182_PRIOR_COMMIT_RESULT_MISSING_OR_INVALID")
    else:
        prior_digest = canonical_payload_digest(step182_prior_commit_result)
        if prior_digest is None:
            reasons.append("STEP_182_PRIOR_COMMIT_RESULT_DIGEST_NOT_COMPUTABLE")
        elif isinstance(step188_atomic_binding_record, Mapping) and step188_atomic_binding_record.get("step181_commit_result_digest") != prior_digest:
            reasons.append("STEP_182_PRIOR_COMMIT_RESULT_NOT_BOUND_TO_STEP_188")

    # Reproduce Step 182 from the exact input bundle. Do not trust a favorable-shaped result alone.
    reproduced_step182_result: dict[str, object] | None = None
    if all(
        isinstance(value, Mapping)
        for value in (
            step182_prior_commit_result,
            commit_receipt,
            execution_receipt,
            outcome_evidence,
            step182_expected,
        )
    ):
        reproduced_step182_result = reproduce_step182(
            prior_commit_result=dict(step182_prior_commit_result),
            commit_receipt=dict(commit_receipt),
            execution_receipt=dict(execution_receipt),
            outcome_evidence=dict(outcome_evidence),
            expected=dict(step182_expected),
        )
    else:
        reasons.append("STEP_182_EXACT_INPUT_BUNDLE_MISSING_OR_INVALID")

    if not isinstance(step182_result, Mapping):
        reasons.append("STEP_182_RESULT_MISSING_OR_INVALID")
    else:
        if reproduced_step182_result is None or dict(step182_result) != reproduced_step182_result:
            reasons.append("STEP_182_RESULT_NOT_REPRODUCIBLE_FROM_EXACT_INPUTS")
        checks = (
            (step182_result.get("correspondence_standing") == "OUTCOME_CORRESPONDENCE_SUPPORTABLE", "STEP_182_OUTCOME_CORRESPONDENCE_NOT_SUPPORTABLE"),
            (step182_result.get("commit_occurred") is True, "STEP_182_COMMIT_FACT_NOT_ESTABLISHED"),
            (step182_result.get("execution_succeeded") is True, "STEP_182_EXECUTION_SUCCESS_NOT_ESTABLISHED"),
            (step182_result.get("intended_outcome_established") is True, "STEP_182_INTENDED_OUTCOME_NOT_ESTABLISHED"),
            (step182_result.get("no_bind_state") == "INACTIVE", "STEP_182_NO_BIND_ACTIVE_OR_INVALID"),
            (step182_result.get("binding_authority_granted") is False, "STEP_182_AUTHORITY_BOUNDARY_INVALID"),
            (step182_result.get("physical_action_executed_by_evaluator") is False, "STEP_182_PHYSICAL_ACTION_BOUNDARY_INVALID"),
            (step182_result.get("causal_attribution_established") is False, "STEP_182_CAUSAL_ATTRIBUTION_BOUNDARY_INVALID"),
        )
        for ok, reason in checks:
            if not ok:
                reasons.append(reason)
        if type(step182_result.get("reasons")) is not list or step182_result.get("reasons"):
            reasons.append("STEP_182_SUPPORTABLE_RESULT_REASONS_INVALID")

    # Explicit Step 189 cross-control binding evidence.
    if not isinstance(outcome_binding_record, Mapping):
        reasons.append("OUTCOME_BINDING_RECORD_MISSING_OR_INVALID")
    else:
        for field in (
            "declared_scope_id",
            "action_id",
            "object_hash",
            "transaction_id",
            "commit_nonce",
            "outcome_binding_point_id",
            "outcome_binding_evidence_ref",
            "outcome_binding_basis_version",
            "step188_result_digest",
            "step188_atomic_binding_record_digest",
            "step182_result_digest",
            "step182_prior_commit_result_digest",
            "commit_receipt_digest",
            "execution_receipt_digest",
            "outcome_evidence_digest",
            "step182_expected_digest",
            "step188_evaluator_blob",
            "step188_test_blob",
            "step182_evaluator_blob",
            "step182_test_blob",
        ):
            if not _valid_nonempty(outcome_binding_record.get(field)):
                reasons.append("OUTCOME_BINDING_" + field.upper() + "_MISSING_OR_INVALID")

        for field, expected_value, reason in (
            ("declared_scope_id", scope, "OUTCOME_BINDING_SCOPE_MISMATCH"),
            ("action_id", action, "OUTCOME_BINDING_ACTION_MISMATCH"),
            ("object_hash", obj, "OUTCOME_BINDING_OBJECT_MISMATCH"),
            ("transaction_id", transaction, "OUTCOME_BINDING_TRANSACTION_MISMATCH"),
            ("commit_nonce", nonce, "OUTCOME_BINDING_NONCE_MISMATCH"),
        ):
            if expected_value is not None and outcome_binding_record.get(field) != expected_value:
                reasons.append(reason)

        source_checks = (
            ("step188_evaluator_blob", STEP188_EVALUATOR_BLOB, "OUTCOME_BINDING_STEP_188_EVALUATOR_SOURCE_MISMATCH"),
            ("step188_test_blob", STEP188_TEST_BLOB, "OUTCOME_BINDING_STEP_188_TEST_SOURCE_MISMATCH"),
            ("step182_evaluator_blob", STEP182_EVALUATOR_BLOB, "OUTCOME_BINDING_STEP_182_EVALUATOR_SOURCE_MISMATCH"),
            ("step182_test_blob", STEP182_TEST_BLOB, "OUTCOME_BINDING_STEP_182_TEST_SOURCE_MISMATCH"),
        )
        for field, expected_value, reason in source_checks:
            if outcome_binding_record.get(field) != expected_value:
                reasons.append(reason)

        digest_inputs = (
            ("step188_result_digest", step188_result, "STEP_188_RESULT_DIGEST_NOT_COMPUTABLE", "OUTCOME_BINDING_STEP_188_RESULT_DIGEST_MISMATCH"),
            ("step188_atomic_binding_record_digest", step188_atomic_binding_record, "STEP_188_BINDING_DIGEST_NOT_COMPUTABLE", "OUTCOME_BINDING_STEP_188_BINDING_DIGEST_MISMATCH"),
            ("step182_result_digest", step182_result, "STEP_182_RESULT_DIGEST_NOT_COMPUTABLE", "OUTCOME_BINDING_STEP_182_RESULT_DIGEST_MISMATCH"),
            ("step182_prior_commit_result_digest", step182_prior_commit_result, "STEP_182_PRIOR_DIGEST_NOT_COMPUTABLE", "OUTCOME_BINDING_STEP_182_PRIOR_DIGEST_MISMATCH"),
            ("commit_receipt_digest", commit_receipt, "COMMIT_RECEIPT_DIGEST_NOT_COMPUTABLE", "OUTCOME_BINDING_COMMIT_RECEIPT_DIGEST_MISMATCH"),
            ("execution_receipt_digest", execution_receipt, "EXECUTION_RECEIPT_DIGEST_NOT_COMPUTABLE", "OUTCOME_BINDING_EXECUTION_RECEIPT_DIGEST_MISMATCH"),
            ("outcome_evidence_digest", outcome_evidence, "OUTCOME_EVIDENCE_DIGEST_NOT_COMPUTABLE", "OUTCOME_BINDING_OUTCOME_EVIDENCE_DIGEST_MISMATCH"),
            ("step182_expected_digest", step182_expected, "STEP_182_EXPECTED_DIGEST_NOT_COMPUTABLE", "OUTCOME_BINDING_STEP_182_EXPECTED_DIGEST_MISMATCH"),
        )
        for field, payload, not_computable, mismatch in digest_inputs:
            if isinstance(payload, Mapping):
                digest = canonical_payload_digest(payload)
                if digest is None:
                    reasons.append(not_computable)
                elif outcome_binding_record.get(field) != digest:
                    reasons.append(mismatch)
            else:
                reasons.append(not_computable)

        if outcome_binding_record.get("binding_traceable") is not True:
            reasons.append("OUTCOME_BINDING_NOT_TRACEABLE")
        if outcome_binding_record.get("binding_current") is not True:
            reasons.append("OUTCOME_BINDING_NOT_CURRENT")
        if outcome_binding_record.get("binding_ambiguity_present") is not False:
            reasons.append("OUTCOME_BINDING_AMBIGUOUS_OR_INVALID")
        if outcome_binding_record.get("binding_temporal_ordering_established") is not True:
            reasons.append("OUTCOME_BINDING_TEMPORAL_ORDERING_NOT_ESTABLISHED")
        if outcome_binding_record.get("binding_change_assessment_complete") is not True:
            reasons.append("OUTCOME_BINDING_CHANGE_ASSESSMENT_INCOMPLETE")
        material_change = outcome_binding_record.get("material_change_after_outcome_binding")
        revalidated = outcome_binding_record.get("outcome_binding_revalidated_after_latest_material_change")
        if type(material_change) is not bool:
            reasons.append("OUTCOME_BINDING_MATERIAL_CHANGE_STATE_INVALID")
        if type(revalidated) is not bool:
            reasons.append("OUTCOME_BINDING_REVALIDATION_STATE_INVALID")
        if material_change is True and revalidated is not True:
            reasons.append("OUTCOME_BINDING_STALE_AFTER_MATERIAL_CHANGE")

    blocked = bool(reasons)
    if blocked and caller_requested_outcome in {
        "RELY",
        "CLOSE",
        "RELEASE",
        "EXECUTE",
        "ADMISSIBLE",
        "OUTCOME_ESTABLISHED",
    }:
        reasons.append("CALLER_OVERRIDE_REJECTED")

    return {
        "integration_revision": "STEP_189_R1",
        "accountability_outcome_standing": NOT_ESTABLISHED if blocked else SUPPORTABLE,
        "accountability_outcome_decision": "NOT_SUPPORTABLE" if blocked else "ACCOUNTABILITY_OUTCOME_CORRESPONDENCE_PREREQUISITES_SUPPORTABLE",
        "no_bind_state": "ACTIVE" if blocked else "SEPARATE_AUTHORIZED_OUTCOME_DISPOSITION_REQUIRED",
        "action_held": blocked,
        "caller_requested_outcome": caller_requested_outcome,
        "expected_scope_id": expected_scope_id,
        "expected_action_id": expected_action_id,
        "expected_object_hash": expected_object_hash,
        "expected_transaction_id": expected_transaction_id,
        "expected_commit_nonce": expected_commit_nonce,
        "reasons": sorted(set(reasons)),
        "step_188_result_consumed": True,
        "step_188_atomic_binding_record_consumed": True,
        "step_182_result_consumed": True,
        "step_182_exact_input_bundle_consumed": True,
        "step_182_result_reproduced": reproduced_step182_result is not None,
        "step_181_prior_commit_cross_binding_checked": True,
        "outcome_cross_binding_checked": True,
        "source_identity_checked": True,
        "payload_digest_binding_checked": True,
        "outcome_temporal_currentness_checked": True,
        "commit_occurred_historical_fact": step182_result.get("commit_occurred") if isinstance(step182_result, Mapping) else None,
        "execution_succeeded_historical_fact": step182_result.get("execution_succeeded") if isinstance(step182_result, Mapping) else None,
        "intended_outcome_established_as_evidence": step182_result.get("intended_outcome_established") if isinstance(step182_result, Mapping) else None,
        "token_consumption_required_by_step_188": True,
        "token_consumption_proven_by_step_189": False,
        "binding_provenance_manufactured": False,
        "binding_authority_granted": False,
        "action_admissibility_granted": False,
        "commit_authorized": False,
        "execution_authorized": False,
        "outcome_disposition_authorized": False,
        "commit_token_consumed_by_evaluator": False,
        "physical_action_executed": False,
        "regulated_release_or_disposition_authorized": False,
        "causal_attribution_established": False,
        "historical_facts_rewritten": False,
        "irlt_mag_state_changed": False,
    }
