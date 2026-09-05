"""Step 189 — Accountability Continuity Through Commit / Execution / Outcome Non-Bypass R1.

Bounded composition of frozen Step 188 with existing Step 182. This evaluator
requires a supportable accountability-aware atomic binding and exact reproducible
Step 182 correspondence inputs before it will return a supportable through-outcome
accountability continuity prerequisite result.

It does not authorize commit/execution, consume a token, execute physical action,
create accountable authority, prove receipt authenticity, or modify IRLT-MAG.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

STEP188_EVALUATOR_BLOB = "e75ef018802c7ca2370fd54ee9864709c50a81d7"
STEP188_TEST_BLOB = "1946c4763ecdf0a56e2ed8cc998308aefdac803f"
STEP182_EVALUATOR_BLOB = "b2c999b9dd5f3528a851646871dafc08d8bda5a3"
STEP182_TEST_BLOB = "4acf9a219278b7a31c55df8ab78e916405d71741"

SUPPORTABLE = "ACCOUNTABILITY_CONTINUITY_THROUGH_OUTCOME_SUPPORTABLE"
NOT_ESTABLISHED = "ACCOUNTABILITY_CONTINUITY_THROUGH_OUTCOME_NOT_ESTABLISHED"


def _nonempty(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def canonical_digest(value: Mapping[str, object]) -> str | None:
    try:
        payload = json.dumps(dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError):
        return None
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _base(*, blocked: bool, reasons: list[str]) -> dict[str, object]:
    return {
        "integration_revision": "STEP_189_R1",
        "through_outcome_accountability_standing": NOT_ESTABLISHED if blocked else SUPPORTABLE,
        "through_outcome_decision": "NOT_SUPPORTABLE" if blocked else "ACCOUNTABILITY_OUTCOME_PREREQUISITES_SUPPORTABLE",
        "no_bind_state": "ACTIVE" if blocked else "SEPARATE_AUTHORIZED_CONSEQUENCE_OR_DISPOSITION_MECHANISM_REQUIRED",
        "action_held": blocked,
        "reasons": sorted(set(reasons)),
        "step188_result_consumed": not blocked,
        "step182_result_consumed": not blocked,
        "step182_inputs_reproduced": not blocked,
        "cross_control_identity_checked": not blocked,
        "payload_binding_checked": not blocked,
        "binding_authority_granted": False,
        "action_admissibility_granted": False,
        "commit_authorized": False,
        "execution_authorized": False,
        "commit_token_consumed_by_evaluator": False,
        "physical_action_executed": False,
        "regulated_release_or_disposition_authorized": False,
        "accountability_manufactured": False,
        "receipt_authenticity_established": False,
        "causal_attribution_established": False,
        "historical_facts_rewritten": False,
        "irlt_mag_state_changed": False,
    }


def _mismatches(record: Mapping[str, object], expected: Mapping[str, object], fields: tuple[str, ...], prefix: str) -> list[str]:
    reasons: list[str] = []
    for field in fields:
        expected_value = expected.get(field)
        if expected_value is not None and record.get(field) != expected_value:
            reasons.append(f"{prefix}_{field.upper()}_MISMATCH")
    return reasons


def reproduce_step182(
    *,
    prior_commit_result: Mapping[str, object],
    commit_receipt: Mapping[str, object] | None,
    execution_receipt: Mapping[str, object] | None,
    outcome_evidence: Mapping[str, object] | None,
    expected: Mapping[str, object],
) -> dict[str, object]:
    """Reproduce the frozen existing Step 182 evaluator semantics."""

    def result(standing: str, reasons: list[str], commit_occurred=None,
               execution_succeeded=None, intended_outcome_established=None,
               no_bind_state: str = "ACTIVE") -> dict[str, object]:
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

    required_expected = ("action_id", "transaction_id", "object_hash")
    missing = [f"EXPECTED_{f.upper()}_MISSING" for f in required_expected if not expected.get(f)]
    if missing:
        return result("CORRESPONDENCE_BASIS_INCOMPLETE", missing)

    if (prior_commit_result.get("commit_decision") != "COMMIT_ROUTE_ADMISSIBLE"
            or prior_commit_result.get("atomic_commit_standing") != "SUPPORTABLE"
            or prior_commit_result.get("no_bind_state") != "INACTIVE"):
        return result("PRIOR_COMMIT_ROUTE_NOT_ADMISSIBLE", ["STEP181_COMMIT_ROUTE_NOT_SUPPORTABLE"])

    if not isinstance(commit_receipt, Mapping):
        return result("COMMIT_NOT_ESTABLISHED", ["COMMIT_RECEIPT_NOT_PRESENT"])

    reasons = _mismatches(commit_receipt, expected, ("transaction_id", "object_hash"), "COMMIT_RECEIPT")
    if reasons:
        return result("COMMIT_CORRESPONDENCE_MISMATCH", reasons)
    if commit_receipt.get("commit_status") != "COMMITTED":
        return result("COMMIT_NOT_ESTABLISHED", ["COMMIT_STATUS_NOT_COMMITTED"],
                      commit_occurred=False if commit_receipt.get("commit_status") == "FAILED" else None)

    if not isinstance(execution_receipt, Mapping):
        return result("COMMITTED_EXECUTION_NOT_ESTABLISHED", ["EXECUTION_RECEIPT_NOT_PRESENT"], True)
    reasons = _mismatches(execution_receipt, expected,
                          ("action_id", "transaction_id", "object_hash", "target", "destination"),
                          "EXECUTION_RECEIPT")
    if reasons:
        return result("EXECUTION_CORRESPONDENCE_MISMATCH", reasons, True)
    if execution_receipt.get("execution_status") == "FAILED":
        return result("COMMITTED_EXECUTION_FAILED", ["EXECUTION_EXPLICITLY_FAILED"], True, False)
    if execution_receipt.get("execution_status") != "SUCCEEDED":
        return result("COMMITTED_EXECUTION_NOT_ESTABLISHED", ["EXECUTION_SUCCESS_NOT_ESTABLISHED"], True)

    if not isinstance(outcome_evidence, Mapping):
        return result("EXECUTED_OUTCOME_NOT_ESTABLISHED", ["OUTCOME_EVIDENCE_NOT_PRESENT"], True, True)
    reasons = _mismatches(outcome_evidence, expected,
                          ("action_id", "transaction_id", "object_hash", "target", "destination"),
                          "OUTCOME_EVIDENCE")
    if reasons:
        return result("OUTCOME_CORRESPONDENCE_MISMATCH", reasons, True, True)
    if outcome_evidence.get("outcome_status") != "OBSERVED":
        return result("EXECUTED_OUTCOME_NOT_ESTABLISHED", ["OBSERVED_OUTCOME_NOT_ESTABLISHED"], True, True)
    if expected.get("intended_outcome") is None:
        return result("CORRESPONDENCE_BASIS_INCOMPLETE", ["EXPECTED_INTENDED_OUTCOME_MISSING"], True, True)
    if outcome_evidence.get("observed_outcome") != expected.get("intended_outcome"):
        return result("OUTCOME_DIVERGED", ["OBSERVED_OUTCOME_DIFFERS_FROM_INTENDED_OUTCOME"], True, True, False)
    return result("OUTCOME_CORRESPONDENCE_SUPPORTABLE", [], True, True, True, "INACTIVE")


def evaluate_accountability_continuity_through_outcome_nonbypass(
    *,
    step188_result: Mapping[str, object],
    step182_result: Mapping[str, object],
    step181_commit_result: Mapping[str, object],
    commit_receipt: Mapping[str, object],
    execution_receipt: Mapping[str, object],
    outcome_evidence: Mapping[str, object],
    expected: Mapping[str, object],
    outcome_binding_record: Mapping[str, object],
    expected_scope_id: str,
    expected_action_id: str,
    expected_object_hash: str,
    expected_transaction_id: str,
    caller_requested_decision: str,
) -> dict[str, object]:
    reasons: list[str] = []

    for name, value in (
        ("EXPECTED_SCOPE_ID", expected_scope_id),
        ("EXPECTED_ACTION_ID", expected_action_id),
        ("EXPECTED_OBJECT_HASH", expected_object_hash),
        ("EXPECTED_TRANSACTION_ID", expected_transaction_id),
    ):
        if not _nonempty(value):
            reasons.append(name + "_MISSING_OR_INVALID")

    # Frozen Step 188 result contract.
    if not isinstance(step188_result, Mapping):
        reasons.append("STEP_188_RESULT_MISSING_OR_INVALID")
    else:
        checks = (
            (step188_result.get("integration_revision") == "STEP_188_R1", "STEP_188_REVISION_NOT_ESTABLISHED"),
            (step188_result.get("atomic_accountability_standing") == "ACCOUNTABILITY_ATOMIC_COMMIT_BINDING_SUPPORTABLE", "STEP_188_STANDING_NOT_SUPPORTABLE"),
            (step188_result.get("atomic_accountability_decision") == "ACCOUNTABILITY_ATOMIC_COMMIT_PREREQUISITES_SUPPORTABLE", "STEP_188_DECISION_NOT_SUPPORTABLE"),
            (step188_result.get("no_bind_state") == "SEPARATE_AUTHORIZED_COMMIT_EXECUTION_AND_TOKEN_CONSUMPTION_REQUIRED", "STEP_188_NO_BIND_CONTRACT_INVALID"),
            (step188_result.get("action_held") is False, "STEP_188_ACTION_HOLD_NOT_CLEARED"),
            (step188_result.get("binding_authority_granted") is False, "STEP_188_AUTHORITY_BOUNDARY_INVALID"),
            (step188_result.get("commit_authorized") is False, "STEP_188_COMMIT_BOUNDARY_INVALID"),
            (step188_result.get("execution_authorized") is False, "STEP_188_EXECUTION_BOUNDARY_INVALID"),
            (step188_result.get("commit_token_consumed_by_evaluator") is False, "STEP_188_TOKEN_BOUNDARY_INVALID"),
            (step188_result.get("physical_action_executed") is False, "STEP_188_PHYSICAL_ACTION_BOUNDARY_INVALID"),
            (step188_result.get("historical_facts_rewritten") is False, "STEP_188_HISTORY_BOUNDARY_INVALID"),
            (step188_result.get("irlt_mag_state_changed") is False, "STEP_188_IRLT_BOUNDARY_INVALID"),
        )
        for ok, reason in checks:
            if not ok:
                reasons.append(reason)
        if step188_result.get("reasons") != []:
            reasons.append("STEP_188_SUPPORTABLE_RESULT_REASONS_INVALID")
        if _nonempty(expected_scope_id) and step188_result.get("expected_scope_id") != expected_scope_id.strip():
            reasons.append("STEP_188_SCOPE_MISMATCH")
        if _nonempty(expected_action_id) and step188_result.get("expected_action_id") != expected_action_id.strip():
            reasons.append("STEP_188_ACTION_MISMATCH")
        if _nonempty(expected_object_hash) and step188_result.get("expected_object_hash") != expected_object_hash.strip():
            reasons.append("STEP_188_OBJECT_MISMATCH")
        if _nonempty(expected_transaction_id) and step188_result.get("expected_transaction_id") != expected_transaction_id.strip():
            reasons.append("STEP_188_TRANSACTION_MISMATCH")

    # Expected Step 182 identity must align with Step 188 declared identifiers.
    if not isinstance(expected, Mapping):
        reasons.append("STEP_182_EXPECTED_BASIS_MISSING_OR_INVALID")
    else:
        if _nonempty(expected_action_id) and expected.get("action_id") != expected_action_id.strip():
            reasons.append("STEP_182_EXPECTED_ACTION_MISMATCH")
        if _nonempty(expected_object_hash) and expected.get("object_hash") != expected_object_hash.strip():
            reasons.append("STEP_182_EXPECTED_OBJECT_MISMATCH")
        if _nonempty(expected_transaction_id) and expected.get("transaction_id") != expected_transaction_id.strip():
            reasons.append("STEP_182_EXPECTED_TRANSACTION_MISMATCH")

    # Exact Step 182 semantic reproduction prevents favorable-result substitution.
    if not all(isinstance(x, Mapping) for x in (step181_commit_result, commit_receipt, execution_receipt, outcome_evidence)):
        reasons.append("STEP_182_INPUT_BUNDLE_MISSING_OR_INVALID")
        reproduced = None
    else:
        reproduced = reproduce_step182(
            prior_commit_result=step181_commit_result,
            commit_receipt=commit_receipt,
            execution_receipt=execution_receipt,
            outcome_evidence=outcome_evidence,
            expected=expected,
        )
        if dict(step182_result) != reproduced:
            reasons.append("STEP_182_RESULT_NOT_REPRODUCIBLE_FROM_EXACT_INPUTS")
        if reproduced.get("correspondence_standing") != "OUTCOME_CORRESPONDENCE_SUPPORTABLE":
            reasons.append("STEP_182_OUTCOME_CORRESPONDENCE_NOT_SUPPORTABLE")
        if reproduced.get("no_bind_state") != "INACTIVE":
            reasons.append("STEP_182_NO_BIND_NOT_INACTIVE")
        if reproduced.get("commit_occurred") is not True:
            reasons.append("STEP_182_COMMIT_NOT_ESTABLISHED")
        if reproduced.get("execution_succeeded") is not True:
            reasons.append("STEP_182_EXECUTION_SUCCESS_NOT_ESTABLISHED")
        if reproduced.get("intended_outcome_established") is not True:
            reasons.append("STEP_182_INTENDED_OUTCOME_NOT_ESTABLISHED")

    # Binding record binds exact upstream results and exact Step 182 evidence bundle.
    if not isinstance(outcome_binding_record, Mapping):
        reasons.append("OUTCOME_BINDING_RECORD_MISSING_OR_INVALID")
    else:
        required_strings = (
            "declared_scope_id", "action_id", "object_hash", "transaction_id",
            "outcome_binding_point_id", "outcome_binding_evidence_ref", "outcome_binding_basis_version",
            "step188_result_digest", "step182_result_digest", "step181_commit_result_digest",
            "commit_receipt_digest", "execution_receipt_digest", "outcome_evidence_digest", "expected_digest",
            "step188_evaluator_blob", "step188_test_blob", "step182_evaluator_blob", "step182_test_blob",
        )
        for field in required_strings:
            if not _nonempty(outcome_binding_record.get(field)):
                reasons.append("OUTCOME_BINDING_" + field.upper() + "_MISSING_OR_INVALID")
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
        if type(material_change) is not bool or type(revalidated) is not bool:
            reasons.append("OUTCOME_BINDING_CHANGE_STATE_INVALID")
        elif material_change and not revalidated:
            reasons.append("OUTCOME_BINDING_STALE_AFTER_MATERIAL_CHANGE")

        identity_checks = {
            "declared_scope_id": expected_scope_id.strip() if _nonempty(expected_scope_id) else None,
            "action_id": expected_action_id.strip() if _nonempty(expected_action_id) else None,
            "object_hash": expected_object_hash.strip() if _nonempty(expected_object_hash) else None,
            "transaction_id": expected_transaction_id.strip() if _nonempty(expected_transaction_id) else None,
            "step188_evaluator_blob": STEP188_EVALUATOR_BLOB,
            "step188_test_blob": STEP188_TEST_BLOB,
            "step182_evaluator_blob": STEP182_EVALUATOR_BLOB,
            "step182_test_blob": STEP182_TEST_BLOB,
        }
        for field, value in identity_checks.items():
            if value is not None and outcome_binding_record.get(field) != value:
                reasons.append("OUTCOME_BINDING_" + field.upper() + "_MISMATCH")

        payloads = {
            "step188_result_digest": step188_result,
            "step182_result_digest": step182_result,
            "step181_commit_result_digest": step181_commit_result,
            "commit_receipt_digest": commit_receipt,
            "execution_receipt_digest": execution_receipt,
            "outcome_evidence_digest": outcome_evidence,
            "expected_digest": expected,
        }
        for digest_field, payload in payloads.items():
            if isinstance(payload, Mapping):
                digest = canonical_digest(payload)
                if digest is None or outcome_binding_record.get(digest_field) != digest:
                    reasons.append("OUTCOME_BINDING_" + digest_field.upper() + "_MISMATCH")

    blocked = bool(reasons)
    if blocked and caller_requested_decision in {"COMMIT", "EXECUTE", "ADMISSIBLE", "RELEASE", "DISPOSE"}:
        reasons.append("CALLER_OVERRIDE_REJECTED")
    return _base(blocked=bool(reasons), reasons=reasons)
