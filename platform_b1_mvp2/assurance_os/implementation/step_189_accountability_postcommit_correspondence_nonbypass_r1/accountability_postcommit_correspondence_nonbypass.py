"""Step 189 — Accountability Post-Commit Correspondence Non-Bypass R1.

This bounded successor integration control composes frozen Step 188 with existing
Step 182 without modifying either upstream control. It closes the downstream
bypass in which Step 182 can otherwise be evaluated from a favorable Step 181
shape without requiring the exact Step 188 accountability binding or evidence
that the exact single-use Step 181 token bound by Step 188 corresponded to the
commit receipt.

Step 189 reproduces the frozen Step 188 evaluator from its exact input bundle,
reproduces Step 182 from its exact input bundle, requires the Step 182 prior
commit result to be the exact Step 181 result already consumed by Step 188, and
requires caller-supplied token-consumption evidence to correspond to the exact
Step 188-bound token, action, transaction, object, nonce, and commit point.

It does not grant authority, execute or authorize commit/execution, consume a
commit token, authenticate caller-supplied receipts, prove causation, or modify
IRLT-MAG.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType


SUPPORTABLE = "ACCOUNTABILITY_POSTCOMMIT_CORRESPONDENCE_SUPPORTABLE"
NOT_ESTABLISHED = "ACCOUNTABILITY_POSTCOMMIT_CORRESPONDENCE_NOT_ESTABLISHED"

STEP188_EVALUATOR_BLOB = "e75ef018802c7ca2370fd54ee9864709c50a81d7"
STEP188_TEST_BLOB = "1946c4763ecdf0a56e2ed8cc998308aefdac803f"
STEP182_EVALUATOR_BLOB = "b2c999b9dd5f3528a851646871dafc08d8bda5a3"
STEP182_TEST_BLOB = "4acf9a219278b7a31c55df8ab78e916405d71741"

STEP188_REQUIRED_INPUT_KEYS = frozenset({
    "step187_result",
    "step187_commit_binding_record",
    "step187_current_snapshot",
    "step181_token",
    "step181_commit_result",
    "commit_snapshot",
    "atomic_binding_record",
    "expected_scope_id",
    "expected_action_id",
    "expected_object_hash",
    "expected_transaction_id",
    "expected_commit_nonce",
    "caller_requested_decision",
})

STEP182_REQUIRED_INPUT_KEYS = frozenset({
    "prior_commit_result",
    "commit_receipt",
    "execution_receipt",
    "outcome_evidence",
    "expected",
})

IMPLEMENTATION_DIR = Path(__file__).resolve().parent.parent
STEP188_EVALUATOR_PATH = (
    IMPLEMENTATION_DIR
    / "step_188_accountability_continuity_atomic_commit_nonbypass_r1"
    / "accountability_atomic_commit_nonbypass.py"
)
STEP182_EVALUATOR_PATH = (
    IMPLEMENTATION_DIR
    / "step_182_commit_execution_outcome_correspondence_r1"
    / "commit_execution_outcome_correspondence.py"
)


def _valid_nonempty(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def canonical_digest(value: object) -> str | None:
    """Return a stable SHA-256 digest over JSON-serializable bounded evidence."""
    normalized = dict(value) if isinstance(value, Mapping) else value
    try:
        payload = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    except (TypeError, ValueError):
        return None
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def git_blob_sha1(path: Path) -> str | None:
    """Reconstruct the Git blob SHA-1 for exact checked-out source bytes."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _load_module(path: Path, module_name: str) -> ModuleType | None:
    try:
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


def _check_exact_keys(
    bundle: object,
    required: frozenset[str],
    prefix: str,
    reasons: list[str],
) -> bool:
    if not isinstance(bundle, Mapping):
        reasons.append(prefix + "_INPUT_BUNDLE_MISSING_OR_INVALID")
        return False
    keys = set(bundle.keys())
    for key in sorted(required - keys):
        reasons.append(prefix + "_INPUT_" + key.upper() + "_MISSING")
    for key in sorted(keys - required):
        reasons.append(prefix + "_INPUT_" + str(key).upper() + "_UNEXPECTED")
    return keys == set(required)


def _reproduce_step188(
    step188_inputs: Mapping[str, object],
    reasons: list[str],
) -> dict[str, object] | None:
    actual_blob = git_blob_sha1(STEP188_EVALUATOR_PATH)
    if actual_blob != STEP188_EVALUATOR_BLOB:
        reasons.append("STEP_188_FROZEN_EVALUATOR_SOURCE_IDENTITY_MISMATCH")
        return None
    module = _load_module(STEP188_EVALUATOR_PATH, "step189_frozen_step188")
    if module is None:
        reasons.append("STEP_188_FROZEN_EVALUATOR_LOAD_FAILED")
        return None
    evaluator = getattr(module, "evaluate_accountability_atomic_commit_nonbypass", None)
    if not callable(evaluator):
        reasons.append("STEP_188_FROZEN_EVALUATOR_ENTRYPOINT_MISSING")
        return None
    try:
        result = evaluator(**dict(step188_inputs))
    except Exception:
        reasons.append("STEP_188_RESULT_REPRODUCTION_FAILED")
        return None
    return result if isinstance(result, dict) else None


def _reproduce_step182(
    step182_inputs: Mapping[str, object],
    reasons: list[str],
) -> dict[str, object] | None:
    actual_blob = git_blob_sha1(STEP182_EVALUATOR_PATH)
    if actual_blob != STEP182_EVALUATOR_BLOB:
        reasons.append("STEP_182_EVALUATOR_SOURCE_IDENTITY_MISMATCH")
        return None
    module = _load_module(STEP182_EVALUATOR_PATH, "step189_step182")
    if module is None:
        reasons.append("STEP_182_EVALUATOR_LOAD_FAILED")
        return None
    evaluator = getattr(module, "evaluate_commit_execution_outcome_correspondence", None)
    if not callable(evaluator):
        reasons.append("STEP_182_EVALUATOR_ENTRYPOINT_MISSING")
        return None
    try:
        result = evaluator(**dict(step182_inputs))
    except Exception:
        reasons.append("STEP_182_RESULT_REPRODUCTION_FAILED")
        return None
    return result if isinstance(result, dict) else None


def evaluate_accountability_postcommit_correspondence_nonbypass(
    *,
    step188_inputs: Mapping[str, object],
    step188_result: Mapping[str, object],
    step182_inputs: Mapping[str, object],
    step182_result: Mapping[str, object],
    postcommit_binding_record: Mapping[str, object],
    caller_requested_decision: str = "EVALUATE",
) -> dict[str, object]:
    """Fail closed unless Step 188 remains inseparable from Step 182 correspondence."""

    reasons: list[str] = []
    token_reasons: list[str] = []

    step188_exact = _check_exact_keys(
        step188_inputs, STEP188_REQUIRED_INPUT_KEYS, "STEP_188", reasons
    )
    step182_exact = _check_exact_keys(
        step182_inputs, STEP182_REQUIRED_INPUT_KEYS, "STEP_182", reasons
    )

    reproduced_step188 = (
        _reproduce_step188(step188_inputs, reasons) if step188_exact else None
    )
    reproduced_step182 = (
        _reproduce_step182(step182_inputs, reasons) if step182_exact else None
    )

    if not isinstance(step188_result, Mapping):
        reasons.append("STEP_188_RESULT_MISSING_OR_INVALID")
    else:
        if reproduced_step188 is not None and dict(step188_result) != reproduced_step188:
            reasons.append("STEP_188_RESULT_NOT_REPRODUCIBLE_FROM_EXACT_INPUTS")
        checks = (
            (step188_result.get("integration_revision") == "STEP_188_R1", "STEP_188_REVISION_NOT_ESTABLISHED"),
            (step188_result.get("atomic_accountability_standing") == "ACCOUNTABILITY_ATOMIC_COMMIT_BINDING_SUPPORTABLE", "STEP_188_STANDING_NOT_SUPPORTABLE"),
            (step188_result.get("atomic_accountability_decision") == "ACCOUNTABILITY_ATOMIC_COMMIT_PREREQUISITES_SUPPORTABLE", "STEP_188_DECISION_NOT_SUPPORTABLE"),
            (step188_result.get("no_bind_state") == "SEPARATE_AUTHORIZED_COMMIT_EXECUTION_AND_TOKEN_CONSUMPTION_REQUIRED", "STEP_188_NO_BIND_CONTRACT_INVALID"),
            (step188_result.get("action_held") is False, "STEP_188_ACTION_HOLD_NOT_CLEARED"),
            (step188_result.get("step_187_result_consumed") is True, "STEP_188_STEP_187_CONSUMPTION_NOT_ESTABLISHED"),
            (step188_result.get("step_181_token_consumed_as_evidence") is True, "STEP_188_TOKEN_EVIDENCE_CONSUMPTION_NOT_ESTABLISHED"),
            (step188_result.get("step_181_commit_result_consumed") is True, "STEP_188_STEP_181_RESULT_CONSUMPTION_NOT_ESTABLISHED"),
            (step188_result.get("step_181_commit_result_reproduced") is True, "STEP_188_STEP_181_REPRODUCTION_NOT_ESTABLISHED"),
            (step188_result.get("cross_snapshot_state_equality_checked") is True, "STEP_188_CROSS_SNAPSHOT_CHECK_NOT_ESTABLISHED"),
            (step188_result.get("atomic_cross_binding_checked") is True, "STEP_188_ATOMIC_CROSS_BINDING_NOT_ESTABLISHED"),
            (step188_result.get("source_identity_checked") is True, "STEP_188_SOURCE_IDENTITY_NOT_ESTABLISHED"),
            (step188_result.get("payload_digest_binding_checked") is True, "STEP_188_PAYLOAD_BINDING_NOT_ESTABLISHED"),
            (step188_result.get("atomic_temporal_currentness_checked") is True, "STEP_188_TEMPORAL_CURRENTNESS_NOT_ESTABLISHED"),
            (step188_result.get("token_consumption_required_on_authorized_commit") is True, "STEP_188_TOKEN_CONSUMPTION_REQUIREMENT_NOT_ESTABLISHED"),
            (step188_result.get("binding_provenance_manufactured") is False, "STEP_188_PROVENANCE_BOUNDARY_INVALID"),
            (step188_result.get("binding_authority_granted") is False, "STEP_188_AUTHORITY_BOUNDARY_INVALID"),
            (step188_result.get("action_admissibility_granted") is False, "STEP_188_ACTION_ADMISSIBILITY_BOUNDARY_INVALID"),
            (step188_result.get("commit_authorized") is False, "STEP_188_COMMIT_AUTHORITY_BOUNDARY_INVALID"),
            (step188_result.get("execution_authorized") is False, "STEP_188_EXECUTION_AUTHORITY_BOUNDARY_INVALID"),
            (step188_result.get("commit_token_consumed_by_evaluator") is False, "STEP_188_TOKEN_CONSUMPTION_BOUNDARY_INVALID"),
            (step188_result.get("physical_action_executed") is False, "STEP_188_PHYSICAL_ACTION_BOUNDARY_INVALID"),
            (step188_result.get("regulated_release_or_disposition_authorized") is False, "STEP_188_RELEASE_BOUNDARY_INVALID"),
            (step188_result.get("historical_facts_rewritten") is False, "STEP_188_HISTORY_BOUNDARY_INVALID"),
            (step188_result.get("irlt_mag_state_changed") is False, "STEP_188_IRLT_BOUNDARY_INVALID"),
        )
        for ok, reason in checks:
            if not ok:
                reasons.append(reason)
        step188_reasons = step188_result.get("reasons")
        if type(step188_reasons) is not list or step188_reasons:
            reasons.append("STEP_188_SUPPORTABLE_RESULT_REASONS_INVALID")

    if not isinstance(step182_result, Mapping):
        reasons.append("STEP_182_RESULT_MISSING_OR_INVALID")
    else:
        if reproduced_step182 is not None and dict(step182_result) != reproduced_step182:
            reasons.append("STEP_182_RESULT_NOT_REPRODUCIBLE_FROM_EXACT_INPUTS")
        checks = (
            (step182_result.get("correspondence_standing") == "OUTCOME_CORRESPONDENCE_SUPPORTABLE", "STEP_182_OUTCOME_CORRESPONDENCE_NOT_SUPPORTABLE"),
            (step182_result.get("commit_occurred") is True, "STEP_182_COMMIT_NOT_ESTABLISHED"),
            (step182_result.get("execution_succeeded") is True, "STEP_182_EXECUTION_NOT_ESTABLISHED"),
            (step182_result.get("intended_outcome_established") is True, "STEP_182_INTENDED_OUTCOME_NOT_ESTABLISHED"),
            (step182_result.get("no_bind_state") == "INACTIVE", "STEP_182_NO_BIND_ACTIVE_OR_INVALID"),
            (step182_result.get("binding_authority_granted") is False, "STEP_182_AUTHORITY_BOUNDARY_INVALID"),
            (step182_result.get("physical_action_executed_by_evaluator") is False, "STEP_182_PHYSICAL_ACTION_BOUNDARY_INVALID"),
            (step182_result.get("causal_attribution_established") is False, "STEP_182_CAUSATION_BOUNDARY_INVALID"),
        )
        for ok, reason in checks:
            if not ok:
                reasons.append(reason)
        step182_reasons = step182_result.get("reasons")
        if type(step182_reasons) is not list or step182_reasons:
            reasons.append("STEP_182_SUPPORTABLE_RESULT_REASONS_INVALID")

    # The downstream Step 182 route must consume the exact Step 181 result already
    # inside the Step 188 input bundle. A favorable Step 181-shaped substitute is
    # not sufficient.
    if isinstance(step188_inputs, Mapping) and isinstance(step182_inputs, Mapping):
        prior = step182_inputs.get("prior_commit_result")
        step181_result = step188_inputs.get("step181_commit_result")
        if not isinstance(prior, Mapping) or not isinstance(step181_result, Mapping):
            reasons.append("STEP_181_CROSS_CONTROL_RESULT_MISSING_OR_INVALID")
        elif dict(prior) != dict(step181_result):
            reasons.append("STEP_182_PRIOR_COMMIT_RESULT_NOT_EXACT_STEP_188_STEP_181_RESULT")

        expected = step182_inputs.get("expected")
        if not isinstance(expected, Mapping):
            reasons.append("STEP_182_EXPECTED_BASIS_MISSING_OR_INVALID")
        else:
            cross_expected = (
                ("action_id", "expected_action_id", "STEP_182_EXPECTED_ACTION_NOT_STEP_188_BOUND"),
                ("transaction_id", "expected_transaction_id", "STEP_182_EXPECTED_TRANSACTION_NOT_STEP_188_BOUND"),
                ("object_hash", "expected_object_hash", "STEP_182_EXPECTED_OBJECT_NOT_STEP_188_BOUND"),
            )
            for step182_field, step188_field, reason in cross_expected:
                if expected.get(step182_field) != step188_inputs.get(step188_field):
                    reasons.append(reason)

    # Establish bounded correspondence for caller-supplied evidence that the exact
    # Step 188-bound single-use token was consumed at the corresponding commit.
    token = step188_inputs.get("step181_token") if isinstance(step188_inputs, Mapping) else None
    atomic_binding = step188_inputs.get("atomic_binding_record") if isinstance(step188_inputs, Mapping) else None
    commit_receipt = step182_inputs.get("commit_receipt") if isinstance(step182_inputs, Mapping) else None

    if not isinstance(token, Mapping):
        token_reasons.append("STEP_188_BOUND_TOKEN_MISSING_OR_INVALID")
    if not isinstance(atomic_binding, Mapping):
        token_reasons.append("STEP_188_ATOMIC_BINDING_RECORD_MISSING_OR_INVALID")
    if not isinstance(commit_receipt, Mapping):
        token_reasons.append("COMMIT_RECEIPT_MISSING_FOR_TOKEN_CONSUMPTION_CORRESPONDENCE")

    if isinstance(token, Mapping) and isinstance(commit_receipt, Mapping):
        if commit_receipt.get("action_id") != step188_inputs.get("expected_action_id"):
            token_reasons.append("COMMIT_RECEIPT_ACTION_NOT_STEP_188_BOUND")
        if commit_receipt.get("transaction_id") != step188_inputs.get("expected_transaction_id"):
            token_reasons.append("COMMIT_RECEIPT_TRANSACTION_NOT_STEP_188_BOUND")
        if commit_receipt.get("object_hash") != step188_inputs.get("expected_object_hash"):
            token_reasons.append("COMMIT_RECEIPT_OBJECT_NOT_STEP_188_BOUND")
        if commit_receipt.get("commit_nonce") != step188_inputs.get("expected_commit_nonce"):
            token_reasons.append("COMMIT_RECEIPT_NONCE_NOT_STEP_188_BOUND")
        if commit_receipt.get("commit_token_id") != token.get("token_id"):
            token_reasons.append("COMMIT_RECEIPT_TOKEN_ID_NOT_STEP_188_BOUND")
        if commit_receipt.get("token_consumed") is not True:
            token_reasons.append("BOUND_COMMIT_TOKEN_CONSUMPTION_NOT_ESTABLISHED")
        count = commit_receipt.get("token_consumption_count")
        if type(count) is not int or count != 1:
            token_reasons.append("BOUND_COMMIT_TOKEN_SINGLE_USE_CONSUMPTION_NOT_ESTABLISHED")
        if commit_receipt.get("token_replay_detected") is not False:
            token_reasons.append("BOUND_COMMIT_TOKEN_REPLAY_STATE_NOT_CLEAR")
        for field in ("commit_event_id", "token_consumption_evidence_ref"):
            if not _valid_nonempty(commit_receipt.get(field)):
                token_reasons.append("COMMIT_RECEIPT_" + field.upper() + "_MISSING_OR_INVALID")

    if isinstance(atomic_binding, Mapping) and isinstance(commit_receipt, Mapping):
        if commit_receipt.get("commit_point_id") != atomic_binding.get("commit_point_id"):
            token_reasons.append("COMMIT_RECEIPT_COMMIT_POINT_NOT_STEP_188_BOUND")

    reasons.extend(token_reasons)

    # Explicit Step 189 binding record prevents independent substitution of a
    # favorable upstream result, downstream result, receipt, or evidence bundle.
    if not isinstance(postcommit_binding_record, Mapping):
        reasons.append("POSTCOMMIT_BINDING_RECORD_MISSING_OR_INVALID")
    else:
        required_strings = (
            "declared_scope_id",
            "action_id",
            "object_hash",
            "transaction_id",
            "commit_nonce",
            "commit_point_id",
            "binding_evidence_ref",
            "binding_basis_version",
            "step188_input_bundle_digest",
            "step188_result_digest",
            "step182_input_bundle_digest",
            "step182_result_digest",
            "step181_token_digest",
            "commit_receipt_digest",
            "execution_receipt_digest",
            "outcome_evidence_digest",
            "expected_digest",
            "step188_evaluator_blob",
            "step188_test_blob",
            "step182_evaluator_blob",
            "step182_test_blob",
        )
        for field in required_strings:
            if not _valid_nonempty(postcommit_binding_record.get(field)):
                reasons.append("POSTCOMMIT_BINDING_" + field.upper() + "_MISSING_OR_INVALID")

        if postcommit_binding_record.get("binding_traceable") is not True:
            reasons.append("POSTCOMMIT_BINDING_NOT_TRACEABLE")
        if postcommit_binding_record.get("binding_current") is not True:
            reasons.append("POSTCOMMIT_BINDING_NOT_CURRENT")
        if postcommit_binding_record.get("binding_ambiguity_present") is not False:
            reasons.append("POSTCOMMIT_BINDING_AMBIGUOUS_OR_INVALID")
        if postcommit_binding_record.get("binding_temporal_ordering_established") is not True:
            reasons.append("POSTCOMMIT_BINDING_TEMPORAL_ORDERING_NOT_ESTABLISHED")
        if postcommit_binding_record.get("binding_change_assessment_complete") is not True:
            reasons.append("POSTCOMMIT_BINDING_CHANGE_ASSESSMENT_INCOMPLETE")

        material_change = postcommit_binding_record.get("material_change_after_postcommit_binding")
        revalidated = postcommit_binding_record.get("postcommit_binding_revalidated_after_latest_material_change")
        if type(material_change) is not bool:
            reasons.append("POSTCOMMIT_BINDING_MATERIAL_CHANGE_STATE_INVALID")
        if type(revalidated) is not bool:
            reasons.append("POSTCOMMIT_BINDING_REVALIDATION_STATE_INVALID")
        if material_change is True and revalidated is not True:
            reasons.append("POSTCOMMIT_BINDING_STALE_AFTER_MATERIAL_CHANGE")

        if isinstance(step188_inputs, Mapping):
            id_checks = (
                ("declared_scope_id", step188_inputs.get("expected_scope_id"), "POSTCOMMIT_BINDING_SCOPE_MISMATCH"),
                ("action_id", step188_inputs.get("expected_action_id"), "POSTCOMMIT_BINDING_ACTION_MISMATCH"),
                ("object_hash", step188_inputs.get("expected_object_hash"), "POSTCOMMIT_BINDING_OBJECT_MISMATCH"),
                ("transaction_id", step188_inputs.get("expected_transaction_id"), "POSTCOMMIT_BINDING_TRANSACTION_MISMATCH"),
                ("commit_nonce", step188_inputs.get("expected_commit_nonce"), "POSTCOMMIT_BINDING_NONCE_MISMATCH"),
            )
            for field, expected_value, reason in id_checks:
                if postcommit_binding_record.get(field) != expected_value:
                    reasons.append(reason)

        if isinstance(atomic_binding, Mapping):
            if postcommit_binding_record.get("commit_point_id") != atomic_binding.get("commit_point_id"):
                reasons.append("POSTCOMMIT_BINDING_COMMIT_POINT_MISMATCH")

        source_checks = (
            ("step188_evaluator_blob", STEP188_EVALUATOR_BLOB, "STEP_188_FROZEN_EVALUATOR_IDENTITY_RECORD_MISMATCH"),
            ("step188_test_blob", STEP188_TEST_BLOB, "STEP_188_FROZEN_TEST_IDENTITY_RECORD_MISMATCH"),
            ("step182_evaluator_blob", STEP182_EVALUATOR_BLOB, "STEP_182_EVALUATOR_IDENTITY_RECORD_MISMATCH"),
            ("step182_test_blob", STEP182_TEST_BLOB, "STEP_182_TEST_IDENTITY_RECORD_MISMATCH"),
        )
        for field, expected_value, reason in source_checks:
            if postcommit_binding_record.get(field) != expected_value:
                reasons.append(reason)

        step181_token = step188_inputs.get("step181_token") if isinstance(step188_inputs, Mapping) else None
        execution_receipt = step182_inputs.get("execution_receipt") if isinstance(step182_inputs, Mapping) else None
        outcome_evidence = step182_inputs.get("outcome_evidence") if isinstance(step182_inputs, Mapping) else None
        expected = step182_inputs.get("expected") if isinstance(step182_inputs, Mapping) else None
        digest_checks = (
            ("step188_input_bundle_digest", step188_inputs, "STEP_188_INPUT_BUNDLE"),
            ("step188_result_digest", step188_result, "STEP_188_RESULT"),
            ("step182_input_bundle_digest", step182_inputs, "STEP_182_INPUT_BUNDLE"),
            ("step182_result_digest", step182_result, "STEP_182_RESULT"),
            ("step181_token_digest", step181_token, "STEP_181_TOKEN"),
            ("commit_receipt_digest", commit_receipt, "COMMIT_RECEIPT"),
            ("execution_receipt_digest", execution_receipt, "EXECUTION_RECEIPT"),
            ("outcome_evidence_digest", outcome_evidence, "OUTCOME_EVIDENCE"),
            ("expected_digest", expected, "EXPECTED_BASIS"),
        )
        for field, payload, label in digest_checks:
            digest = canonical_digest(payload)
            if digest is None:
                reasons.append(label + "_DIGEST_NOT_COMPUTABLE")
            elif postcommit_binding_record.get(field) != digest:
                reasons.append("POSTCOMMIT_BINDING_" + label + "_DIGEST_MISMATCH")

    override_requested = caller_requested_decision in {
        "AUTHORIZE",
        "BIND",
        "COMMIT",
        "EXECUTE",
        "RELEASE",
        "DISPOSE",
    }
    if override_requested:
        reasons.append("CALLER_AUTHORITY_OVERRIDE_REJECTED")

    blocked = bool(reasons)
    historical = (
        reproduced_step182.get("historical_facts", {})
        if isinstance(reproduced_step182, Mapping)
        else {}
    )

    return {
        "integration_revision": "STEP_189_R1",
        "accountability_postcommit_standing": NOT_ESTABLISHED if blocked else SUPPORTABLE,
        "accountability_postcommit_decision": "NOT_SUPPORTABLE" if blocked else "ACCOUNTABILITY_COMMIT_EXECUTION_OUTCOME_CORRESPONDENCE_SUPPORTABLE",
        "no_bind_state": "ACTIVE" if blocked else "SEPARATE_EXTERNAL_AUTHORITY_AUTHENTICITY_CAUSATION_AND_OPERATIONAL_VALIDATION_REQUIRED",
        "postcommit_reliance_held": blocked,
        "caller_requested_decision": caller_requested_decision,
        "caller_override_rejected": override_requested,
        "reasons": sorted(set(reasons)),
        "step_188_result_consumed": True,
        "step_188_result_reproduced": reproduced_step188 is not None,
        "step_182_result_consumed": True,
        "step_182_result_reproduced": reproduced_step182 is not None,
        "exact_step_181_cross_control_result_checked": True,
        "token_consumption_evidence_correspondence_checked": True,
        "token_consumption_correspondence_supportable": not bool(token_reasons),
        "postcommit_cross_binding_checked": True,
        "source_identity_checked": (
            git_blob_sha1(STEP188_EVALUATOR_PATH) == STEP188_EVALUATOR_BLOB
            and git_blob_sha1(STEP182_EVALUATOR_PATH) == STEP182_EVALUATOR_BLOB
        ),
        "payload_digest_binding_checked": True,
        "historical_facts": dict(historical) if isinstance(historical, Mapping) else {},
        "commit_occurred": reproduced_step182.get("commit_occurred") if isinstance(reproduced_step182, Mapping) else None,
        "execution_succeeded": reproduced_step182.get("execution_succeeded") if isinstance(reproduced_step182, Mapping) else None,
        "intended_outcome_established": reproduced_step182.get("intended_outcome_established") if isinstance(reproduced_step182, Mapping) else None,
        "binding_provenance_manufactured": False,
        "binding_authority_granted": False,
        "action_admissibility_granted": False,
        "commit_authorized": False,
        "execution_authorized": False,
        "commit_token_consumed_by_evaluator": False,
        "physical_action_executed_by_evaluator": False,
        "causal_attribution_established": False,
        "regulated_release_or_disposition_authorized": False,
        "historical_facts_rewritten": False,
        "irlt_mag_state_changed": False,
    }
