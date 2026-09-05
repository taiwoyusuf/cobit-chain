"""Step 188 — Accountability Continuity Atomic Commit Non-Bypass R1.

This bounded adapter composes frozen Step 187 Accountability Continuity
Commit-Time Revalidation with existing Step 181 Atomic Commit Binding.

The hardened configuration re-establishes the Step 187 current-state binding at
the atomic boundary, reproduces Step 181 verification from the exact token and
commit inputs, and then requires exact cross-control correspondence.

It does not replace Step 181, grant authority, authorize commit/execution,
consume a commit token, execute a physical/regulated action, or modify IRLT-MAG.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping


SUPPORTABLE = "ACCOUNTABILITY_ATOMIC_COMMIT_BINDING_SUPPORTABLE"
NOT_ESTABLISHED = "ACCOUNTABILITY_ATOMIC_COMMIT_BINDING_NOT_ESTABLISHED"

STEP187_STANDING = "ACCOUNTABILITY_COMMIT_TIME_CONTINUITY_SUPPORTABLE"
STEP187_DECISION = "ACCOUNTABILITY_COMMIT_PREREQUISITES_SUPPORTABLE"
STEP187_NO_BIND = "SEPARATE_AUTHORIZED_COMMIT_MECHANISM_REQUIRED"

STEP187_EVALUATOR_BLOB = "8e00cbe56eca71997d6b87b7657a0549f8082d77"
STEP187_PRIMARY_TEST_BLOB = "cd673b77939f3bf5e290bf288a6005e6d23ada23"
STEP187_HARDENING_TEST_BLOB = "48c8ce54eb0597a331373a264abd87364af24517"
STEP181_EVALUATOR_BLOB = "93cb7f58ac7d17f17e6ccba9174fd05458afd857"
STEP181_TEST_BLOB = "e923353bdcbd4b4cfa272cc1fb158dba66fd44ad"

STEP181_SNAPSHOT_FIELDS = (
    "object_hash",
    "authority_current",
    "evidence_digest",
    "criteria_version",
    "configuration_hash",
    "environment_context_hash",
)

STEP187_SNAPSHOT_FIELDS = ("action_id",) + STEP181_SNAPSHOT_FIELDS


def _valid_nonempty(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def canonical_payload_digest(record: Mapping[str, object]) -> str | None:
    """SHA-256 over exact JSON-serializable mapping, prefixed for Step 188 records."""
    try:
        payload = json.dumps(dict(record), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError):
        return None
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def step181_digest(value: Mapping[str, object]) -> str | None:
    """Reproduce Step 181 canonical digest shape (hex without prefix)."""
    try:
        payload = json.dumps(dict(value), sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verification_input_payload(
    *,
    token: Mapping[str, object],
    commit_snapshot: Mapping[str, object],
    action_id: str,
    transaction_id: str,
    commit_nonce: str,
) -> dict[str, object]:
    return {
        "token": dict(token),
        "commit_snapshot": dict(commit_snapshot),
        "action_id": action_id,
        "transaction_id": transaction_id,
        "commit_nonce": commit_nonce,
        "token_consumed": False,
    }


def reproduce_step181_verify(
    *,
    token: Mapping[str, object],
    commit_snapshot: Mapping[str, object],
    action_id: str,
    transaction_id: str,
    commit_nonce: str,
) -> dict[str, object] | None:
    """Reproduce Step 181 verify_atomic_commit for token_consumed=False."""
    if not isinstance(token, Mapping) or not isinstance(commit_snapshot, Mapping):
        return None

    reasons: list[str] = []
    if token.get("token_state") != "ISSUED":
        reasons.append("VALID_COMMIT_TOKEN_NOT_PRESENT")
    if token.get("action_id") != action_id:
        reasons.append("ACTION_CHANGED_AFTER_REVALIDATION")
    if token.get("transaction_id") != transaction_id:
        reasons.append("TRANSACTION_CHANGED_AFTER_REVALIDATION")
    if token.get("commit_nonce") != commit_nonce:
        reasons.append("COMMIT_NONCE_MISMATCH")
    if token.get("object_hash") != commit_snapshot.get("object_hash"):
        reasons.append("OBJECT_CHANGED_BETWEEN_REVALIDATION_AND_COMMIT")

    snapshot_digest = step181_digest(commit_snapshot)
    if snapshot_digest is None:
        return None
    if token.get("snapshot_digest") != snapshot_digest:
        reasons.append("COMMIT_STATE_CHANGED_AFTER_REVALIDATION")

    blocked = bool(reasons)
    return {
        "atomic_commit_standing": "SUPPORTABLE" if not blocked else "NO_BIND",
        "commit_decision": "COMMIT_ROUTE_ADMISSIBLE" if not blocked else "NOT_ADMISSIBLE",
        "no_bind_state": "INACTIVE" if not blocked else "ACTIVE",
        "action_held": blocked,
        "token_consumption_required_on_commit": not blocked,
        "reasons": sorted(set(reasons)),
        "evaluated_to_committed_binding_verified": not blocked,
        "binding_authority_granted": False,
        "physical_action_executed": False,
    }


def evaluate_accountability_atomic_commit_nonbypass(
    *,
    step187_result: Mapping[str, object],
    step187_commit_binding_record: Mapping[str, object],
    step187_current_snapshot: Mapping[str, object],
    step181_token: Mapping[str, object],
    step181_commit_result: Mapping[str, object],
    commit_snapshot: Mapping[str, object],
    atomic_binding_record: Mapping[str, object],
    expected_scope_id: str,
    expected_action_id: str,
    expected_object_hash: str,
    expected_transaction_id: str,
    expected_commit_nonce: str,
    caller_requested_decision: str,
) -> dict[str, object]:
    """Fail closed unless accountability continuity is bound to the atomic commit route."""

    reasons: list[str] = []

    expected_fields = (
        ("EXPECTED_SCOPE_ID", expected_scope_id),
        ("EXPECTED_ACTION_ID", expected_action_id),
        ("EXPECTED_OBJECT_HASH", expected_object_hash),
        ("EXPECTED_TRANSACTION_ID", expected_transaction_id),
        ("EXPECTED_COMMIT_NONCE", expected_commit_nonce),
    )
    for name, value in expected_fields:
        if not _valid_nonempty(value):
            reasons.append(name + "_MISSING_OR_INVALID")

    scope = expected_scope_id.strip() if _valid_nonempty(expected_scope_id) else None
    action = expected_action_id.strip() if _valid_nonempty(expected_action_id) else None
    obj = expected_object_hash.strip() if _valid_nonempty(expected_object_hash) else None
    transaction = expected_transaction_id.strip() if _valid_nonempty(expected_transaction_id) else None
    nonce = expected_commit_nonce.strip() if _valid_nonempty(expected_commit_nonce) else None

    # Frozen Step 187 result contract.
    if not isinstance(step187_result, Mapping):
        reasons.append("STEP_187_RESULT_MISSING_OR_INVALID")
    else:
        checks = (
            (step187_result.get("integration_revision") == "STEP_187_R1", "STEP_187_REVISION_NOT_ESTABLISHED"),
            (step187_result.get("commit_time_accountability_standing") == STEP187_STANDING, "STEP_187_STANDING_NOT_SUPPORTABLE"),
            (step187_result.get("commit_time_decision") == STEP187_DECISION, "STEP_187_DECISION_NOT_SUPPORTABLE"),
            (step187_result.get("no_bind_state") == STEP187_NO_BIND, "STEP_187_NO_BIND_CONTRACT_INVALID"),
            (step187_result.get("action_held") is False, "STEP_187_ACTION_HOLD_NOT_CLEARED"),
            (step187_result.get("step_186_result_consumed") is True, "STEP_187_STEP_186_CONSUMPTION_NOT_ESTABLISHED"),
            (step187_result.get("step_180_result_consumed") is True, "STEP_187_STEP_180_CONSUMPTION_NOT_ESTABLISHED"),
            (step187_result.get("current_snapshot_consumed") is True, "STEP_187_SNAPSHOT_CONSUMPTION_NOT_ESTABLISHED"),
            (step187_result.get("commit_binding_checked") is True, "STEP_187_COMMIT_BINDING_NOT_ESTABLISHED"),
            (step187_result.get("source_identity_checked") is True, "STEP_187_SOURCE_IDENTITY_NOT_ESTABLISHED"),
            (step187_result.get("payload_digest_binding_checked") is True, "STEP_187_PAYLOAD_BINDING_NOT_ESTABLISHED"),
            (step187_result.get("commit_temporal_currentness_checked") is True, "STEP_187_TEMPORAL_CURRENTNESS_NOT_ESTABLISHED"),
            (step187_result.get("binding_provenance_manufactured") is False, "STEP_187_PROVENANCE_BOUNDARY_INVALID"),
            (step187_result.get("binding_authority_granted") is False, "STEP_187_AUTHORITY_BOUNDARY_INVALID"),
            (step187_result.get("action_admissibility_granted") is False, "STEP_187_ACTION_ADMISSIBILITY_BOUNDARY_INVALID"),
            (step187_result.get("commit_authorized") is False, "STEP_187_COMMIT_AUTHORITY_BOUNDARY_INVALID"),
            (step187_result.get("execution_authorized") is False, "STEP_187_EXECUTION_BOUNDARY_INVALID"),
            (step187_result.get("physical_action_executed") is False, "STEP_187_PHYSICAL_ACTION_BOUNDARY_INVALID"),
            (step187_result.get("regulated_release_or_disposition_authorized") is False, "STEP_187_RELEASE_BOUNDARY_INVALID"),
            (step187_result.get("historical_facts_rewritten") is False, "STEP_187_HISTORY_BOUNDARY_INVALID"),
            (step187_result.get("irlt_mag_state_changed") is False, "STEP_187_IRLT_BOUNDARY_INVALID"),
        )
        for ok, reason in checks:
            if not ok:
                reasons.append(reason)
        step187_reasons = step187_result.get("reasons")
        if type(step187_reasons) is not list or step187_reasons:
            reasons.append("STEP_187_SUPPORTABLE_RESULT_REASONS_INVALID")
        if scope is not None and step187_result.get("expected_scope_id") != scope:
            reasons.append("STEP_187_SCOPE_MISMATCH")
        if action is not None and step187_result.get("expected_action_id") != action:
            reasons.append("STEP_187_ACTION_MISMATCH")
        if obj is not None and step187_result.get("expected_object_hash") != obj:
            reasons.append("STEP_187_OBJECT_MISMATCH")

    # Re-establish the exact Step 187 current-state binding at this boundary.
    if not isinstance(step187_current_snapshot, Mapping):
        reasons.append("STEP_187_CURRENT_SNAPSHOT_MISSING_OR_INVALID")
    else:
        for field in STEP187_SNAPSHOT_FIELDS:
            if field not in step187_current_snapshot:
                reasons.append("STEP_187_CURRENT_" + field.upper() + "_MISSING")
        if step187_current_snapshot.get("authority_current") is not True:
            reasons.append("STEP_187_CURRENT_AUTHORITY_NOT_ESTABLISHED")
        if action is not None and step187_current_snapshot.get("action_id") != action:
            reasons.append("STEP_187_CURRENT_ACTION_MISMATCH")
        if obj is not None and step187_current_snapshot.get("object_hash") != obj:
            reasons.append("STEP_187_CURRENT_OBJECT_MISMATCH")

    if not isinstance(step187_commit_binding_record, Mapping):
        reasons.append("STEP_187_COMMIT_BINDING_RECORD_MISSING_OR_INVALID")
    else:
        for field in (
            "declared_scope_id",
            "action_id",
            "object_hash",
            "commit_point_id",
            "commit_binding_evidence_ref",
            "commit_binding_basis_version",
            "step186_result_digest",
            "step180_result_digest",
            "current_snapshot_digest",
            "step186_evaluator_blob",
            "step186_test_blob",
            "step180_evaluator_blob",
            "step180_test_blob",
        ):
            if not _valid_nonempty(step187_commit_binding_record.get(field)):
                reasons.append("STEP_187_BINDING_" + field.upper() + "_MISSING_OR_INVALID")
        if step187_commit_binding_record.get("binding_traceable") is not True:
            reasons.append("STEP_187_BINDING_NOT_TRACEABLE")
        if step187_commit_binding_record.get("binding_current") is not True:
            reasons.append("STEP_187_BINDING_NOT_CURRENT")
        if step187_commit_binding_record.get("binding_ambiguity_present") is not False:
            reasons.append("STEP_187_BINDING_AMBIGUOUS_OR_INVALID")
        if step187_commit_binding_record.get("binding_temporal_ordering_established") is not True:
            reasons.append("STEP_187_BINDING_TEMPORAL_ORDERING_NOT_ESTABLISHED")
        if step187_commit_binding_record.get("binding_change_assessment_complete") is not True:
            reasons.append("STEP_187_BINDING_CHANGE_ASSESSMENT_INCOMPLETE")
        material_change = step187_commit_binding_record.get("material_change_after_commit_binding")
        revalidated = step187_commit_binding_record.get("commit_binding_revalidated_after_latest_material_change")
        if type(material_change) is not bool:
            reasons.append("STEP_187_BINDING_MATERIAL_CHANGE_STATE_INVALID")
        if type(revalidated) is not bool:
            reasons.append("STEP_187_BINDING_REVALIDATION_STATE_INVALID")
        if material_change is True and revalidated is not True:
            reasons.append("STEP_187_BINDING_STALE_AFTER_MATERIAL_CHANGE")
        if scope is not None and step187_commit_binding_record.get("declared_scope_id") != scope:
            reasons.append("STEP_187_BINDING_SCOPE_MISMATCH")
        if action is not None and step187_commit_binding_record.get("action_id") != action:
            reasons.append("STEP_187_BINDING_ACTION_MISMATCH")
        if obj is not None and step187_commit_binding_record.get("object_hash") != obj:
            reasons.append("STEP_187_BINDING_OBJECT_MISMATCH")
        if isinstance(step187_current_snapshot, Mapping):
            snapshot_digest = canonical_payload_digest(step187_current_snapshot)
            if snapshot_digest is None:
                reasons.append("STEP_187_CURRENT_SNAPSHOT_DIGEST_NOT_COMPUTABLE")
            elif step187_commit_binding_record.get("current_snapshot_digest") != snapshot_digest:
                reasons.append("STEP_187_BINDING_CURRENT_SNAPSHOT_DIGEST_MISMATCH")

    # Step 181 issued-token contract plus deterministic token reconstruction.
    if not isinstance(step181_token, Mapping):
        reasons.append("STEP_181_TOKEN_MISSING_OR_INVALID")
    else:
        checks = (
            (step181_token.get("token_state") == "ISSUED", "STEP_181_VALID_TOKEN_NOT_ISSUED"),
            (step181_token.get("revalidation_decision") == "ADMISSIBLE", "STEP_181_TOKEN_REVALIDATION_NOT_ADMISSIBLE"),
            (step181_token.get("single_use_required") is True, "STEP_181_SINGLE_USE_REQUIREMENT_NOT_ESTABLISHED"),
            (step181_token.get("binding_authority_granted") is False, "STEP_181_TOKEN_AUTHORITY_BOUNDARY_INVALID"),
            (step181_token.get("physical_action_executed") is False, "STEP_181_TOKEN_PHYSICAL_ACTION_BOUNDARY_INVALID"),
        )
        for ok, reason in checks:
            if not ok:
                reasons.append(reason)
        token_reasons = step181_token.get("reasons")
        if type(token_reasons) is not list or token_reasons:
            reasons.append("STEP_181_ISSUED_TOKEN_REASONS_INVALID")
        if action is not None and step181_token.get("action_id") != action:
            reasons.append("STEP_181_TOKEN_ACTION_MISMATCH")
        if transaction is not None and step181_token.get("transaction_id") != transaction:
            reasons.append("STEP_181_TOKEN_TRANSACTION_MISMATCH")
        if nonce is not None and step181_token.get("commit_nonce") != nonce:
            reasons.append("STEP_181_TOKEN_NONCE_MISMATCH")
        if obj is not None and step181_token.get("object_hash") != obj:
            reasons.append("STEP_181_TOKEN_OBJECT_MISMATCH")

        token_material = {
            "action_id": step181_token.get("action_id"),
            "transaction_id": step181_token.get("transaction_id"),
            "commit_nonce": step181_token.get("commit_nonce"),
            "object_hash": step181_token.get("object_hash"),
            "snapshot_digest": step181_token.get("snapshot_digest"),
        }
        expected_token_id = step181_digest(token_material)
        if expected_token_id is None:
            reasons.append("STEP_181_TOKEN_ID_NOT_COMPUTABLE")
        elif step181_token.get("token_id") != expected_token_id:
            reasons.append("STEP_181_TOKEN_ID_MISMATCH")

    # Exact commit snapshot correspondence.
    if not isinstance(commit_snapshot, Mapping):
        reasons.append("COMMIT_SNAPSHOT_MISSING_OR_INVALID")
    else:
        for field in STEP181_SNAPSHOT_FIELDS:
            if field not in commit_snapshot:
                reasons.append("COMMIT_" + field.upper() + "_MISSING")
        if commit_snapshot.get("authority_current") is not True:
            reasons.append("COMMIT_AUTHORITY_NOT_CURRENT")
        if obj is not None and commit_snapshot.get("object_hash") != obj:
            reasons.append("COMMIT_OBJECT_MISMATCH")
        snapshot_digest = step181_digest(commit_snapshot)
        if snapshot_digest is None:
            reasons.append("COMMIT_SNAPSHOT_STEP_181_DIGEST_NOT_COMPUTABLE")
        elif isinstance(step181_token, Mapping) and step181_token.get("snapshot_digest") != snapshot_digest:
            reasons.append("STEP_181_TOKEN_SNAPSHOT_DIGEST_MISMATCH")

    # Cross-snapshot equality: Step 187 state must still be the Step 181 commit state.
    if isinstance(step187_current_snapshot, Mapping) and isinstance(commit_snapshot, Mapping):
        for field in STEP181_SNAPSHOT_FIELDS:
            if step187_current_snapshot.get(field) != commit_snapshot.get(field):
                reasons.append("STEP_187_TO_STEP_181_" + field.upper() + "_MISMATCH")

    # Reproduce Step 181 verification from exact inputs and require exact result equality.
    reproduced_step181_result = None
    if isinstance(step181_token, Mapping) and isinstance(commit_snapshot, Mapping):
        reproduced_step181_result = reproduce_step181_verify(
            token=step181_token,
            commit_snapshot=commit_snapshot,
            action_id=expected_action_id,
            transaction_id=expected_transaction_id,
            commit_nonce=expected_commit_nonce,
        )
        if reproduced_step181_result is None:
            reasons.append("STEP_181_COMMIT_RESULT_REPRODUCTION_NOT_COMPUTABLE")

    if not isinstance(step181_commit_result, Mapping):
        reasons.append("STEP_181_COMMIT_RESULT_MISSING_OR_INVALID")
    else:
        checks = (
            (step181_commit_result.get("atomic_commit_standing") == "SUPPORTABLE", "STEP_181_ATOMIC_COMMIT_NOT_SUPPORTABLE"),
            (step181_commit_result.get("commit_decision") == "COMMIT_ROUTE_ADMISSIBLE", "STEP_181_COMMIT_ROUTE_NOT_ADMISSIBLE"),
            (step181_commit_result.get("no_bind_state") == "INACTIVE", "STEP_181_NO_BIND_ACTIVE_OR_INVALID"),
            (step181_commit_result.get("action_held") is False, "STEP_181_ACTION_HOLD_NOT_CLEARED"),
            (step181_commit_result.get("token_consumption_required_on_commit") is True, "STEP_181_TOKEN_CONSUMPTION_REQUIREMENT_NOT_ESTABLISHED"),
            (step181_commit_result.get("evaluated_to_committed_binding_verified") is True, "STEP_181_ATOMIC_BINDING_NOT_VERIFIED"),
            (step181_commit_result.get("binding_authority_granted") is False, "STEP_181_COMMIT_AUTHORITY_BOUNDARY_INVALID"),
            (step181_commit_result.get("physical_action_executed") is False, "STEP_181_COMMIT_PHYSICAL_ACTION_BOUNDARY_INVALID"),
        )
        for ok, reason in checks:
            if not ok:
                reasons.append(reason)
        commit_reasons = step181_commit_result.get("reasons")
        if type(commit_reasons) is not list or commit_reasons:
            reasons.append("STEP_181_SUPPORTABLE_COMMIT_RESULT_REASONS_INVALID")
        if reproduced_step181_result is not None and dict(step181_commit_result) != reproduced_step181_result:
            reasons.append("STEP_181_COMMIT_RESULT_NOT_REPRODUCIBLE_FROM_EXACT_INPUTS")

    # Explicit Step 188 binding evidence.
    if not isinstance(atomic_binding_record, Mapping):
        reasons.append("ATOMIC_ACCOUNTABILITY_BINDING_RECORD_MISSING_OR_INVALID")
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
        )
        for field in required_strings:
            if not _valid_nonempty(atomic_binding_record.get(field)):
                reasons.append("ATOMIC_BINDING_" + field.upper() + "_MISSING_OR_INVALID")

        if atomic_binding_record.get("binding_traceable") is not True:
            reasons.append("ATOMIC_BINDING_NOT_TRACEABLE")
        if atomic_binding_record.get("binding_current") is not True:
            reasons.append("ATOMIC_BINDING_NOT_CURRENT")
        if atomic_binding_record.get("binding_ambiguity_present") is not False:
            reasons.append("ATOMIC_BINDING_AMBIGUOUS_OR_INVALID")
        if atomic_binding_record.get("binding_temporal_ordering_established") is not True:
            reasons.append("ATOMIC_BINDING_TEMPORAL_ORDERING_NOT_ESTABLISHED")
        if atomic_binding_record.get("binding_change_assessment_complete") is not True:
            reasons.append("ATOMIC_BINDING_CHANGE_ASSESSMENT_INCOMPLETE")

        material_change = atomic_binding_record.get("material_change_after_atomic_binding")
        revalidated = atomic_binding_record.get("atomic_binding_revalidated_after_latest_material_change")
        if type(material_change) is not bool:
            reasons.append("ATOMIC_BINDING_MATERIAL_CHANGE_STATE_INVALID")
        if type(revalidated) is not bool:
            reasons.append("ATOMIC_BINDING_REVALIDATION_STATE_INVALID")
        if material_change is True and revalidated is not True:
            reasons.append("ATOMIC_BINDING_STALE_AFTER_MATERIAL_CHANGE")

        for field, expected, reason in (
            ("declared_scope_id", scope, "ATOMIC_BINDING_SCOPE_MISMATCH"),
            ("action_id", action, "ATOMIC_BINDING_ACTION_MISMATCH"),
            ("object_hash", obj, "ATOMIC_BINDING_OBJECT_MISMATCH"),
            ("transaction_id", transaction, "ATOMIC_BINDING_TRANSACTION_MISMATCH"),
            ("commit_nonce", nonce, "ATOMIC_BINDING_NONCE_MISMATCH"),
        ):
            if expected is not None and atomic_binding_record.get(field) != expected:
                reasons.append(reason)

        source_checks = (
            ("step187_evaluator_blob", STEP187_EVALUATOR_BLOB, "STEP_187_FROZEN_EVALUATOR_IDENTITY_MISMATCH"),
            ("step187_primary_test_blob", STEP187_PRIMARY_TEST_BLOB, "STEP_187_FROZEN_PRIMARY_TEST_IDENTITY_MISMATCH"),
            ("step187_hardening_test_blob", STEP187_HARDENING_TEST_BLOB, "STEP_187_FROZEN_HARDENING_TEST_IDENTITY_MISMATCH"),
            ("step181_evaluator_blob", STEP181_EVALUATOR_BLOB, "STEP_181_EVALUATOR_IDENTITY_MISMATCH"),
            ("step181_test_blob", STEP181_TEST_BLOB, "STEP_181_TEST_IDENTITY_MISMATCH"),
        )
        for field, expected, reason in source_checks:
            if atomic_binding_record.get(field) != expected:
                reasons.append(reason)

        digest_inputs = (
            ("step187_result_digest", step187_result, "STEP_187_PAYLOAD_DIGEST_NOT_COMPUTABLE", "ATOMIC_BINDING_STEP_187_PAYLOAD_DIGEST_MISMATCH"),
            ("step187_commit_binding_record_digest", step187_commit_binding_record, "STEP_187_BINDING_RECORD_DIGEST_NOT_COMPUTABLE", "ATOMIC_BINDING_STEP_187_BINDING_RECORD_DIGEST_MISMATCH"),
            ("step187_current_snapshot_digest", step187_current_snapshot, "STEP_187_CURRENT_SNAPSHOT_PAYLOAD_DIGEST_NOT_COMPUTABLE", "ATOMIC_BINDING_STEP_187_CURRENT_SNAPSHOT_DIGEST_MISMATCH"),
            ("step181_token_digest", step181_token, "STEP_181_TOKEN_PAYLOAD_DIGEST_NOT_COMPUTABLE", "ATOMIC_BINDING_STEP_181_TOKEN_DIGEST_MISMATCH"),
            ("step181_commit_result_digest", step181_commit_result, "STEP_181_COMMIT_RESULT_DIGEST_NOT_COMPUTABLE", "ATOMIC_BINDING_STEP_181_COMMIT_RESULT_DIGEST_MISMATCH"),
            ("commit_snapshot_digest", commit_snapshot, "COMMIT_SNAPSHOT_PAYLOAD_DIGEST_NOT_COMPUTABLE", "ATOMIC_BINDING_COMMIT_SNAPSHOT_DIGEST_MISMATCH"),
        )
        for field, payload, not_computable_reason, mismatch_reason in digest_inputs:
            if isinstance(payload, Mapping):
                digest = canonical_payload_digest(payload)
                if digest is None:
                    reasons.append(not_computable_reason)
                elif atomic_binding_record.get(field) != digest:
                    reasons.append(mismatch_reason)

        if isinstance(step187_result, Mapping):
            if atomic_binding_record.get("declared_scope_id") != step187_result.get("expected_scope_id"):
                reasons.append("ATOMIC_BINDING_SCOPE_DOES_NOT_MATCH_STEP_187")
            if atomic_binding_record.get("action_id") != step187_result.get("expected_action_id"):
                reasons.append("ATOMIC_BINDING_ACTION_DOES_NOT_MATCH_STEP_187")
            if atomic_binding_record.get("object_hash") != step187_result.get("expected_object_hash"):
                reasons.append("ATOMIC_BINDING_OBJECT_DOES_NOT_MATCH_STEP_187")

        if isinstance(step181_token, Mapping) and isinstance(commit_snapshot, Mapping):
            verification_payload = verification_input_payload(
                token=step181_token,
                commit_snapshot=commit_snapshot,
                action_id=expected_action_id,
                transaction_id=expected_transaction_id,
                commit_nonce=expected_commit_nonce,
            )
            verification_digest = canonical_payload_digest(verification_payload)
            if verification_digest is None:
                reasons.append("STEP_181_VERIFICATION_INPUT_DIGEST_NOT_COMPUTABLE")
            elif atomic_binding_record.get("step181_verification_input_digest") != verification_digest:
                reasons.append("ATOMIC_BINDING_STEP_181_VERIFICATION_INPUT_DIGEST_MISMATCH")

    blocked = bool(reasons)

    return {
        "integration_revision": "STEP_188_R1",
        "atomic_accountability_standing": NOT_ESTABLISHED if blocked else SUPPORTABLE,
        "atomic_accountability_decision": "NOT_SUPPORTABLE" if blocked else "ACCOUNTABILITY_ATOMIC_COMMIT_PREREQUISITES_SUPPORTABLE",
        "no_bind_state": "ACTIVE" if blocked else "SEPARATE_AUTHORIZED_COMMIT_EXECUTION_AND_TOKEN_CONSUMPTION_REQUIRED",
        "action_held": blocked,
        "caller_requested_decision": caller_requested_decision,
        "caller_override_rejected": blocked and caller_requested_decision in {"COMMIT", "EXECUTE", "ADMISSIBLE"},
        "expected_scope_id": expected_scope_id,
        "expected_action_id": expected_action_id,
        "expected_object_hash": expected_object_hash,
        "expected_transaction_id": expected_transaction_id,
        "expected_commit_nonce": expected_commit_nonce,
        "reasons": sorted(set(reasons)),
        "step_187_result_consumed": True,
        "step_187_binding_record_consumed": True,
        "step_187_current_snapshot_consumed": True,
        "step_181_token_consumed_as_evidence": True,
        "step_181_commit_result_consumed": True,
        "commit_snapshot_consumed": True,
        "step_181_commit_result_reproduced": reproduced_step181_result is not None,
        "cross_snapshot_state_equality_checked": True,
        "atomic_cross_binding_checked": True,
        "source_identity_checked": True,
        "payload_digest_binding_checked": True,
        "atomic_temporal_currentness_checked": True,
        "token_consumption_required_on_authorized_commit": True,
        "binding_provenance_manufactured": False,
        "binding_authority_granted": False,
        "action_admissibility_granted": False,
        "commit_authorized": False,
        "execution_authorized": False,
        "commit_token_consumed_by_evaluator": False,
        "physical_action_executed": False,
        "regulated_release_or_disposition_authorized": False,
        "historical_facts_rewritten": False,
        "irlt_mag_state_changed": False,
    }
