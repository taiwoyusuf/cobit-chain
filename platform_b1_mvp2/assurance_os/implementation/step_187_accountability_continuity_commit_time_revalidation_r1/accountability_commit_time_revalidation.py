"""Step 187 — Accountability Continuity Commit-Time Revalidation R1.

This bounded adapter composes a frozen Step 186 accountability-boundary result
with an existing Step 180 execution-time revalidation result and an explicit
commit-binding evidence record.

It does not modify Step 180, Step 185, or Step 186; grant authority; grant Action
Admissibility; authorize commit/execution; execute physical action; or modify
IRLT-MAG state.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping


SUPPORTABLE = "ACCOUNTABILITY_COMMIT_TIME_CONTINUITY_SUPPORTABLE"
NOT_ESTABLISHED = "ACCOUNTABILITY_COMMIT_TIME_CONTINUITY_NOT_ESTABLISHED"

STEP186_SUPPORTABLE = "ACCOUNTABILITY_BOUNDARY_INTEGRATION_SUPPORTABLE"
STEP186_DECISION = "ACCOUNTABILITY_BOUNDARY_PREREQUISITES_SUPPORTABLE"
STEP186_NO_BIND = "SEPARATE_EXECUTION_TIME_REVALIDATION_REQUIRED"

STEP186_EVALUATOR_BLOB = "356d7b249dff4c0c48be24e6470f2519cae0594d"
STEP186_TEST_BLOB = "a9acc4cdc0d1288999744760eac2223d55963a54"
STEP180_EVALUATOR_BLOB = "c5d84fc6532632a282fe4f80fbbec9bd3594772f"
STEP180_TEST_BLOB = "07ce7a902be2542d77bd50f70892680e54af026a"

CURRENT_SNAPSHOT_STRING_FIELDS = (
    "action_id",
    "object_hash",
    "evidence_digest",
    "criteria_version",
    "configuration_hash",
    "environment_context_hash",
)


def _valid_nonempty(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def canonical_payload_digest(record: Mapping[str, object]) -> str | None:
    """Return deterministic SHA-256 for a JSON-serializable mapping payload."""
    try:
        payload = json.dumps(dict(record), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError):
        return None
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def evaluate_accountability_commit_time_revalidation(
    *,
    step186_result: Mapping[str, object],
    step180_result: Mapping[str, object],
    current_snapshot: Mapping[str, object],
    commit_binding_record: Mapping[str, object],
    expected_scope_id: str,
    expected_action_id: str,
    expected_object_hash: str,
    caller_requested_decision: str,
) -> dict[str, object]:
    """Fail closed unless accountability continuity remains bound at commit time."""

    reasons: list[str] = []

    for name, value in (
        ("EXPECTED_SCOPE_ID", expected_scope_id),
        ("EXPECTED_ACTION_ID", expected_action_id),
        ("EXPECTED_OBJECT_HASH", expected_object_hash),
    ):
        if not _valid_nonempty(value):
            reasons.append(name + "_MISSING_OR_INVALID")

    scope = expected_scope_id.strip() if _valid_nonempty(expected_scope_id) else None
    action = expected_action_id.strip() if _valid_nonempty(expected_action_id) else None
    obj = expected_object_hash.strip() if _valid_nonempty(expected_object_hash) else None

    # Frozen Step 186 contract correspondence.
    if not isinstance(step186_result, Mapping):
        reasons.append("STEP_186_RESULT_MISSING_OR_INVALID")
    else:
        checks = (
            (step186_result.get("integration_revision") == "STEP_186_R1", "STEP_186_RESULT_REVISION_NOT_ESTABLISHED"),
            (step186_result.get("integration_standing") == STEP186_SUPPORTABLE, "STEP_186_INTEGRATION_NOT_SUPPORTABLE"),
            (step186_result.get("integration_decision") == STEP186_DECISION, "STEP_186_DECISION_NOT_SUPPORTABLE"),
            (step186_result.get("no_bind_state") == STEP186_NO_BIND, "STEP_186_NO_BIND_CONTRACT_INVALID"),
            (step186_result.get("action_held") is False, "STEP_186_ACTION_HOLD_NOT_CLEARED"),
            (step186_result.get("step_185_result_consumed") is True, "STEP_186_STEP_185_CONSUMPTION_NOT_ESTABLISHED"),
            (step186_result.get("step_179_result_consumed") is True, "STEP_186_STEP_179_CONSUMPTION_NOT_ESTABLISHED"),
            (step186_result.get("scope_action_object_binding_checked") is True, "STEP_186_SCOPE_ACTION_OBJECT_BINDING_NOT_ESTABLISHED"),
            (step186_result.get("payload_digest_binding_checked") is True, "STEP_186_PAYLOAD_BINDING_NOT_ESTABLISHED"),
            (step186_result.get("binding_temporal_currentness_checked") is True, "STEP_186_BINDING_CURRENTNESS_NOT_ESTABLISHED"),
            (step186_result.get("binding_provenance_manufactured") is False, "STEP_186_PROVENANCE_BOUNDARY_INVALID"),
            (step186_result.get("binding_authority_granted") is False, "STEP_186_AUTHORITY_BOUNDARY_INVALID"),
            (step186_result.get("action_admissibility_granted") is False, "STEP_186_ACTION_ADMISSIBILITY_BOUNDARY_INVALID"),
            (step186_result.get("execution_authorized") is False, "STEP_186_EXECUTION_BOUNDARY_INVALID"),
            (step186_result.get("physical_action_executed") is False, "STEP_186_PHYSICAL_ACTION_BOUNDARY_INVALID"),
            (step186_result.get("historical_facts_rewritten") is False, "STEP_186_HISTORY_BOUNDARY_INVALID"),
            (step186_result.get("irlt_mag_state_changed") is False, "STEP_186_IRLT_BOUNDARY_INVALID"),
            (step186_result.get("separate_execution_time_revalidation_required") is True, "STEP_186_EXECUTION_REVALIDATION_REQUIREMENT_NOT_ESTABLISHED"),
        )
        for ok, reason in checks:
            if not ok:
                reasons.append(reason)

        step186_reasons = step186_result.get("reasons")
        if type(step186_reasons) is not list or step186_reasons:
            reasons.append("STEP_186_SUPPORTABLE_RESULT_REASONS_INVALID")

        if scope is not None and step186_result.get("expected_scope_id") != scope:
            reasons.append("STEP_186_SCOPE_MISMATCH")
        if action is not None and step186_result.get("expected_action_id") != action:
            reasons.append("STEP_186_ACTION_MISMATCH")
        if obj is not None and step186_result.get("expected_object_hash") != obj:
            reasons.append("STEP_186_OBJECT_MISMATCH")

    # Existing Step 180 execution-time revalidation contract correspondence.
    if not isinstance(step180_result, Mapping):
        reasons.append("STEP_180_RESULT_MISSING_OR_INVALID")
    else:
        checks = (
            (step180_result.get("execution_time_standing") == "SUPPORTABLE", "STEP_180_EXECUTION_TIME_STANDING_NOT_SUPPORTABLE"),
            (step180_result.get("execution_time_decision") == "ADMISSIBLE", "STEP_180_DECISION_NOT_ADMISSIBLE"),
            (step180_result.get("no_bind_state") == "INACTIVE", "STEP_180_NO_BIND_ACTIVE_OR_INVALID"),
            (step180_result.get("action_held") is False, "STEP_180_ACTION_HOLD_NOT_CLEARED"),
            (step180_result.get("escalation_required") is False, "STEP_180_ESCALATION_REMAINS_REQUIRED"),
            (step180_result.get("prior_decision_preserved_as_history") is True, "STEP_180_HISTORY_CONTRACT_NOT_ESTABLISHED"),
            (step180_result.get("binding_authority_granted") is False, "STEP_180_AUTHORITY_BOUNDARY_INVALID"),
            (step180_result.get("physical_action_executed") is False, "STEP_180_PHYSICAL_ACTION_BOUNDARY_INVALID"),
            (step180_result.get("commit_revalidation_performed") is True, "STEP_180_COMMIT_REVALIDATION_NOT_ESTABLISHED"),
        )
        for ok, reason in checks:
            if not ok:
                reasons.append(reason)

        step180_reasons = step180_result.get("reasons")
        if type(step180_reasons) is not list or step180_reasons:
            reasons.append("STEP_180_SUPPORTABLE_RESULT_REASONS_INVALID")

        decision_age = step180_result.get("decision_age_ms")
        max_age = step180_result.get("max_decision_age_ms")
        if type(decision_age) is not int or type(max_age) is not int or decision_age < 0 or max_age < 0:
            reasons.append("STEP_180_DECISION_AGE_CONTRACT_INVALID")
        elif decision_age > max_age:
            reasons.append("STEP_180_PRIOR_DECISION_STALE")

        changed_dimensions = step180_result.get("changed_dimensions")
        immaterial_changes = step180_result.get("immaterial_changes")
        material_changes = step180_result.get("material_changes")
        unclassified_changes = step180_result.get("unclassified_changes")
        if type(changed_dimensions) is not list:
            reasons.append("STEP_180_CHANGED_DIMENSIONS_CONTRACT_INVALID")
        if type(immaterial_changes) is not list:
            reasons.append("STEP_180_IMMATERIAL_CHANGE_CONTRACT_INVALID")
        if type(material_changes) is not list or material_changes:
            reasons.append("STEP_180_MATERIAL_CHANGE_CONTRACT_INVALID")
        if type(unclassified_changes) is not list or unclassified_changes:
            reasons.append("STEP_180_UNCLASSIFIED_CHANGE_CONTRACT_INVALID")
        if type(changed_dimensions) is list and type(immaterial_changes) is list:
            if sorted(changed_dimensions) != sorted(immaterial_changes):
                reasons.append("STEP_180_SUPPORTABLE_CHANGE_CLASSIFICATION_INCONSISTENT")

    # Current commit snapshot identity/correspondence.
    if not isinstance(current_snapshot, Mapping):
        reasons.append("CURRENT_COMMIT_SNAPSHOT_MISSING_OR_INVALID")
    else:
        for field in CURRENT_SNAPSHOT_STRING_FIELDS:
            if not _valid_nonempty(current_snapshot.get(field)):
                reasons.append("CURRENT_" + field.upper() + "_MISSING_OR_INVALID")
        if current_snapshot.get("authority_current") is not True:
            reasons.append("CURRENT_AUTHORITY_NOT_ESTABLISHED_AT_COMMIT")
        if action is not None and current_snapshot.get("action_id") != action:
            reasons.append("CURRENT_ACTION_MISMATCH")
        if obj is not None and current_snapshot.get("object_hash") != obj:
            reasons.append("CURRENT_OBJECT_MISMATCH")

    # Explicit commit binding evidence over Step 186, Step 180 and current snapshot.
    if not isinstance(commit_binding_record, Mapping):
        reasons.append("COMMIT_BINDING_RECORD_MISSING_OR_INVALID")
    else:
        required_strings = (
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
        )
        for field in required_strings:
            if not _valid_nonempty(commit_binding_record.get(field)):
                reasons.append("COMMIT_BINDING_" + field.upper() + "_MISSING_OR_INVALID")

        if commit_binding_record.get("binding_traceable") is not True:
            reasons.append("COMMIT_BINDING_NOT_TRACEABLE")
        if commit_binding_record.get("binding_current") is not True:
            reasons.append("COMMIT_BINDING_NOT_CURRENT")
        if commit_binding_record.get("binding_ambiguity_present") is not False:
            reasons.append("COMMIT_BINDING_AMBIGUOUS_OR_INVALID")
        if commit_binding_record.get("binding_temporal_ordering_established") is not True:
            reasons.append("COMMIT_BINDING_TEMPORAL_ORDERING_NOT_ESTABLISHED")
        if commit_binding_record.get("binding_change_assessment_complete") is not True:
            reasons.append("COMMIT_BINDING_CHANGE_ASSESSMENT_INCOMPLETE")

        material_after_binding = commit_binding_record.get("material_change_after_commit_binding")
        revalidated_after_change = commit_binding_record.get("commit_binding_revalidated_after_latest_material_change")
        if type(material_after_binding) is not bool:
            reasons.append("COMMIT_BINDING_MATERIAL_CHANGE_STATE_INVALID")
        if type(revalidated_after_change) is not bool:
            reasons.append("COMMIT_BINDING_REVALIDATION_STATE_INVALID")
        if material_after_binding is True and revalidated_after_change is not True:
            reasons.append("COMMIT_BINDING_STALE_AFTER_MATERIAL_CHANGE")

        if scope is not None and commit_binding_record.get("declared_scope_id") != scope:
            reasons.append("COMMIT_BINDING_SCOPE_MISMATCH")
        if action is not None and commit_binding_record.get("action_id") != action:
            reasons.append("COMMIT_BINDING_ACTION_MISMATCH")
        if obj is not None and commit_binding_record.get("object_hash") != obj:
            reasons.append("COMMIT_BINDING_OBJECT_MISMATCH")

        if commit_binding_record.get("step186_evaluator_blob") != STEP186_EVALUATOR_BLOB:
            reasons.append("STEP_186_FROZEN_EVALUATOR_IDENTITY_MISMATCH")
        if commit_binding_record.get("step186_test_blob") != STEP186_TEST_BLOB:
            reasons.append("STEP_186_FROZEN_TEST_IDENTITY_MISMATCH")
        if commit_binding_record.get("step180_evaluator_blob") != STEP180_EVALUATOR_BLOB:
            reasons.append("STEP_180_EVALUATOR_IDENTITY_MISMATCH")
        if commit_binding_record.get("step180_test_blob") != STEP180_TEST_BLOB:
            reasons.append("STEP_180_TEST_IDENTITY_MISMATCH")

        if isinstance(step186_result, Mapping):
            digest = canonical_payload_digest(step186_result)
            if digest is None:
                reasons.append("STEP_186_PAYLOAD_DIGEST_NOT_COMPUTABLE")
            elif commit_binding_record.get("step186_result_digest") != digest:
                reasons.append("COMMIT_BINDING_STEP_186_PAYLOAD_DIGEST_MISMATCH")
            if commit_binding_record.get("declared_scope_id") != step186_result.get("expected_scope_id"):
                reasons.append("COMMIT_BINDING_SCOPE_DOES_NOT_MATCH_STEP_186")
            if commit_binding_record.get("action_id") != step186_result.get("expected_action_id"):
                reasons.append("COMMIT_BINDING_ACTION_DOES_NOT_MATCH_STEP_186")
            if commit_binding_record.get("object_hash") != step186_result.get("expected_object_hash"):
                reasons.append("COMMIT_BINDING_OBJECT_DOES_NOT_MATCH_STEP_186")

        if isinstance(step180_result, Mapping):
            digest = canonical_payload_digest(step180_result)
            if digest is None:
                reasons.append("STEP_180_PAYLOAD_DIGEST_NOT_COMPUTABLE")
            elif commit_binding_record.get("step180_result_digest") != digest:
                reasons.append("COMMIT_BINDING_STEP_180_PAYLOAD_DIGEST_MISMATCH")

        if isinstance(current_snapshot, Mapping):
            digest = canonical_payload_digest(current_snapshot)
            if digest is None:
                reasons.append("CURRENT_SNAPSHOT_DIGEST_NOT_COMPUTABLE")
            elif commit_binding_record.get("current_snapshot_digest") != digest:
                reasons.append("COMMIT_BINDING_CURRENT_SNAPSHOT_DIGEST_MISMATCH")
            if commit_binding_record.get("action_id") != current_snapshot.get("action_id"):
                reasons.append("COMMIT_BINDING_ACTION_DOES_NOT_MATCH_CURRENT_SNAPSHOT")
            if commit_binding_record.get("object_hash") != current_snapshot.get("object_hash"):
                reasons.append("COMMIT_BINDING_OBJECT_DOES_NOT_MATCH_CURRENT_SNAPSHOT")

    blocked = bool(reasons)

    return {
        "integration_revision": "STEP_187_R1",
        "commit_time_accountability_standing": NOT_ESTABLISHED if blocked else SUPPORTABLE,
        "commit_time_decision": "NOT_SUPPORTABLE" if blocked else "ACCOUNTABILITY_COMMIT_PREREQUISITES_SUPPORTABLE",
        "no_bind_state": "ACTIVE" if blocked else "SEPARATE_AUTHORIZED_COMMIT_MECHANISM_REQUIRED",
        "action_held": blocked,
        "caller_requested_decision": caller_requested_decision,
        "caller_override_rejected": blocked and caller_requested_decision in {"ADMISSIBLE", "COMMIT", "EXECUTE"},
        "expected_scope_id": expected_scope_id,
        "expected_action_id": expected_action_id,
        "expected_object_hash": expected_object_hash,
        "reasons": sorted(set(reasons)),
        "step_186_result_consumed": True,
        "step_180_result_consumed": True,
        "current_snapshot_consumed": True,
        "commit_binding_checked": True,
        "source_identity_checked": True,
        "payload_digest_binding_checked": True,
        "commit_temporal_currentness_checked": True,
        "binding_provenance_manufactured": False,
        "binding_authority_granted": False,
        "action_admissibility_granted": False,
        "commit_authorized": False,
        "execution_authorized": False,
        "physical_action_executed": False,
        "regulated_release_or_disposition_authorized": False,
        "historical_facts_rewritten": False,
        "irlt_mag_state_changed": False,
    }
