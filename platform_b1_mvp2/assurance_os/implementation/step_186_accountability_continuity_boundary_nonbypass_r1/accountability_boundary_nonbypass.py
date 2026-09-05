"""Step 186 — Accountability Continuity Boundary Non-Bypass R1.

This bounded adapter composes a frozen Step 185 Accountability Continuity result
with an existing Step 179 boundary-enforcement result and an explicit
scope/action/object binding record.

It does not replace or modify Step 185 or Step 179, grant authority, grant Action
Admissibility, perform execution, or modify IRLT-MAG state.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping


INTEGRATION_SUPPORTABLE = "ACCOUNTABILITY_BOUNDARY_INTEGRATION_SUPPORTABLE"
INTEGRATION_NOT_ESTABLISHED = "ACCOUNTABILITY_BOUNDARY_INTEGRATION_NOT_ESTABLISHED"

STEP185_SUPPORTABLE = "ACCOUNTABILITY_CONTINUITY_SUPPORTABLE"
STEP185_NO_BIND = "SEPARATE_AUTHORITY_AND_ACTION_ADMISSIBILITY_REQUIRED"


def _valid_nonempty(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def canonical_result_digest(record: Mapping[str, object]) -> str:
    """Return deterministic SHA-256 over the exact consumed mapping payload."""
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def evaluate_accountability_boundary_nonbypass(
    *,
    accountability_result: Mapping[str, object],
    boundary_enforcement_result: Mapping[str, object],
    binding_record: Mapping[str, object],
    expected_scope_id: str,
    expected_action_id: str,
    expected_object_hash: str,
    caller_requested_decision: str,
) -> dict[str, object]:
    """Fail closed unless accountability and boundary results are exactly bound.

    The binding record is evidence input. This adapter verifies structural,
    temporal, digest, and cross-result correspondence; it does not manufacture
    provenance or independently prove the truth of upstream assertions.
    """

    reasons: list[str] = []

    for field_name, value in (
        ("EXPECTED_SCOPE_ID", expected_scope_id),
        ("EXPECTED_ACTION_ID", expected_action_id),
        ("EXPECTED_OBJECT_HASH", expected_object_hash),
    ):
        if not _valid_nonempty(value):
            reasons.append(field_name + "_MISSING_OR_INVALID")

    scope = expected_scope_id.strip() if _valid_nonempty(expected_scope_id) else None
    action = expected_action_id.strip() if _valid_nonempty(expected_action_id) else None
    obj = expected_object_hash.strip() if _valid_nonempty(expected_object_hash) else None

    if not isinstance(accountability_result, Mapping):
        reasons.append("STEP_185_RESULT_MISSING_OR_INVALID")
    else:
        if accountability_result.get("candidate_revision") != "STEP_185_R1":
            reasons.append("STEP_185_RESULT_REVISION_NOT_ESTABLISHED")
        if accountability_result.get("accountability_continuity_standing") != STEP185_SUPPORTABLE:
            reasons.append("STEP_185_ACCOUNTABILITY_CONTINUITY_NOT_SUPPORTABLE")
        if accountability_result.get("accountability_basis_supportable") is not True:
            reasons.append("STEP_185_ACCOUNTABILITY_BASIS_NOT_SUPPORTABLE")
        if accountability_result.get("no_bind_state") != STEP185_NO_BIND:
            reasons.append("STEP_185_NO_BIND_CONTRACT_INVALID")
        if accountability_result.get("binding_authority_granted") is not False:
            reasons.append("STEP_185_AUTHORITY_BOUNDARY_INVALID")
        if accountability_result.get("accountability_manufactured_by_evaluator") is not False:
            reasons.append("STEP_185_MANUFACTURE_BOUNDARY_INVALID")
        if accountability_result.get("irlt_mag_state_changed") is not False:
            reasons.append("STEP_185_IRLT_BOUNDARY_INVALID")
        if scope is not None and accountability_result.get("declared_scope_id") != scope:
            reasons.append("STEP_185_DECLARED_SCOPE_MISMATCH")

    if not isinstance(boundary_enforcement_result, Mapping):
        reasons.append("STEP_179_RESULT_MISSING_OR_INVALID")
    else:
        if boundary_enforcement_result.get("enforcement_decision") != "ADMISSIBLE":
            reasons.append("STEP_179_BOUNDARY_DECISION_NOT_ADMISSIBLE")
        if boundary_enforcement_result.get("no_bind_state") != "INACTIVE":
            reasons.append("STEP_179_NO_BIND_ACTIVE_OR_INVALID")
        if boundary_enforcement_result.get("action_held") is not False:
            reasons.append("STEP_179_ACTION_HOLD_NOT_CLEARED")
        if boundary_enforcement_result.get("non_bypassability_enforced") is not True:
            reasons.append("STEP_179_NON_BYPASS_CONTRACT_NOT_ESTABLISHED")
        if boundary_enforcement_result.get("binding_authority_granted") is not False:
            reasons.append("STEP_179_AUTHORITY_BOUNDARY_INVALID")
        if boundary_enforcement_result.get("physical_action_executed") is not False:
            reasons.append("STEP_179_PHYSICAL_ACTION_BOUNDARY_INVALID")
        if obj is not None and boundary_enforcement_result.get("requested_object_hash") != obj:
            reasons.append("STEP_179_REQUESTED_OBJECT_MISMATCH")

    if not isinstance(binding_record, Mapping):
        reasons.append("SCOPE_ACTION_OBJECT_BINDING_RECORD_MISSING_OR_INVALID")
    else:
        binding_fields = {
            "declared_scope_id": "BINDING_SCOPE_ID",
            "action_id": "BINDING_ACTION_ID",
            "object_hash": "BINDING_OBJECT_HASH",
            "binding_evidence_ref": "BINDING_EVIDENCE_REF",
            "binding_basis_version": "BINDING_BASIS_VERSION",
            "step185_result_digest": "STEP_185_RESULT_DIGEST",
            "step179_result_digest": "STEP_179_RESULT_DIGEST",
        }
        for field, reason_prefix in binding_fields.items():
            if not _valid_nonempty(binding_record.get(field)):
                reasons.append(reason_prefix + "_MISSING_OR_INVALID")

        if binding_record.get("binding_traceable") is not True:
            reasons.append("SCOPE_ACTION_OBJECT_BINDING_NOT_TRACEABLE")
        if binding_record.get("binding_current") is not True:
            reasons.append("SCOPE_ACTION_OBJECT_BINDING_NOT_CURRENT")
        if binding_record.get("binding_ambiguity_present") is not False:
            reasons.append("SCOPE_ACTION_OBJECT_BINDING_AMBIGUOUS_OR_INVALID")
        if binding_record.get("binding_temporal_ordering_established") is not True:
            reasons.append("BINDING_TEMPORAL_ORDERING_NOT_ESTABLISHED")
        if binding_record.get("binding_change_assessment_complete") is not True:
            reasons.append("BINDING_CHANGE_ASSESSMENT_INCOMPLETE")

        if scope is not None and binding_record.get("declared_scope_id") != scope:
            reasons.append("BINDING_SCOPE_MISMATCH")
        if action is not None and binding_record.get("action_id") != action:
            reasons.append("BINDING_ACTION_MISMATCH")
        if obj is not None and binding_record.get("object_hash") != obj:
            reasons.append("BINDING_OBJECT_MISMATCH")

        if isinstance(accountability_result, Mapping):
            if binding_record.get("declared_scope_id") != accountability_result.get("declared_scope_id"):
                reasons.append("BINDING_SCOPE_DOES_NOT_MATCH_STEP_185_RESULT")
            if binding_record.get("step185_result_digest") != canonical_result_digest(accountability_result):
                reasons.append("BINDING_STEP_185_PAYLOAD_DIGEST_MISMATCH")
        if isinstance(boundary_enforcement_result, Mapping):
            if binding_record.get("object_hash") != boundary_enforcement_result.get("requested_object_hash"):
                reasons.append("BINDING_OBJECT_DOES_NOT_MATCH_STEP_179_RESULT")
            if binding_record.get("step179_result_digest") != canonical_result_digest(boundary_enforcement_result):
                reasons.append("BINDING_STEP_179_PAYLOAD_DIGEST_MISMATCH")

    blocked = bool(reasons)

    return {
        "integration_revision": "STEP_186_R1",
        "integration_standing": INTEGRATION_NOT_ESTABLISHED if blocked else INTEGRATION_SUPPORTABLE,
        "integration_decision": "NOT_ADMISSIBLE" if blocked else "ACCOUNTABILITY_BOUNDARY_PREREQUISITES_SUPPORTABLE",
        "no_bind_state": "ACTIVE" if blocked else "SEPARATE_EXECUTION_TIME_REVALIDATION_REQUIRED",
        "action_held": blocked,
        "caller_requested_decision": caller_requested_decision,
        "caller_override_rejected": blocked and caller_requested_decision == "ADMISSIBLE",
        "expected_scope_id": expected_scope_id,
        "expected_action_id": expected_action_id,
        "expected_object_hash": expected_object_hash,
        "reasons": sorted(set(reasons)),
        "step_185_result_consumed": True,
        "step_179_result_consumed": True,
        "scope_action_object_binding_checked": True,
        "payload_digest_binding_checked": True,
        "binding_temporal_currentness_checked": True,
        "binding_provenance_manufactured": False,
        "binding_authority_granted": False,
        "action_admissibility_granted": False,
        "execution_authorized": False,
        "physical_action_executed": False,
        "historical_facts_rewritten": False,
        "irlt_mag_state_changed": False,
        "separate_execution_time_revalidation_required": True,
    }
