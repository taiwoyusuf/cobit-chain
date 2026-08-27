"""Step 181 atomic evaluated-to-committed object binding.

This bounded evaluator closes the evaluation-to-commit TOCTOU gap. It does not
execute regulated or physical actions and does not grant binding authority.
"""

import hashlib
import json


def _digest(value: dict) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def issue_commit_binding_token(*, revalidation_result: dict, current_snapshot: dict,
                               action_id: str, transaction_id: str,
                               commit_nonce: str) -> dict:
    """Freeze the exact revalidated state into a single-use commit token."""
    reasons = []
    if revalidation_result.get("execution_time_decision") != "ADMISSIBLE":
        reasons.append("EXECUTION_TIME_REVALIDATION_NOT_ADMISSIBLE")
    if revalidation_result.get("no_bind_state") != "INACTIVE":
        reasons.append("EXECUTION_TIME_NO_BIND_ACTIVE")
    for field in ("object_hash", "authority_current", "evidence_digest",
                  "criteria_version", "configuration_hash",
                  "environment_context_hash"):
        if field not in current_snapshot:
            reasons.append(field.upper() + "_MISSING")
    if not action_id:
        reasons.append("ACTION_ID_MISSING")
    if not transaction_id:
        reasons.append("TRANSACTION_ID_MISSING")
    if not commit_nonce:
        reasons.append("COMMIT_NONCE_MISSING")

    blocked = bool(reasons)
    snapshot_digest = _digest(current_snapshot) if not blocked else None
    token_material = {
        "action_id": action_id,
        "transaction_id": transaction_id,
        "commit_nonce": commit_nonce,
        "object_hash": current_snapshot.get("object_hash"),
        "snapshot_digest": snapshot_digest,
    }
    token_id = _digest(token_material) if not blocked else None

    return {
        "token_state": "ISSUED" if not blocked else "NOT_ISSUED",
        "token_id": token_id,
        "action_id": action_id,
        "transaction_id": transaction_id,
        "commit_nonce": commit_nonce,
        "object_hash": current_snapshot.get("object_hash"),
        "snapshot_digest": snapshot_digest,
        "revalidation_decision": revalidation_result.get("execution_time_decision"),
        "reasons": sorted(set(reasons)),
        "single_use_required": True,
        "binding_authority_granted": False,
        "physical_action_executed": False,
    }


def verify_atomic_commit(*, token: dict, commit_snapshot: dict,
                         action_id: str, transaction_id: str,
                         commit_nonce: str, token_consumed: bool = False) -> dict:
    """Permit assurance routing only when commit state exactly matches the token."""
    reasons = []
    if not isinstance(token, dict) or token.get("token_state") != "ISSUED":
        reasons.append("VALID_COMMIT_TOKEN_NOT_PRESENT")
    if token_consumed:
        reasons.append("COMMIT_TOKEN_REPLAY_PROHIBITED")

    if isinstance(token, dict):
        if token.get("action_id") != action_id:
            reasons.append("ACTION_CHANGED_AFTER_REVALIDATION")
        if token.get("transaction_id") != transaction_id:
            reasons.append("TRANSACTION_CHANGED_AFTER_REVALIDATION")
        if token.get("commit_nonce") != commit_nonce:
            reasons.append("COMMIT_NONCE_MISMATCH")
        if token.get("object_hash") != commit_snapshot.get("object_hash"):
            reasons.append("OBJECT_CHANGED_BETWEEN_REVALIDATION_AND_COMMIT")
        if token.get("snapshot_digest") != _digest(commit_snapshot):
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
