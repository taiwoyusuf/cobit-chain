"""Step 178 bounded assurance invariants.

These evaluators produce non-binding assurance states only. They do not grant
regulatory authority, release product, authorize radiation work, or execute
physical actions.
"""

EPISTEMIC_CLASSES = {
    "RAW_OBSERVATION",
    "MEASURED",
    "DERIVED",
    "ESTIMATED",
    "INFERRED",
    "RECONSTRUCTED",
    "HUMAN_ATTESTED",
    "VERIFIED",
    "UNKNOWN_MISSING",
}


def evaluate_assurance_control_capacity(*, peak_demand: int, available_capacity: int,
                                        queue_delay_ms: int, enforcement_deadline_ms: int,
                                        retry_amplification: float = 1.0) -> dict:
    """Determine whether the assurance gate can act before consequence binds."""
    if min(peak_demand, available_capacity, queue_delay_ms, enforcement_deadline_ms) < 0:
        raise ValueError("capacity and timing values must be non-negative")
    if retry_amplification < 1.0:
        raise ValueError("retry_amplification must be >= 1.0")

    effective_demand = peak_demand * retry_amplification
    capacity_ok = available_capacity >= effective_demand
    deadline_ok = queue_delay_ms <= enforcement_deadline_ms

    if capacity_ok and deadline_ok:
        standing = "SUPPORTABLE"
        action = "EVALUATE_NORMALLY"
        reason = "CONTROL_CAPACITY_WITHIN_CONSEQUENCE_BOUNDARY"
    else:
        standing = "NOT_ESTABLISHED"
        action = "HOLD_HIGH_CONSEQUENCE"
        reason = "CONTROL_CANNOT_RELIABLY_GOVERN_BEFORE_CONSEQUENCE"

    return {
        "control_capacity_standing": standing,
        "effective_demand": effective_demand,
        "capacity_ok": capacity_ok,
        "deadline_ok": deadline_ok,
        "required_behavior": action,
        "reason": reason,
        "binding_decision_made": False,
        "fail_closed": standing != "SUPPORTABLE",
    }


def preserve_epistemic_class(*, source_class: str, claimed_class: str,
                              transformation_documented: bool,
                              independent_verification: bool = False) -> dict:
    """Prevent silent epistemic upgrading of observations or inferences."""
    if source_class not in EPISTEMIC_CLASSES or claimed_class not in EPISTEMIC_CLASSES:
        raise ValueError("unknown epistemic class")

    same = source_class == claimed_class
    verification_upgrade = claimed_class == "VERIFIED" and independent_verification
    allowed = same or (transformation_documented and verification_upgrade)

    if allowed:
        standing = "SUPPORTABLE"
        reason = "EPISTEMIC_CLASS_PRESERVED_OR_INDEPENDENTLY_VERIFIED"
    else:
        standing = "NOT_ESTABLISHED"
        reason = "SILENT_EPISTEMIC_UPGRADE_PROHIBITED"

    return {
        "source_class": source_class,
        "claimed_class": claimed_class,
        "standing": standing,
        "reason": reason,
        "binding_decision_made": False,
        "fail_closed": not allowed,
    }


def create_boundary_assurance_capsule(*, action_id: str, object_hash: str,
                                      criteria_version: str, evidence_refs: list[str],
                                      authority_snapshot: str, standing: str,
                                      unresolved_conditions: list[str],
                                      determination: str,
                                      committed_object_hash: str | None = None) -> dict:
    """Freeze the decision basis and require evaluated-to-committed object binding."""
    complete = all([action_id, object_hash, criteria_version, evidence_refs, authority_snapshot, standing, determination])
    exact_binding = committed_object_hash is None or committed_object_hash == object_hash

    if not complete:
        capsule_state = "NOT_ESTABLISHED"
        reason = "BOUNDARY_CAPSULE_INCOMPLETE"
    elif not exact_binding:
        capsule_state = "NO_BIND"
        reason = "EVALUATED_OBJECT_DIFFERS_FROM_COMMITTED_OBJECT"
    else:
        capsule_state = "SUPPORTABLE"
        reason = "BOUNDARY_DECISION_BASIS_FROZEN"

    return {
        "action_id": action_id,
        "object_hash": object_hash,
        "criteria_version": criteria_version,
        "evidence_refs": list(evidence_refs),
        "authority_snapshot": authority_snapshot,
        "standing": standing,
        "unresolved_conditions": list(unresolved_conditions),
        "determination": determination,
        "committed_object_hash": committed_object_hash,
        "capsule_state": capsule_state,
        "reason": reason,
        "binding_decision_made": False,
        "fail_closed": capsule_state != "SUPPORTABLE",
    }


def evaluate_recovery_standing(*, execution_stopped: bool, internal_state_reversed: bool,
                               escaped_consequence: bool, downstream_reliance_known: bool,
                               remediation_complete: bool) -> dict:
    """Separate stop, reverse, and remediate from whole-event recovery."""
    if not execution_stopped:
        standing = "NOT_RECOVERED"
        reason = "EXECUTION_NOT_STOPPED"
    elif escaped_consequence and (not downstream_reliance_known or not remediation_complete):
        standing = "PARTIAL"
        reason = "ESCAPED_CONSEQUENCE_REQUIRES_REMEDIATION"
    elif internal_state_reversed and (not escaped_consequence or remediation_complete):
        standing = "RECOVERED_WITHIN_DECLARED_SCOPE"
        reason = "REVERSAL_AND_REQUIRED_REMEDIATION_ESTABLISHED"
    else:
        standing = "PARTIAL"
        reason = "STOP_DOES_NOT_ESTABLISH_REVERSAL"

    return {
        "recovery_standing": standing,
        "execution_stopped": execution_stopped,
        "internal_state_reversed": internal_state_reversed,
        "escaped_consequence": escaped_consequence,
        "downstream_reliance_known": downstream_reliance_known,
        "remediation_complete": remediation_complete,
        "reason": reason,
        "binding_decision_made": False,
    }


def evaluate_processing_authority(*, human_access_authorized: bool,
                                  machine_processing_authorized: bool,
                                  purpose_authorized: bool,
                                  destination_authorized: bool,
                                  retention_authorized: bool) -> dict:
    """Separate access rights from AI/machine-processing authority."""
    all_machine_rights = all([
        machine_processing_authorized,
        purpose_authorized,
        destination_authorized,
        retention_authorized,
    ])

    if not human_access_authorized:
        standing = "NOT_ESTABLISHED"
        reason = "SOURCE_ACCESS_NOT_AUTHORIZED"
    elif not all_machine_rights:
        standing = "NO_BIND"
        reason = "MACHINE_PROCESSING_AUTHORITY_INCOMPLETE"
    else:
        standing = "SUPPORTABLE"
        reason = "PROCESSING_AUTHORITY_ESTABLISHED"

    return {
        "processing_authority_standing": standing,
        "human_access_authorized": human_access_authorized,
        "machine_processing_authorized": machine_processing_authorized,
        "purpose_authorized": purpose_authorized,
        "destination_authorized": destination_authorized,
        "retention_authorized": retention_authorized,
        "reason": reason,
        "binding_decision_made": False,
        "fail_closed": standing != "SUPPORTABLE",
    }


def evaluate_disposition_standing(*, condition_detected: bool, owner_resolved: bool,
                                  deadline_defined: bool, interim_posture_defined: bool,
                                  escalation_defined: bool, closure_evidence_present: bool) -> dict:
    """Require governed disposition after detection; silence is not permission."""
    if not condition_detected:
        standing = "NOT_APPLICABLE"
        reason = "NO_DETECTED_CONDITION"
    elif not all([owner_resolved, deadline_defined, interim_posture_defined, escalation_defined]):
        standing = "NOT_ESTABLISHED"
        reason = "DETECTED_CONDITION_LACKS_GOVERNED_DISPOSITION_PATH"
    elif not closure_evidence_present:
        standing = "OPEN_GOVERNED_CONDITION"
        reason = "DISPOSITION_PATH_ESTABLISHED_CLOSURE_PENDING"
    else:
        standing = "CLOSED_WITH_EVIDENCE"
        reason = "DISPOSITION_AND_CLOSURE_ESTABLISHED"

    return {
        "disposition_standing": standing,
        "reason": reason,
        "binding_decision_made": False,
        "fail_closed": standing in {"NOT_ESTABLISHED", "OPEN_GOVERNED_CONDITION"},
    }
