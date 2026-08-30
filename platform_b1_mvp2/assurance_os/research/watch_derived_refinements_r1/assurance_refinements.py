"""Watch-derived assurance refinements R1.

These evaluators are additive shared-core experiments. They do not create
binding regulatory authority, release product, authorize radiation work, or
replace domain-specific rules. They are intended to compose with existing
COBIT-Chain standing, authority, No-Bind, recovery, and reconstruction logic.
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable, Mapping


def evaluate_non_compensatory_standing(*, mandatory_gates: Mapping[str, bool], aggregate_score: float | None = None) -> dict:
    """A high aggregate score must never compensate for a failed mandatory gate."""
    failed = sorted(name for name, passed in mandatory_gates.items() if not passed)
    standing = "SUPPORTABLE" if not failed else "NOT_ESTABLISHED"
    return {
        "assurance_standing": standing,
        "failed_mandatory_gates": failed,
        "aggregate_score": aggregate_score,
        "aggregate_score_authoritative": False,
        "required_behavior": "EVALUATE_NORMALLY" if not failed else "HOLD",
        "binding_decision_made": False,
        "fail_closed": bool(failed),
    }


def evaluate_human_oversight_queue_standing(*, queue_precision: float, review_capacity: int,
                                             incoming_cases: int, required_review_seconds: float,
                                             available_attention_seconds: float) -> dict:
    """Require enough signal quality and attention for meaningful human review."""
    if not 0 <= queue_precision <= 1:
        raise ValueError("queue_precision must be between 0 and 1")
    if min(review_capacity, incoming_cases) < 0 or min(required_review_seconds, available_attention_seconds) < 0:
        raise ValueError("capacity, case, and attention values must be non-negative")
    capacity_ok = review_capacity >= incoming_cases
    attention_ok = available_attention_seconds >= required_review_seconds * incoming_cases
    precision_ok = queue_precision >= 0.5
    standing = "SUPPORTABLE" if all([capacity_ok, attention_ok, precision_ok]) else "NOT_ESTABLISHED"
    return {
        "human_oversight_standing": standing,
        "queue_precision": queue_precision,
        "capacity_ok": capacity_ok,
        "attention_ok": attention_ok,
        "precision_ok": precision_ok,
        "required_behavior": "REVIEW" if standing == "SUPPORTABLE" else "HOLD_OR_REDESIGN_QUEUE",
        "binding_decision_made": False,
        "fail_closed": standing != "SUPPORTABLE",
    }


def evaluate_claim_identity_and_discharge(*, required_claims: Iterable[str], supported_claims: Iterable[str],
                                          discharged_claims: Iterable[str]) -> dict:
    """A supported claim must not silently discharge different required claims."""
    required = set(required_claims)
    supported = set(supported_claims)
    discharged = set(discharged_claims)
    unsupported_discharges = sorted(discharged - supported)
    missing_dispositions = sorted(required - discharged)
    ok = not unsupported_discharges and not missing_dispositions
    return {
        "claim_discharge_standing": "SUPPORTABLE" if ok else "NOT_ESTABLISHED",
        "unsupported_discharges": unsupported_discharges,
        "missing_required_dispositions": missing_dispositions,
        "binding_decision_made": False,
        "fail_closed": not ok,
    }


def evaluate_independent_evidence_plane(*, record_authentic: bool, witness_independent: bool,
                                        evidence_plane_available: bool, act_to_evidence_bound: bool) -> dict:
    """Separate system-generated records from independently inspectable witness evidence."""
    ok = all([record_authentic, witness_independent, evidence_plane_available, act_to_evidence_bound])
    return {
        "independent_evidence_plane_standing": "SUPPORTABLE" if ok else "NOT_ESTABLISHED",
        "record_authenticity_standing": "SUPPORTABLE" if record_authentic else "NOT_ESTABLISHED",
        "witness_independence_standing": "SUPPORTABLE" if witness_independent else "NOT_ESTABLISHED",
        "evidence_plane_availability": "AVAILABLE" if evidence_plane_available else "UNAVAILABLE",
        "act_to_evidence_binding": "ESTABLISHED" if act_to_evidence_bound else "NOT_ESTABLISHED",
        "binding_decision_made": False,
        "fail_closed": not ok,
    }


def evaluate_recovery_path_noninterference(*, harmful_path_allowed: bool, containment_authorized: bool,
                                           containment_blocked_by_safety_control: bool) -> dict:
    """A preventive safety layer must not obstruct an independently authorized containment path."""
    interference = harmful_path_allowed and containment_authorized and containment_blocked_by_safety_control
    return {
        "recovery_path_interference": interference,
        "recovery_standing": "NOT_ESTABLISHED" if interference else "SUPPORTABLE_WITHIN_DECLARED_SCOPE",
        "required_behavior": "ESCALATE_OR_ISOLATE" if interference else "CONTINUE_GOVERNED_RECOVERY",
        "binding_decision_made": False,
        "fail_closed": interference,
    }


def evaluate_assessor_independence(*, method_guidance_given: bool, solution_shaping_performed: bool,
                                   secondary_independent_review: bool) -> dict:
    """Disclose assessor solution-shaping and require independent review before claiming independence."""
    materially_influenced = solution_shaping_performed
    independently_supportable = not materially_influenced or secondary_independent_review
    return {
        "assessor_independence_standing": "SUPPORTABLE" if independently_supportable else "QUALIFIED_NOT_INDEPENDENT",
        "method_guidance_given": method_guidance_given,
        "solution_shaping_performed": solution_shaping_performed,
        "secondary_independent_review": secondary_independent_review,
        "independent_validation_claim_permitted": independently_supportable,
        "binding_decision_made": False,
        "fail_closed": not independently_supportable,
    }


def evaluate_revocation_propagation(*, parent_scope: Iterable[str], child_scope: Iterable[str],
                                    parent_revoked_at: datetime | None, enforcement_at: datetime | None,
                                    attempted_commit_at: datetime | None) -> dict:
    """Derived scope cannot exceed parent scope; revocation must reach consequence before commit."""
    parent = set(parent_scope)
    child = set(child_scope)
    scope_ok = child.issubset(parent)
    revoked = parent_revoked_at is not None
    enforcement_known = enforcement_at is not None
    latency_seconds = None
    if revoked and enforcement_known:
        latency_seconds = max(0.0, (enforcement_at - parent_revoked_at).total_seconds())
    commit_after_revocation = bool(revoked and attempted_commit_at and attempted_commit_at >= parent_revoked_at)
    enforced_before_commit = bool(
        not commit_after_revocation
        or (enforcement_known and attempted_commit_at and enforcement_at <= attempted_commit_at)
    )
    if not revoked or (attempted_commit_at and attempted_commit_at < parent_revoked_at):
        current = scope_ok
    else:
        current = False
    return {
        "delegation_scope_standing": "SUPPORTABLE" if scope_ok else "NOT_ESTABLISHED",
        "derived_authority_current": current,
        "revocation_latency_seconds": latency_seconds,
        "enforced_before_commit": enforced_before_commit,
        "required_behavior": "ALLOW_EVALUATION" if current else "HOLD_OR_DENY",
        "binding_decision_made": False,
        "fail_closed": not current,
    }


def evaluate_residual_obligation_liveness(*, duty_accepted: bool, duty_completed: bool,
                                          due_at: datetime | None, now: datetime,
                                          custody_transferred: bool = False) -> dict:
    """Reassignment must not reset or erase an unresolved obligation."""
    overdue = bool(duty_accepted and not duty_completed and due_at and now > due_at)
    if duty_completed:
        standing = "CLOSED_WITH_EVIDENCE"
    elif overdue:
        standing = "OPEN_OVERDUE_ESCALATE"
    elif duty_accepted:
        standing = "OPEN_GOVERNED_OBLIGATION"
    else:
        standing = "NOT_ESTABLISHED"
    return {
        "residual_obligation_standing": standing,
        "custody_transferred": custody_transferred,
        "due_at_preserved": due_at.isoformat() if due_at else None,
        "overdue": overdue,
        "binding_decision_made": False,
        "fail_closed": standing != "CLOSED_WITH_EVIDENCE",
    }


def evaluate_governed_interoperability_seam(*, endpoint_a_supportable: bool, endpoint_b_supportable: bool,
                                            interface_version_bound: bool, mapping_version_bound: bool,
                                            evidence_provenance_preserved: bool,
                                            authority_transfer_explicitly_prohibited: bool) -> dict:
    """Endpoint standing does not establish relationship/interface standing."""
    interface_ok = all([
        endpoint_a_supportable,
        endpoint_b_supportable,
        interface_version_bound,
        mapping_version_bound,
        evidence_provenance_preserved,
        authority_transfer_explicitly_prohibited,
    ])
    return {
        "interface_standing": "SUPPORTABLE" if interface_ok else "NOT_ESTABLISHED",
        "authority_inherited": False,
        "binding_decision_made": False,
        "fail_closed": not interface_ok,
    }


def evaluate_retrospective_reliance_exposure(*, changed_proposition: str,
                                              historical_dependencies: Mapping[str, Iterable[str]]) -> dict:
    """Find historical decisions requiring review without declaring them retroactively invalid."""
    exposed = sorted(
        decision_id for decision_id, dependencies in historical_dependencies.items()
        if changed_proposition in set(dependencies)
    )
    return {
        "retrospective_exposure_standing": "REVIEW_REQUIRED" if exposed else "NO_EXPOSURE_IDENTIFIED",
        "exposed_historical_decisions": exposed,
        "historical_decisions_automatically_invalidated": False,
        "binding_decision_made": False,
    }


def evaluate_shared_condition_exposure(*, condition_changed: bool, potentially_exposed_routes: Iterable[str],
                                       explicitly_cleared_routes: Iterable[str]) -> dict:
    """A changed common condition triggers scoped reassessment, not contagious failure."""
    exposed = set(potentially_exposed_routes) if condition_changed else set()
    cleared = set(explicitly_cleared_routes)
    pending = sorted(exposed - cleared)
    return {
        "common_condition_exposure_standing": "REASSESSMENT_REQUIRED" if pending else "SUPPORTABLE",
        "routes_requiring_reassessment": pending,
        "all_dependents_failed": False,
        "binding_decision_made": False,
        "fail_closed": bool(pending),
    }


def evaluate_document_parse_fidelity(*, source_hash_bound: bool, page_region_grounded: bool,
                                     table_structure_preserved: bool, revision_context_preserved: bool,
                                     reading_order_preserved: bool, unknown_missing: bool) -> dict:
    """Parsed text is not admissible regulated evidence unless source meaning is preserved."""
    ok = all([
        source_hash_bound,
        page_region_grounded,
        table_structure_preserved,
        revision_context_preserved,
        reading_order_preserved,
        not unknown_missing,
    ])
    return {
        "document_parse_fidelity_standing": "SUPPORTABLE" if ok else "NOT_ESTABLISHED",
        "unknown_missing": unknown_missing,
        "binding_decision_made": False,
        "fail_closed": not ok,
    }


def evaluate_tool_sequence_information_flow(*, individual_tools_authorized: bool,
                                            sequence_permitted: bool,
                                            information_flow_permitted: bool) -> dict:
    """Individually authorized tools do not make their composition safe."""
    ok = all([individual_tools_authorized, sequence_permitted, information_flow_permitted])
    return {
        "tool_sequence_information_flow_standing": "SUPPORTABLE" if ok else "NOT_ESTABLISHED",
        "required_behavior": "ALLOW_EVALUATION" if ok else "HOLD_OR_NO_BIND",
        "binding_decision_made": False,
        "fail_closed": not ok,
    }
