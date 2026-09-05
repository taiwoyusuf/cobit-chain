"""Accountability Continuity Standing R1 — bounded research evaluator.

Purpose
-------
Evaluate whether accountable ownership for a declared consequence scope remains
identifiable, current, accepted, evidenced, and continuous across organizational,
system, vendor, or agent handoffs.

This evaluator deliberately preserves these distinctions:

RESPONSIBILITY != ACCOUNTABILITY != AUTHORITY != CAPABILITY
SHARED_RESPONSIBILITY != ACCOUNTABILITY_DILUTION
ACTION_TRACEABILITY != ACCOUNTABILITY_TRACEABILITY

A positive result does not grant authority, authorize action, establish regulatory
release/disposition, or modify IRLT-MAG state.
"""

from __future__ import annotations

from collections.abc import Mapping


SUPPORTABLE = "ACCOUNTABILITY_CONTINUITY_SUPPORTABLE"
NOT_ESTABLISHED = "ACCOUNTABILITY_CONTINUITY_NOT_ESTABLISHED"
HANDOFF_NOT_ESTABLISHED = "ACCOUNTABILITY_HANDOFF_NOT_ESTABLISHED"
CONTRADICTED = "ACCOUNTABILITY_CONTINUITY_CONTRADICTED"


def _required_bool(record: Mapping[str, object], field: str, reasons: list[str], prefix: str) -> bool | None:
    if field not in record:
        reasons.append(f"{prefix}_{field.upper()}_MISSING")
        return None
    value = record.get(field)
    if type(value) is not bool:
        reasons.append(f"{prefix}_{field.upper()}_INVALID")
        return None
    return value


def _required_nonnegative_int(record: Mapping[str, object], field: str, reasons: list[str], prefix: str) -> int | None:
    if field not in record:
        reasons.append(f"{prefix}_{field.upper()}_MISSING")
        return None
    value = record.get(field)
    if type(value) is not int or value < 0:
        reasons.append(f"{prefix}_{field.upper()}_INVALID")
        return None
    return value


def _required_nonempty_str(record: Mapping[str, object], field: str, reasons: list[str], prefix: str) -> str | None:
    if field not in record:
        reasons.append(f"{prefix}_{field.upper()}_MISSING")
        return None
    value = record.get(field)
    if type(value) is not str or not value.strip():
        reasons.append(f"{prefix}_{field.upper()}_INVALID")
        return None
    return value.strip()


def _result(standing: str, reason: str, reasons: list[str], **extra: object) -> dict[str, object]:
    blocked = standing != SUPPORTABLE
    return {
        "accountability_continuity_standing": standing,
        "reason": reason,
        "reasons": sorted(set(reasons)),
        "accountability_basis_supportable": not blocked,
        "no_bind_state": "ACTIVE" if blocked else "SEPARATE_AUTHORITY_AND_ACTION_ADMISSIBILITY_REQUIRED",
        "action_hold_required_on_accountability_basis": blocked,
        "binding_authority_granted": False,
        "physical_action_executed_by_evaluator": False,
        "regulated_release_or_disposition_authorized": False,
        "responsibility_treated_as_accountability": False,
        "accountability_manufactured_by_evaluator": False,
        "historical_facts_rewritten": False,
        "irlt_mag_state_changed": False,
        "separate_authority_evaluation_required": True,
        **extra,
    }


def evaluate_accountability_continuity(
    *,
    responsibility_context: Mapping[str, object],
    accountability_state: Mapping[str, object],
    handoff_state: Mapping[str, object],
    evidence_state: Mapping[str, object],
) -> dict[str, object]:
    """Evaluate accountability continuity for one declared consequence scope.

    Positive standing requires a resolvable current accountable entity for the
    declared scope. If a handoff occurred, the successor must be identified,
    accepted, scope-consistent, obligation-preserving, traceable, and reflected as
    the current accountable owner.

    Responsibility completeness is reported but does not substitute for or define
    accountability. A downstream composition may separately require complete RACI
    or responsibility standing.
    """

    if not all(isinstance(x, Mapping) for x in (
        responsibility_context,
        accountability_state,
        handoff_state,
        evidence_state,
    )):
        return _result(
            NOT_ESTABLISHED,
            "REQUIRED_INPUT_MAPPING_MISSING",
            ["REQUIRED_INPUT_MAPPING_MISSING"],
        )

    reasons: list[str] = []
    handoff_reasons: list[str] = []

    responsible_party_count = _required_nonnegative_int(
        responsibility_context, "responsible_party_count", reasons, "RESPONSIBILITY"
    )
    shared_responsibility_declared = _required_bool(
        responsibility_context, "shared_responsibility_declared", reasons, "RESPONSIBILITY"
    )
    responsibility_assignment_complete = _required_bool(
        responsibility_context, "responsibility_assignment_complete", reasons, "RESPONSIBILITY"
    )

    declared_scope_id = _required_nonempty_str(accountability_state, "declared_scope_id", reasons, "ACCOUNTABILITY")
    owner_identified = _required_bool(accountability_state, "accountable_owner_identified", reasons, "ACCOUNTABILITY")
    accountable_owner_id = _required_nonempty_str(accountability_state, "accountable_owner_id", reasons, "ACCOUNTABILITY")
    entity_resolvable = _required_bool(accountability_state, "accountable_entity_resolvable", reasons, "ACCOUNTABILITY")
    scope_defined = _required_bool(accountability_state, "accountability_scope_defined", reasons, "ACCOUNTABILITY")
    mandate_current = _required_bool(accountability_state, "accountable_mandate_current", reasons, "ACCOUNTABILITY")
    acceptance_current = _required_bool(accountability_state, "accountability_acceptance_current", reasons, "ACCOUNTABILITY")
    ambiguity_present = _required_bool(accountability_state, "accountability_ambiguity_present", reasons, "ACCOUNTABILITY")
    orphaned = _required_bool(accountability_state, "orphaned_accountability", reasons, "ACCOUNTABILITY")
    conflicting_claims = _required_bool(
        accountability_state, "conflicting_accountability_claims_present", reasons, "ACCOUNTABILITY"
    )
    material_change_after_assignment = _required_bool(
        accountability_state, "material_change_after_accountability_assignment", reasons, "ACCOUNTABILITY"
    )
    revalidated_after_material_change = _required_bool(
        accountability_state,
        "accountability_revalidated_after_latest_material_change",
        reasons,
        "ACCOUNTABILITY",
    )

    if owner_identified is False:
        reasons.append("ACCOUNTABLE_OWNER_NOT_IDENTIFIED")
    if entity_resolvable is False:
        reasons.append("ACCOUNTABLE_ENTITY_NOT_RESOLVABLE")
    if scope_defined is False:
        reasons.append("ACCOUNTABILITY_SCOPE_NOT_DEFINED")
    if mandate_current is False:
        reasons.append("ACCOUNTABLE_MANDATE_NOT_CURRENT")
    if acceptance_current is False:
        reasons.append("ACCOUNTABILITY_ACCEPTANCE_NOT_CURRENT")
    if ambiguity_present is True:
        reasons.append("ACCOUNTABILITY_AMBIGUITY_PRESENT")
    if orphaned is True:
        reasons.append("ACCOUNTABILITY_ORPHANED")
    if conflicting_claims is True:
        reasons.append("CONFLICTING_ACCOUNTABILITY_CLAIMS_PRESENT")
    if material_change_after_assignment is True and revalidated_after_material_change is not True:
        reasons.append("ACCOUNTABILITY_BASIS_STALE_AFTER_MATERIAL_CHANGE")

    assignment_traceable = _required_bool(
        evidence_state, "accountability_assignment_traceable", reasons, "EVIDENCE"
    )
    acceptance_traceable = _required_bool(
        evidence_state, "accountability_acceptance_traceable", reasons, "EVIDENCE"
    )
    decision_point_traceable = _required_bool(evidence_state, "decision_point_traceable", reasons, "EVIDENCE")
    outcome_owner_traceable = _required_bool(evidence_state, "outcome_owner_traceable", reasons, "EVIDENCE")
    evidence_current = _required_bool(evidence_state, "accountability_evidence_current", reasons, "EVIDENCE")
    execution_actor_traceable = _required_bool(evidence_state, "execution_actor_traceable", reasons, "EVIDENCE")

    if assignment_traceable is False:
        reasons.append("ACCOUNTABILITY_ASSIGNMENT_NOT_TRACEABLE")
    if acceptance_traceable is False:
        reasons.append("ACCOUNTABILITY_ACCEPTANCE_NOT_TRACEABLE")
    if decision_point_traceable is False:
        reasons.append("ACCOUNTABILITY_DECISION_POINT_NOT_TRACEABLE")
    if outcome_owner_traceable is False:
        reasons.append("ACCOUNTABLE_OUTCOME_OWNER_NOT_TRACEABLE")
    if evidence_current is False:
        reasons.append("ACCOUNTABILITY_EVIDENCE_NOT_CURRENT")

    handoff_occurred = _required_bool(handoff_state, "handoff_occurred", reasons, "HANDOFF")
    successor_owner_id: str | None = None

    if handoff_occurred is True:
        successor_identified = _required_bool(handoff_state, "successor_owner_identified", handoff_reasons, "HANDOFF")
        successor_owner_id = _required_nonempty_str(handoff_state, "successor_owner_id", handoff_reasons, "HANDOFF")
        successor_acceptance = _required_bool(
            handoff_state, "successor_acceptance_current", handoff_reasons, "HANDOFF"
        )
        scope_preserved = _required_bool(handoff_state, "scope_preserved_across_handoff", handoff_reasons, "HANDOFF")
        obligations_preserved = _required_bool(
            handoff_state, "obligations_preserved_across_handoff", handoff_reasons, "HANDOFF"
        )
        transfer_traceable = _required_bool(handoff_state, "transfer_traceable", handoff_reasons, "HANDOFF")
        predecessor_disposition = _required_bool(
            handoff_state, "predecessor_scope_disposition_established", handoff_reasons, "HANDOFF"
        )

        if successor_identified is False:
            handoff_reasons.append("HANDOFF_SUCCESSOR_NOT_IDENTIFIED")
        if successor_acceptance is False:
            handoff_reasons.append("HANDOFF_SUCCESSOR_ACCEPTANCE_NOT_CURRENT")
        if scope_preserved is False:
            handoff_reasons.append("HANDOFF_SCOPE_NOT_PRESERVED")
        if obligations_preserved is False:
            handoff_reasons.append("HANDOFF_OBLIGATIONS_NOT_PRESERVED")
        if transfer_traceable is False:
            handoff_reasons.append("HANDOFF_TRANSFER_NOT_TRACEABLE")
        if predecessor_disposition is False:
            handoff_reasons.append("HANDOFF_PREDECESSOR_SCOPE_DISPOSITION_NOT_ESTABLISHED")
        if successor_owner_id is not None and accountable_owner_id is not None and successor_owner_id != accountable_owner_id:
            handoff_reasons.append("CURRENT_ACCOUNTABLE_OWNER_DOES_NOT_MATCH_HANDOFF_SUCCESSOR")

    reasons.extend(handoff_reasons)

    # Strong precedence: contradictory accountability claims are preserved rather
    # than averaged or resolved by responsibility count, execution evidence, or a
    # later handoff assertion.
    if conflicting_claims is True:
        standing = CONTRADICTED
        reason = "CONFLICTING_ACCOUNTABILITY_CLAIMS_PREVENT_CONTINUITY"
    elif handoff_reasons:
        standing = HANDOFF_NOT_ESTABLISHED
        reason = "ACCOUNTABILITY_HANDOFF_PRECONDITIONS_NOT_ESTABLISHED"
    elif reasons:
        standing = NOT_ESTABLISHED
        reason = "ONE_OR_MORE_ACCOUNTABILITY_CONTINUITY_PRECONDITIONS_NOT_ESTABLISHED"
    else:
        standing = SUPPORTABLE
        reason = "CURRENT_ACCOUNTABILITY_CONTINUITY_ESTABLISHED_FOR_DECLARED_SCOPE"

    return _result(
        standing,
        reason,
        reasons,
        declared_scope_id=declared_scope_id,
        accountable_owner_id=accountable_owner_id,
        responsible_party_count=responsible_party_count,
        shared_responsibility_declared=shared_responsibility_declared,
        responsibility_assignment_complete=responsibility_assignment_complete,
        execution_actor_traceable=execution_actor_traceable,
        handoff_occurred=handoff_occurred,
        handoff_successor_owner_id=successor_owner_id,
        material_change_after_accountability_assignment=material_change_after_assignment,
        accountability_revalidated_after_latest_material_change=revalidated_after_material_change,
    )
