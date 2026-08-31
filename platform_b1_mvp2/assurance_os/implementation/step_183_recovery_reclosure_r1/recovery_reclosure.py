"""Step 183 — Recovery / Re-closure / Return-to-Reliance Standing R1.

This evaluator composes previously established assurance states. It does not
perform recovery, close CAPA/investigations, grant authority, release product,
authorize radiation work, or execute physical actions.
"""

from __future__ import annotations

from typing import Iterable, Mapping


def _blocking_obligations(obligations: Iterable[Mapping[str, object]]) -> list[str]:
    blocked: list[str] = []
    for item in obligations:
        obligation_id = str(item.get("obligation_id") or item.get("id") or "UNIDENTIFIED")
        blocking = bool(item.get("blocking", False))
        closed = bool(item.get("closed", False))
        if blocking and not closed:
            blocked.append(obligation_id)
    return sorted(blocked)


def _open_obligations(obligations: Iterable[Mapping[str, object]]) -> list[str]:
    opened: list[str] = []
    for item in obligations:
        obligation_id = str(item.get("obligation_id") or item.get("id") or "UNIDENTIFIED")
        if not bool(item.get("closed", False)):
            opened.append(obligation_id)
    return sorted(opened)


def evaluate_recovery_reclosure(
    *,
    prior_outcome_result: Mapping[str, object],
    recovery_result: Mapping[str, object],
    disposition_result: Mapping[str, object],
    residual_obligations: Iterable[Mapping[str, object]],
    reclosure_evidence: Mapping[str, object],
    reclosure_required: bool = True,
    independent_outcome_reverification_required: bool = False,
) -> dict:
    """Evaluate whether return to reliance is supportable after a disturbed event.

    Step 183 deliberately keeps these propositions separate:

    RECOVERY != DISPOSITION_CLOSURE != RECLOSURE != RETURN_TO_RELIANCE

    Open non-blocking duties may survive re-entry. Open blocking duties may not.
    Historical failure/divergence facts are never rewritten by later recovery.
    """

    prior_state = prior_outcome_result.get("correspondence_standing")
    recovery_state = recovery_result.get("recovery_standing")
    disposition_state = disposition_result.get("disposition_standing")

    obligations = list(residual_obligations)
    blocking = _blocking_obligations(obligations)
    opened = _open_obligations(obligations)

    if not reclosure_required:
        return {
            "reclosure_standing": "NOT_APPLICABLE",
            "prior_outcome_state": prior_state,
            "recovery_standing": recovery_state,
            "disposition_standing": disposition_state,
            "blocking_obligations": blocking,
            "open_obligations_preserved": opened,
            "return_to_reliance_supportable": None,
            "no_bind_state": "UNCHANGED",
            "historical_facts_rewritten": False,
            "binding_authority_granted": False,
            "reason": "RECLOSURE_NOT_REQUIRED_FOR_THIS_ROUTE",
        }

    history_preserved = bool(reclosure_evidence.get("historical_event_preserved", False))
    world_current = bool(reclosure_evidence.get("current_world_correspondence_established", False))
    criteria_current = bool(reclosure_evidence.get("criteria_current", False))
    authority_current = bool(reclosure_evidence.get("authority_current", False))
    evidence_current = bool(reclosure_evidence.get("required_evidence_current", False))
    baseline_established = bool(reclosure_evidence.get("reclosure_baseline_established", False))
    independent_reverified = bool(reclosure_evidence.get("independent_outcome_reverified", False))

    if not history_preserved:
        standing = "HISTORICAL_EVENT_PRESERVATION_NOT_ESTABLISHED"
        reason = "RECLOSURE_MUST_NOT_REWRITE_PRIOR_FAILURE_OR_DIVERGENCE"
    elif recovery_state != "RECOVERED_WITHIN_DECLARED_SCOPE":
        standing = "RECOVERY_NOT_ESTABLISHED"
        reason = "STOP_OR_PARTIAL_REMEDIATION_DOES_NOT_ESTABLISH_RECOVERY"
    elif disposition_state != "CLOSED_WITH_EVIDENCE":
        standing = "DISPOSITION_NOT_CLOSED"
        reason = "GOVERNED_CONDITION_REMAINS_OPEN"
    elif blocking:
        standing = "BLOCKING_RESIDUAL_OBLIGATION_OPEN"
        reason = "ONE_OR_MORE_BLOCKING_DUTIES_REMAIN_UNRESOLVED"
    elif not world_current:
        standing = "CURRENT_WORLD_CORRESPONDENCE_NOT_ESTABLISHED"
        reason = "RECOVERED_STATE_NOT_BOUND_TO_CURRENT_REALITY"
    elif not criteria_current:
        standing = "CURRENT_CRITERIA_NOT_ESTABLISHED"
        reason = "RECLOSURE_CRITERIA_OR_DEFINITION_NOT_CURRENT"
    elif not authority_current:
        standing = "CURRENT_AUTHORITY_NOT_ESTABLISHED"
        reason = "RECLOSURE_OR_REENTRY_AUTHORITY_NOT_CURRENT"
    elif not evidence_current:
        standing = "CURRENT_EVIDENCE_NOT_ESTABLISHED"
        reason = "REQUIRED_RECLOSURE_EVIDENCE_NOT_CURRENT"
    elif not baseline_established:
        standing = "RECLOSURE_BASELINE_NOT_ESTABLISHED"
        reason = "NO_SUPPORTABLE_POST_RECOVERY_BASELINE"
    elif independent_outcome_reverification_required and not independent_reverified:
        standing = "INDEPENDENT_OUTCOME_REVERIFICATION_NOT_ESTABLISHED"
        reason = "POST_RECOVERY_PHYSICAL_OR_EXTERNAL_OUTCOME_REQUIRES_INDEPENDENT_REVERIFICATION"
    else:
        standing = "RECLOSURE_SUPPORTABLE"
        reason = "CURRENT_RECLOSURE_BASIS_ESTABLISHED_WITHIN_DECLARED_SCOPE"

    supportable = standing == "RECLOSURE_SUPPORTABLE"
    return {
        "reclosure_standing": standing,
        "prior_outcome_state": prior_state,
        "recovery_standing": recovery_state,
        "disposition_standing": disposition_state,
        "blocking_obligations": blocking,
        "open_obligations_preserved": opened,
        "current_world_correspondence_established": world_current,
        "criteria_current": criteria_current,
        "authority_current": authority_current,
        "required_evidence_current": evidence_current,
        "reclosure_baseline_established": baseline_established,
        "independent_outcome_reverification_required": independent_outcome_reverification_required,
        "independent_outcome_reverified": independent_reverified,
        "return_to_reliance_supportable": supportable,
        "no_bind_state": "INACTIVE" if supportable else "ACTIVE",
        "historical_facts_rewritten": False,
        "binding_authority_granted": False,
        "reason": reason,
        "fail_closed": not supportable,
    }
