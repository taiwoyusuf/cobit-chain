"""Residual-Consequence R1 bounded research challenge controls.

These evaluators preserve epistemic and assurance boundaries. They do not grant
binding authority, execute actions, or alter IRLT-MAG state.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping


def _result(state: str, reason: str, **extra) -> dict:
    return {
        "state": state,
        "reason": reason,
        "binding_authority_granted": False,
        "physical_action_executed": False,
        "irlt_mag_state_changed": False,
        **extra,
    }


def evaluate_proposition_bound_witness(*,
                                       claimed_proposition: str,
                                       qualified_propositions: Iterable[str],
                                       witness_authenticated: bool,
                                       witness_healthy: bool,
                                       channel_validated: bool,
                                       observation_current: bool,
                                       provenance_complete: bool) -> dict:
    """Require explicit witness qualification for the proposition being asserted."""
    qualified = {str(p) for p in qualified_propositions}
    if not claimed_proposition:
        return _result("NOT_ESTABLISHED", "CLAIMED_PROPOSITION_MISSING")
    if not witness_authenticated or not witness_healthy:
        return _result("NOT_ESTABLISHED", "WITNESS_STANDING_DEFECT")
    if not channel_validated:
        return _result("NOT_ESTABLISHED", "OBSERVATION_CHANNEL_NOT_VALIDATED")
    if not provenance_complete:
        return _result("NOT_ESTABLISHED", "WITNESS_PROVENANCE_INCOMPLETE")
    if not observation_current:
        return _result("REASSESSMENT_REQUIRED", "WITNESS_OBSERVATION_NOT_CURRENT")
    if claimed_proposition not in qualified:
        return _result(
            "NOT_ESTABLISHED",
            "WITNESS_NOT_QUALIFIED_FOR_CLAIMED_PROPOSITION",
            claimed_proposition=claimed_proposition,
            qualified_propositions=sorted(qualified),
        )
    return _result(
        "SUPPORTABLE",
        "PROPOSITION_BOUND_WITNESS_STANDING_SUPPORTED",
        claimed_proposition=claimed_proposition,
    )


def evaluate_negative_evidence_boundary(*,
                                        observation_result: str,
                                        opportunity_to_observe_established: bool,
                                        detection_capability_established: bool,
                                        detection_limit_appropriate: bool,
                                        observation_window_adequate: bool,
                                        evidence_service_available: bool = True) -> dict:
    """Prevent silence, non-detection, or unavailable evidence from becoming absence."""
    normalized = str(observation_result or "UNKNOWN").upper()
    if not evidence_service_available:
        return _result(
            "UNKNOWN",
            "EVIDENCE_SERVICE_UNAVAILABLE",
            absence_established=False,
            contradiction_free_established=False,
        )
    if normalized in {"ABSENT", "NOT_PRESENT"}:
        if not all([
            opportunity_to_observe_established,
            detection_capability_established,
            detection_limit_appropriate,
            observation_window_adequate,
        ]):
            return _result(
                "NOT_ESTABLISHED",
                "NEGATIVE_EVIDENCE_BASIS_INCOMPLETE",
                absence_established=False,
            )
        return _result(
            "ABSENCE_SUPPORTABLE",
            "NEGATIVE_EVIDENCE_BASIS_ESTABLISHED",
            absence_established=True,
        )
    if normalized in {"NOT_OBSERVED", "NOT_DETECTED", "NO_SIGNAL", "MISSING", "UNKNOWN"}:
        return _result(
            "UNKNOWN",
            "NON_OBSERVATION_DOES_NOT_ESTABLISH_ABSENCE",
            absence_established=False,
        )
    return _result(
        "PRESENT_OR_OBSERVED",
        "POSITIVE_OBSERVATION_PRESERVED",
        absence_established=False,
    )


def evaluate_contradiction_and_independence(*,
                                            evidence_records: Iterable[Mapping[str, object]],
                                            contradiction_service_available: bool = True) -> dict:
    """Preserve contradictions and discount corroboration sharing material dependencies."""
    records = list(evidence_records)
    if not contradiction_service_available:
        return _result(
            "UNKNOWN",
            "CONTRADICTION_SERVICE_UNAVAILABLE",
            contradiction_free_established=False,
            independent_support_count=0,
        )
    if not records:
        return _result(
            "NOT_ESTABLISHED",
            "NO_EVIDENCE_RECORDS",
            contradiction_free_established=False,
            independent_support_count=0,
        )

    supported = []
    opposed = []
    dependency_groups = set()
    unknown_dependency = False

    for item in records:
        stance = str(item.get("stance", "UNKNOWN")).upper()
        record_id = str(item.get("record_id", "UNIDENTIFIED"))
        dependency = item.get("failure_domain_id")
        if dependency is None:
            unknown_dependency = True
        else:
            dependency_groups.add(str(dependency))
        if stance == "SUPPORTS":
            supported.append(record_id)
        elif stance == "CONTRADICTS":
            opposed.append(record_id)

    if supported and opposed:
        return _result(
            "CONTRADICTED",
            "CONFLICTING_EVIDENCE_PRESERVED",
            supporting_records=sorted(supported),
            contradicting_records=sorted(opposed),
            contradiction_free_established=False,
            independent_support_count=len(dependency_groups),
        )

    if unknown_dependency and len(records) > 1:
        return _result(
            "DEPENDENCY_UNCERTAIN",
            "FAILURE_DOMAIN_INDEPENDENCE_NOT_ESTABLISHED",
            contradiction_free_established=not bool(opposed),
            independent_support_count=len(dependency_groups),
        )

    if supported:
        return _result(
            "SUPPORTABLE",
            "NON_CONTRADICTED_SUPPORT_WITH_DECLARED_FAILURE_DOMAINS",
            contradiction_free_established=True,
            independent_support_count=len(dependency_groups),
            apparent_support_count=len(supported),
        )

    return _result(
        "NOT_ESTABLISHED",
        "NO_SUPPORTING_EVIDENCE",
        contradiction_free_established=not bool(opposed),
        independent_support_count=len(dependency_groups),
    )


def evaluate_residual_consequence_closure(*,
                                         prior_permission_current: bool,
                                         execution_receipt_succeeded: bool,
                                         physical_outcome_observed: bool,
                                         intended_outcome_established: bool,
                                         residual_effects_present: bool,
                                         blocking_obligations_open: bool,
                                         current_world_correspondence_established: bool,
                                         criteria_current: bool,
                                         evidence_current: bool,
                                         authority_current: bool,
                                         independent_reverification_required: bool,
                                         independent_reverification_established: bool,
                                         history_preserved: bool) -> dict:
    """Challenge whether consequence closure survives execution and recovery boundaries."""
    reasons = []

    if not history_preserved:
        reasons.append("HISTORICAL_EVENT_PRESERVATION_NOT_ESTABLISHED")
    if not prior_permission_current:
        reasons.append("CURRENT_PERMISSION_OR_STANDING_NOT_ESTABLISHED")
    if not execution_receipt_succeeded:
        reasons.append("EXECUTION_SUCCESS_NOT_ESTABLISHED")
    if not physical_outcome_observed:
        reasons.append("PHYSICAL_OUTCOME_NOT_OBSERVED")
    if not intended_outcome_established:
        reasons.append("INTENDED_OUTCOME_NOT_ESTABLISHED")
    if residual_effects_present:
        reasons.append("RESIDUAL_CONSEQUENCE_REMAINS")
    if blocking_obligations_open:
        reasons.append("BLOCKING_RESIDUAL_OBLIGATION_OPEN")
    if not current_world_correspondence_established:
        reasons.append("CURRENT_WORLD_CORRESPONDENCE_NOT_ESTABLISHED")
    if not criteria_current:
        reasons.append("CURRENT_CRITERIA_NOT_ESTABLISHED")
    if not evidence_current:
        reasons.append("CURRENT_EVIDENCE_NOT_ESTABLISHED")
    if not authority_current:
        reasons.append("CURRENT_AUTHORITY_NOT_ESTABLISHED")
    if independent_reverification_required and not independent_reverification_established:
        reasons.append("INDEPENDENT_REVERIFICATION_NOT_ESTABLISHED")

    if reasons:
        return _result(
            "RECLOSURE_NOT_ESTABLISHED",
            "RESIDUAL_CONSEQUENCE_CLOSURE_FAILED",
            reasons=sorted(reasons),
            return_to_reliance_supportable=False,
            no_bind_state="ACTIVE",
            historical_facts_rewritten=False,
        )

    return _result(
        "RECLOSURE_SUPPORTABLE",
        "RESIDUAL_CONSEQUENCE_CLOSURE_SUPPORTED_WITHIN_DECLARED_SCOPE",
        reasons=[],
        return_to_reliance_supportable=True,
        no_bind_state="SEPARATE_AUTHORITY_AND_ACTION_ADMISSIBILITY_REQUIRED",
        historical_facts_rewritten=False,
    )
