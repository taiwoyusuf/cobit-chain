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


def evaluate_transition_authority_continuity(*,
                                             authority_current_at_start: bool,
                                             authority_current_at_commit: bool,
                                             authority_current_at_irreversible_boundary: bool,
                                             consequence_started: bool,
                                             irreversible_consequence_occurred: bool,
                                             stop_command_accepted: bool,
                                             stop_effective_before_irreversible: bool) -> dict:
    """Challenge authority continuity across a transition into irreversible consequence.

    This does not replace Step 180. It pressure-tests the composition rule that a
    previously valid authorization cannot silently survive revocation while an
    action is moving from reversible execution into irreversible consequence.
    """
    if not authority_current_at_start:
        return _result(
            "TRANSITION_NOT_SUPPORTABLE",
            "AUTHORITY_NOT_CURRENT_AT_TRANSITION_START",
            current_execution_supportable=False,
            no_bind_state="ACTIVE",
            residual_consequence_review_required=consequence_started,
        )
    if not authority_current_at_commit:
        return _result(
            "TRANSITION_NOT_SUPPORTABLE",
            "AUTHORITY_NOT_CURRENT_AT_COMMIT",
            current_execution_supportable=False,
            no_bind_state="ACTIVE",
            residual_consequence_review_required=consequence_started,
        )
    if not authority_current_at_irreversible_boundary:
        if stop_command_accepted and stop_effective_before_irreversible and not irreversible_consequence_occurred:
            return _result(
                "HELD_BEFORE_IRREVERSIBLE_CONSEQUENCE",
                "AUTHORITY_REVOKED_DURING_TRANSITION",
                current_execution_supportable=False,
                no_bind_state="ACTIVE",
                residual_consequence_review_required=consequence_started,
            )
        return _result(
            "RESIDUAL_CONSEQUENCE_REVIEW_REQUIRED",
            "REVOCATION_DID_NOT_PREVENT_IRREVERSIBLE_CONSEQUENCE",
            current_execution_supportable=False,
            no_bind_state="ACTIVE",
            residual_consequence_review_required=True,
        )
    return _result(
        "TRANSITION_SUPPORTABLE",
        "AUTHORITY_CONTINUITY_SUPPORTED_THROUGH_DECLARED_BOUNDARY",
        current_execution_supportable=True,
        no_bind_state="SEPARATE_ACTION_ADMISSIBILITY_REQUIRED",
        residual_consequence_review_required=False,
    )


def evaluate_competing_execution_claims(*,
                                        consequence_id: str,
                                        claims: Iterable[Mapping[str, object]],
                                        serialization_winner_claim_id: str | None = None,
                                        losing_claims_retired_before_consequence: bool = False) -> dict:
    """Challenge multiple execution claims against one consequence identity."""
    records = [dict(item) for item in claims]
    eligible = [item for item in records if bool(item.get("eligible", False))]
    executed = [item for item in records if bool(item.get("executed", False))]
    eligible_ids = sorted(str(item.get("claim_id", "UNIDENTIFIED")) for item in eligible)
    executed_ids = sorted(str(item.get("claim_id", "UNIDENTIFIED")) for item in executed)

    if not consequence_id:
        return _result(
            "NOT_ESTABLISHED",
            "CONSEQUENCE_ID_MISSING",
            no_bind_state="ACTIVE",
        )
    if len(executed) > 1:
        return _result(
            "DUPLICATE_CONSEQUENCE_DETECTED",
            "MULTIPLE_EXECUTION_CLAIMS_REACHED_CONSEQUENCE",
            eligible_claim_ids=eligible_ids,
            executed_claim_ids=executed_ids,
            no_bind_state="ACTIVE",
        )
    if len(eligible) > 1 and not serialization_winner_claim_id:
        return _result(
            "RACE_UNRESOLVED",
            "MULTIPLE_CURRENT_EXECUTION_CLAIMS_WITHOUT_SERIALIZATION_WINNER",
            eligible_claim_ids=eligible_ids,
            executed_claim_ids=executed_ids,
            no_bind_state="ACTIVE",
        )
    if len(eligible) > 1:
        winner = str(serialization_winner_claim_id)
        if winner not in eligible_ids:
            return _result(
                "RACE_UNRESOLVED",
                "DECLARED_WINNER_NOT_CURRENTLY_ELIGIBLE",
                eligible_claim_ids=eligible_ids,
                executed_claim_ids=executed_ids,
                no_bind_state="ACTIVE",
            )
        if not losing_claims_retired_before_consequence:
            return _result(
                "RACE_UNRESOLVED",
                "LOSING_EXECUTION_CLAIMS_NOT_RETIRED_BEFORE_CONSEQUENCE",
                eligible_claim_ids=eligible_ids,
                executed_claim_ids=executed_ids,
                serialization_winner_claim_id=winner,
                no_bind_state="ACTIVE",
            )
    return _result(
        "SINGLE_CONSEQUENCE_ROUTE_SUPPORTABLE",
        "COMPETING_CLAIMS_BOUNDED_WITHIN_DECLARED_SCOPE",
        eligible_claim_ids=eligible_ids,
        executed_claim_ids=executed_ids,
        serialization_winner_claim_id=serialization_winner_claim_id,
        no_bind_state="SEPARATE_ACTION_ADMISSIBILITY_REQUIRED",
    )


def evaluate_retry_replay_consequence(*,
                                      retry_or_replay_requested: bool,
                                      prior_consequence_state_known: bool,
                                      original_idempotency_key: str | None,
                                      retry_idempotency_key: str | None,
                                      duplicate_prevention_established: bool,
                                      second_consequence_observed: bool) -> dict:
    """Prevent retry/replay ambiguity from producing duplicate consequence."""
    if second_consequence_observed:
        return _result(
            "DUPLICATE_CONSEQUENCE_DETECTED",
            "SECOND_CONSEQUENCE_OBSERVED",
            no_bind_state="ACTIVE",
            retry_supportable=False,
        )
    if not retry_or_replay_requested:
        return _result(
            "NOT_APPLICABLE",
            "NO_RETRY_OR_REPLAY_REQUESTED",
            no_bind_state="UNCHANGED",
            retry_supportable=None,
        )
    if not prior_consequence_state_known:
        return _result(
            "RETRY_NOT_SUPPORTABLE",
            "PRIOR_CONSEQUENCE_STATE_UNKNOWN",
            no_bind_state="ACTIVE",
            retry_supportable=False,
        )
    if not original_idempotency_key or not retry_idempotency_key:
        return _result(
            "RETRY_NOT_SUPPORTABLE",
            "IDEMPOTENCY_CORRESPONDENCE_NOT_ESTABLISHED",
            no_bind_state="ACTIVE",
            retry_supportable=False,
        )
    if str(original_idempotency_key) != str(retry_idempotency_key):
        return _result(
            "RETRY_NOT_SUPPORTABLE",
            "RETRY_IDEMPOTENCY_KEY_MISMATCH",
            no_bind_state="ACTIVE",
            retry_supportable=False,
        )
    if not duplicate_prevention_established:
        return _result(
            "RETRY_NOT_SUPPORTABLE",
            "DUPLICATE_CONSEQUENCE_PREVENTION_NOT_ESTABLISHED",
            no_bind_state="ACTIVE",
            retry_supportable=False,
        )
    return _result(
        "RETRY_ROUTE_SUPPORTABLE",
        "RETRY_BOUNDED_BY_ESTABLISHED_IDEMPOTENCY_AND_PRIOR_STATE",
        no_bind_state="SEPARATE_ACTION_ADMISSIBILITY_REQUIRED",
        retry_supportable=True,
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
                                         history_preserved: bool,
                                         partial_irreversible_consequence_present: bool = False,
                                         latent_consequence_possible: bool = False,
                                         latent_observation_window_complete: bool = True,
                                         execution_stop_established: bool = False,
                                         propagation_after_stop_present: bool = False) -> dict:
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
    if partial_irreversible_consequence_present:
        reasons.append("PARTIAL_IRREVERSIBLE_CONSEQUENCE_PRESENT")
    if residual_effects_present:
        reasons.append("RESIDUAL_CONSEQUENCE_REMAINS")
    if latent_consequence_possible and not latent_observation_window_complete:
        reasons.append("LATENT_CONSEQUENCE_WINDOW_OPEN")
    if propagation_after_stop_present:
        if execution_stop_established:
            reasons.append("CONSEQUENCE_PROPAGATING_AFTER_EXECUTION_STOP")
        else:
            reasons.append("CONSEQUENCE_PROPAGATION_PRESENT_WITHOUT_ESTABLISHED_STOP")
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
