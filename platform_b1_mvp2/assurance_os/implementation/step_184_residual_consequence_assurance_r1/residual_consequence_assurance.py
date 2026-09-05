"""Step 184 — Residual-Consequence Assurance R1.

This bounded evaluator hardens the post-execution / post-stop boundary. It asks
whether a consequence has actually terminated and whether return to reliance is
supportable after considering residual, partial, latent, contradictory, race, and
retry states.

It does not execute actions, grant authority, close regulated investigations, or
modify IRLT-MAG state.
"""

from __future__ import annotations

from collections.abc import Mapping


def _result(standing: str, reason: str, reasons: list[str], **extra) -> dict:
    blocked = standing != "RESIDUAL_CONSEQUENCE_CLOSED_WITHIN_DECLARED_SCOPE"
    return {
        "residual_consequence_standing": standing,
        "reason": reason,
        "reasons": sorted(set(reasons)),
        "return_to_reliance_supportable": not blocked,
        "no_bind_state": "ACTIVE" if blocked else "SEPARATE_AUTHORITY_AND_ACTION_ADMISSIBILITY_REQUIRED",
        "action_hold_required": blocked,
        "binding_authority_granted": False,
        "physical_action_executed_by_evaluator": False,
        "historical_facts_rewritten": False,
        "irlt_mag_state_changed": False,
        **extra,
    }


def evaluate_residual_consequence_assurance(
    *,
    execution_time_result: Mapping[str, object],
    outcome_result: Mapping[str, object],
    reclosure_result: Mapping[str, object],
    consequence_state: Mapping[str, object],
    race_retry_state: Mapping[str, object],
    evidence_state: Mapping[str, object],
) -> dict:
    """Evaluate whether residual consequence is closed within a declared scope.

    The evaluator preserves these distinctions:

    AUTHORITY WITHDRAWN != EXECUTION TERMINATED != CONSEQUENCE TERMINATED
    EXECUTION SUCCESS != INTENDED OUTCOME ESTABLISHED
    STOP SUCCESS != CONSEQUENCE TERMINATION
    RECOVERY != RECLOSURE != RETURN TO RELIANCE

    A positive result is non-binding and still requires separate current authority
    and Action Admissibility evaluation before any new consequence-producing action.
    """

    if not all(isinstance(x, Mapping) for x in (
        execution_time_result,
        outcome_result,
        reclosure_result,
        consequence_state,
        race_retry_state,
        evidence_state,
    )):
        return _result(
            "RESIDUAL_CONSEQUENCE_STANDING_NOT_ESTABLISHED",
            "REQUIRED_INPUT_MAPPING_MISSING",
            ["REQUIRED_INPUT_MAPPING_MISSING"],
        )

    reasons: list[str] = []

    execution_standing = execution_time_result.get("execution_time_standing")
    outcome_standing = outcome_result.get("correspondence_standing")
    reclosure_standing = reclosure_result.get("reclosure_standing")

    if execution_standing != "SUPPORTABLE":
        reasons.append("EXECUTION_TIME_STANDING_NOT_SUPPORTABLE")
    if outcome_standing != "OUTCOME_CORRESPONDENCE_SUPPORTABLE":
        reasons.append("OUTCOME_CORRESPONDENCE_NOT_SUPPORTABLE")
    if reclosure_standing != "RECLOSURE_SUPPORTABLE":
        reasons.append("PRIOR_RECLOSURE_NOT_SUPPORTABLE")

    history_preserved = consequence_state.get("historical_event_preserved") is True
    if not history_preserved:
        reasons.append("HISTORICAL_EVENT_PRESERVATION_NOT_ESTABLISHED")

    authority_current_at_boundary = consequence_state.get("authority_current_at_irreversible_boundary") is True
    irreversible_boundary_crossed = consequence_state.get("irreversible_boundary_crossed") is True
    if irreversible_boundary_crossed and not authority_current_at_boundary:
        reasons.append("AUTHORITY_NOT_CURRENT_AT_IRREVERSIBLE_BOUNDARY")

    stop_succeeded = consequence_state.get("stop_command_succeeded") is True
    termination_observed = consequence_state.get("consequence_termination_observed") is True
    if stop_succeeded and not termination_observed:
        reasons.append("STOP_SUCCESS_WITHOUT_CONSEQUENCE_TERMINATION_EVIDENCE")

    partial_irreversible = consequence_state.get("partial_irreversible_consequence") is True
    residual_propagation = consequence_state.get("residual_propagation_active") is True
    latent_window_open = consequence_state.get("latent_consequence_window_open") is True
    residual_effects = consequence_state.get("residual_effects_present") is True

    if partial_irreversible:
        reasons.append("PARTIAL_IRREVERSIBLE_CONSEQUENCE_PRESENT")
    if residual_propagation:
        reasons.append("RESIDUAL_PROPAGATION_ACTIVE")
    if latent_window_open:
        reasons.append("LATENT_CONSEQUENCE_WINDOW_OPEN")
    if residual_effects:
        reasons.append("RESIDUAL_EFFECTS_PRESENT")

    if consequence_state.get("current_physical_correspondence_established") is not True:
        reasons.append("CURRENT_PHYSICAL_CORRESPONDENCE_NOT_ESTABLISHED")
    if consequence_state.get("witness_proposition_qualified") is not True:
        reasons.append("WITNESS_NOT_QUALIFIED_FOR_TERMINATION_PROPOSITION")
    if consequence_state.get("observation_current") is not True:
        reasons.append("CONSEQUENCE_OBSERVATION_NOT_CURRENT")

    contradiction_present = evidence_state.get("contradiction_present") is True
    if contradiction_present:
        reasons.append("CONTRADICTORY_CONSEQUENCE_EVIDENCE_PRESENT")
    if evidence_state.get("independent_failure_domains_established") is not True:
        reasons.append("WITNESS_FAILURE_DOMAIN_INDEPENDENCE_NOT_ESTABLISHED")
    if evidence_state.get("negative_evidence_basis_complete") is not True:
        reasons.append("NEGATIVE_EVIDENCE_BASIS_NOT_ESTABLISHED")

    competing_claims = int(race_retry_state.get("active_competing_claim_count", 0) or 0)
    if competing_claims > 1:
        if race_retry_state.get("single_winner_serialized") is not True:
            reasons.append("COMPETING_EXECUTION_CLAIMS_NOT_SERIALIZED")
        if race_retry_state.get("losing_claims_retired") is not True:
            reasons.append("LOSING_EXECUTION_CLAIMS_NOT_RETIRED")

    retry_requested = race_retry_state.get("retry_requested") is True
    if retry_requested:
        if race_retry_state.get("prior_attempt_consequence_state_known") is not True:
            reasons.append("PRIOR_ATTEMPT_CONSEQUENCE_STATE_UNKNOWN")
        if race_retry_state.get("idempotency_identity_matches") is not True:
            reasons.append("IDEMPOTENCY_IDENTITY_NOT_ESTABLISHED")
        if race_retry_state.get("duplicate_consequence_prevention_established") is not True:
            reasons.append("DUPLICATE_CONSEQUENCE_PREVENTION_NOT_ESTABLISHED")

    if contradiction_present:
        standing = "RESIDUAL_CONSEQUENCE_CONTRADICTED"
        reason = "CONTRADICTORY_EVIDENCE_PREVENTS_CLOSURE"
    elif any(r in reasons for r in (
        "PARTIAL_IRREVERSIBLE_CONSEQUENCE_PRESENT",
        "RESIDUAL_PROPAGATION_ACTIVE",
        "LATENT_CONSEQUENCE_WINDOW_OPEN",
        "RESIDUAL_EFFECTS_PRESENT",
    )):
        standing = "RESIDUAL_CONSEQUENCE_PRESENT_OR_OPEN"
        reason = "CONSEQUENCE_HAS_NOT_BEEN_SHOWN_TO_BE_TERMINATED"
    elif any(r in reasons for r in (
        "COMPETING_EXECUTION_CLAIMS_NOT_SERIALIZED",
        "LOSING_EXECUTION_CLAIMS_NOT_RETIRED",
        "PRIOR_ATTEMPT_CONSEQUENCE_STATE_UNKNOWN",
        "IDEMPOTENCY_IDENTITY_NOT_ESTABLISHED",
        "DUPLICATE_CONSEQUENCE_PREVENTION_NOT_ESTABLISHED",
    )):
        standing = "CONSEQUENCE_CONTROL_CLOSURE_NOT_ESTABLISHED"
        reason = "RACE_OR_RETRY_CONSEQUENCE_CONTROL_INCOMPLETE"
    elif reasons:
        standing = "RESIDUAL_CONSEQUENCE_STANDING_NOT_ESTABLISHED"
        reason = "ONE_OR_MORE_CLOSURE_PRECONDITIONS_NOT_ESTABLISHED"
    else:
        standing = "RESIDUAL_CONSEQUENCE_CLOSED_WITHIN_DECLARED_SCOPE"
        reason = "CURRENT_TERMINATION_AND_RECLOSURE_BASIS_ESTABLISHED"

    return _result(
        standing,
        reason,
        reasons,
        execution_time_standing=execution_standing,
        outcome_correspondence_standing=outcome_standing,
        prior_reclosure_standing=reclosure_standing,
        irreversible_boundary_crossed=irreversible_boundary_crossed,
        authority_current_at_irreversible_boundary=authority_current_at_boundary,
        stop_command_succeeded=stop_succeeded,
        consequence_termination_observed=termination_observed,
        partial_irreversible_consequence=partial_irreversible,
        residual_propagation_active=residual_propagation,
        latent_consequence_window_open=latent_window_open,
        residual_effects_present=residual_effects,
        contradiction_present=contradiction_present,
        active_competing_claim_count=competing_claims,
        retry_requested=retry_requested,
    )
