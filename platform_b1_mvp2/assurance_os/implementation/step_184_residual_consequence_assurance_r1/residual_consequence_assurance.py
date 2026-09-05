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


CLOSED = "RESIDUAL_CONSEQUENCE_CLOSED_WITHIN_DECLARED_SCOPE"


def _result(standing: str, reason: str, reasons: list[str], **extra) -> dict:
    blocked = standing != CLOSED
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


def _required_bool(record: Mapping[str, object], field: str, reasons: list[str], prefix: str) -> bool | None:
    """Return an explicitly supplied bool; missing/invalid values fail closed."""
    if field not in record:
        reasons.append(f"{prefix}_{field.upper()}_MISSING")
        return None
    value = record.get(field)
    if type(value) is not bool:
        reasons.append(f"{prefix}_{field.upper()}_INVALID")
        return None
    return value


def _required_nonnegative_int(record: Mapping[str, object], field: str, reasons: list[str], prefix: str) -> int | None:
    """Reject coercion and booleans; malformed counts become bounded uncertainty."""
    if field not in record:
        reasons.append(f"{prefix}_{field.upper()}_MISSING")
        return None
    value = record.get(field)
    if type(value) is not int or value < 0:
        reasons.append(f"{prefix}_{field.upper()}_INVALID")
        return None
    return value


def _validate_upstream_contracts(
    execution_time_result: Mapping[str, object],
    outcome_result: Mapping[str, object],
    reclosure_result: Mapping[str, object],
    reasons: list[str],
) -> tuple[object, object, object]:
    """Validate the declared non-binding output contracts of Steps 180, 182, 183."""
    execution_standing = execution_time_result.get("execution_time_standing")
    outcome_standing = outcome_result.get("correspondence_standing")
    reclosure_standing = reclosure_result.get("reclosure_standing")

    if execution_standing != "SUPPORTABLE":
        reasons.append("EXECUTION_TIME_STANDING_NOT_SUPPORTABLE")
    if execution_time_result.get("execution_time_decision") != "ADMISSIBLE":
        reasons.append("EXECUTION_TIME_DECISION_NOT_ADMISSIBLE")
    if execution_time_result.get("no_bind_state") != "INACTIVE":
        reasons.append("EXECUTION_TIME_NO_BIND_NOT_INACTIVE")
    if execution_time_result.get("binding_authority_granted") is not False:
        reasons.append("EXECUTION_TIME_NONAUTHORITY_CONTRACT_NOT_ESTABLISHED")
    if execution_time_result.get("prior_decision_preserved_as_history") is not True:
        reasons.append("EXECUTION_TIME_HISTORY_PRESERVATION_NOT_ESTABLISHED")

    if outcome_standing != "OUTCOME_CORRESPONDENCE_SUPPORTABLE":
        reasons.append("OUTCOME_CORRESPONDENCE_NOT_SUPPORTABLE")
    if outcome_result.get("commit_occurred") is not True:
        reasons.append("OUTCOME_COMMIT_FACT_NOT_ESTABLISHED")
    if outcome_result.get("execution_succeeded") is not True:
        reasons.append("OUTCOME_EXECUTION_SUCCESS_NOT_ESTABLISHED")
    if outcome_result.get("intended_outcome_established") is not True:
        reasons.append("INTENDED_OUTCOME_NOT_ESTABLISHED")
    if outcome_result.get("no_bind_state") != "INACTIVE":
        reasons.append("OUTCOME_NO_BIND_NOT_INACTIVE")
    if outcome_result.get("binding_authority_granted") is not False:
        reasons.append("OUTCOME_NONAUTHORITY_CONTRACT_NOT_ESTABLISHED")
    historical_facts = outcome_result.get("historical_facts")
    if not isinstance(historical_facts, Mapping):
        reasons.append("OUTCOME_HISTORICAL_FACTS_MISSING")
    else:
        if historical_facts.get("commit_occurred") is not True:
            reasons.append("OUTCOME_HISTORICAL_COMMIT_FACT_NOT_PRESERVED")
        if historical_facts.get("execution_succeeded") is not True:
            reasons.append("OUTCOME_HISTORICAL_EXECUTION_FACT_NOT_PRESERVED")

    if reclosure_standing != "RECLOSURE_SUPPORTABLE":
        reasons.append("PRIOR_RECLOSURE_NOT_SUPPORTABLE")
    if reclosure_result.get("return_to_reliance_supportable") is not True:
        reasons.append("PRIOR_RETURN_TO_RELIANCE_NOT_SUPPORTABLE")
    if reclosure_result.get("no_bind_state") != "SEPARATE_AUTHORITY_AND_ACTION_ADMISSIBILITY_REQUIRED":
        reasons.append("RECLOSURE_NO_BIND_CONTRACT_NOT_ESTABLISHED")
    if reclosure_result.get("binding_authority_granted") is not False:
        reasons.append("RECLOSURE_NONAUTHORITY_CONTRACT_NOT_ESTABLISHED")
    if reclosure_result.get("historical_facts_rewritten") is not False:
        reasons.append("RECLOSURE_HISTORY_PRESERVATION_NOT_ESTABLISHED")

    return execution_standing, outcome_standing, reclosure_standing


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

    Unknown safety-critical negative states do not default to benign values. A
    positive result is non-binding and still requires separate current authority
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

    execution_standing, outcome_standing, reclosure_standing = _validate_upstream_contracts(
        execution_time_result, outcome_result, reclosure_result, reasons
    )

    history_preserved = _required_bool(consequence_state, "historical_event_preserved", reasons, "CONSEQUENCE")
    authority_current_at_boundary = _required_bool(
        consequence_state, "authority_current_at_irreversible_boundary", reasons, "CONSEQUENCE"
    )
    irreversible_boundary_crossed = _required_bool(
        consequence_state, "irreversible_boundary_crossed", reasons, "CONSEQUENCE"
    )
    stop_succeeded = _required_bool(consequence_state, "stop_command_succeeded", reasons, "CONSEQUENCE")
    termination_observed = _required_bool(
        consequence_state, "consequence_termination_observed", reasons, "CONSEQUENCE"
    )
    partial_irreversible = _required_bool(
        consequence_state, "partial_irreversible_consequence", reasons, "CONSEQUENCE"
    )
    residual_propagation = _required_bool(
        consequence_state, "residual_propagation_active", reasons, "CONSEQUENCE"
    )
    latent_window_open = _required_bool(
        consequence_state, "latent_consequence_window_open", reasons, "CONSEQUENCE"
    )
    residual_effects = _required_bool(consequence_state, "residual_effects_present", reasons, "CONSEQUENCE")
    current_physical = _required_bool(
        consequence_state, "current_physical_correspondence_established", reasons, "CONSEQUENCE"
    )
    witness_qualified = _required_bool(
        consequence_state, "witness_proposition_qualified", reasons, "CONSEQUENCE"
    )
    observation_current = _required_bool(consequence_state, "observation_current", reasons, "CONSEQUENCE")

    if history_preserved is False:
        reasons.append("HISTORICAL_EVENT_PRESERVATION_NOT_ESTABLISHED")
    if irreversible_boundary_crossed is True and authority_current_at_boundary is not True:
        reasons.append("AUTHORITY_NOT_CURRENT_AT_IRREVERSIBLE_BOUNDARY")
    if stop_succeeded is True and termination_observed is not True:
        reasons.append("STOP_SUCCESS_WITHOUT_CONSEQUENCE_TERMINATION_EVIDENCE")
    if partial_irreversible is True:
        reasons.append("PARTIAL_IRREVERSIBLE_CONSEQUENCE_PRESENT")
    if residual_propagation is True:
        reasons.append("RESIDUAL_PROPAGATION_ACTIVE")
    if latent_window_open is True:
        reasons.append("LATENT_CONSEQUENCE_WINDOW_OPEN")
    if residual_effects is True:
        reasons.append("RESIDUAL_EFFECTS_PRESENT")
    if current_physical is False:
        reasons.append("CURRENT_PHYSICAL_CORRESPONDENCE_NOT_ESTABLISHED")
    if witness_qualified is False:
        reasons.append("WITNESS_NOT_QUALIFIED_FOR_TERMINATION_PROPOSITION")
    if observation_current is False:
        reasons.append("CONSEQUENCE_OBSERVATION_NOT_CURRENT")

    contradiction_present = _required_bool(evidence_state, "contradiction_present", reasons, "EVIDENCE")
    independent_domains = _required_bool(
        evidence_state, "independent_failure_domains_established", reasons, "EVIDENCE"
    )
    negative_basis = _required_bool(evidence_state, "negative_evidence_basis_complete", reasons, "EVIDENCE")

    if contradiction_present is True:
        reasons.append("CONTRADICTORY_CONSEQUENCE_EVIDENCE_PRESENT")
    if independent_domains is False:
        reasons.append("WITNESS_FAILURE_DOMAIN_INDEPENDENCE_NOT_ESTABLISHED")
    if negative_basis is False:
        reasons.append("NEGATIVE_EVIDENCE_BASIS_NOT_ESTABLISHED")

    competing_claims = _required_nonnegative_int(
        race_retry_state, "active_competing_claim_count", reasons, "RACE_RETRY"
    )
    retry_requested = _required_bool(race_retry_state, "retry_requested", reasons, "RACE_RETRY")

    if competing_claims is not None and competing_claims > 1:
        winner_serialized = _required_bool(
            race_retry_state, "single_winner_serialized", reasons, "RACE_RETRY"
        )
        losing_retired = _required_bool(
            race_retry_state, "losing_claims_retired", reasons, "RACE_RETRY"
        )
        if winner_serialized is False:
            reasons.append("COMPETING_EXECUTION_CLAIMS_NOT_SERIALIZED")
        if losing_retired is False:
            reasons.append("LOSING_EXECUTION_CLAIMS_NOT_RETIRED")

    if retry_requested is True:
        prior_state_known = _required_bool(
            race_retry_state, "prior_attempt_consequence_state_known", reasons, "RACE_RETRY"
        )
        idempotency_matches = _required_bool(
            race_retry_state, "idempotency_identity_matches", reasons, "RACE_RETRY"
        )
        duplicate_prevention = _required_bool(
            race_retry_state, "duplicate_consequence_prevention_established", reasons, "RACE_RETRY"
        )
        if prior_state_known is False:
            reasons.append("PRIOR_ATTEMPT_CONSEQUENCE_STATE_UNKNOWN")
        if idempotency_matches is False:
            reasons.append("IDEMPOTENCY_IDENTITY_NOT_ESTABLISHED")
        if duplicate_prevention is False:
            reasons.append("DUPLICATE_CONSEQUENCE_PREVENTION_NOT_ESTABLISHED")

    if contradiction_present is True:
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
        standing = CLOSED
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
