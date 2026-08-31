"""Cross-domain physical evidence standing primitives for Assurance Engineering.

Bounded, non-binding evaluators. They do not authorize regulated actions.
"""


def _result(state, reason, **extra):
    return {"state": state, "reason": reason, "binding_decision_made": False, **extra}


def evaluate_operating_envelope(
    *,
    calibrated,
    authenticated,
    healthy,
    inside_validated_state_space,
    corridor_supported=True,
    structural_change_detected=False,
    topology_changed=False,
    bifurcation_detected=False,
    qualified_envelope_id=None,
    current_envelope_id=None,
):
    """Evaluate current operating-envelope standing without silent regime inheritance.

    The original Step 176 instrument/state-space checks remain authoritative.
    Optional structural-regime inputs sharpen the same control: green current
    values do not establish that the qualified operating regime is unchanged.
    """
    if not all([calibrated, authenticated, healthy]):
        return _result("NOT_ESTABLISHED", "INSTRUMENT_STANDING_DEFECT")
    if not corridor_supported:
        return _result("NOT_ESTABLISHED", "NO_SUPPORTABLE_OPERATING_CORRIDOR")
    if bifurcation_detected:
        return _result("REASSESSMENT_REQUIRED", "OPERATING_REGIME_BIFURCATED")
    if structural_change_detected or topology_changed:
        return _result("REASSESSMENT_REQUIRED", "STRUCTURAL_OPERATING_REGIME_CHANGED")
    if qualified_envelope_id is not None and current_envelope_id is not None:
        if str(qualified_envelope_id) != str(current_envelope_id):
            return _result("REASSESSMENT_REQUIRED", "QUALIFIED_OPERATING_ENVELOPE_ID_CHANGED")
    if not inside_validated_state_space:
        return _result("REASSESSMENT_REQUIRED", "OUTSIDE_VALIDATED_OPERATING_ENVELOPE")
    return _result("SUPPORTABLE", "OPERATING_ENVELOPE_SUPPORTED")


def evaluate_observation_channel(*, channel_validated, transport_loss_material, witness_perturbation_material):
    if not channel_validated:
        return _result("NOT_ESTABLISHED", "OBSERVATION_CHANNEL_NOT_VALIDATED")
    if transport_loss_material or witness_perturbation_material:
        return _result("REASSESSMENT_REQUIRED", "OBSERVATION_CHANNEL_FIDELITY_COMPROMISED")
    return _result("SUPPORTABLE", "OBSERVATION_CHANNEL_FIDELITY_SUPPORTED")


def evaluate_temporal_resolution(*, sensor_response_seconds, sampling_interval_seconds, event_timescale_seconds, aggregation_window_seconds=0):
    if min(sensor_response_seconds, sampling_interval_seconds, event_timescale_seconds) <= 0:
        raise ValueError("times must be positive")
    if sensor_response_seconds > event_timescale_seconds:
        return _result("NOT_ESTABLISHED", "SENSOR_RESPONSE_TOO_SLOW")
    if sampling_interval_seconds > event_timescale_seconds:
        return _result("NOT_ESTABLISHED", "TEMPORAL_ALIASING_POSSIBLE")
    if aggregation_window_seconds and aggregation_window_seconds > event_timescale_seconds:
        return _result("REASSESSMENT_REQUIRED", "AGGREGATION_MAY_MASK_TRANSIENT")
    return _result("SUPPORTABLE", "TEMPORAL_RESOLUTION_SUFFICIENT")


def evaluate_detectability(*, value, detection_limit, quantification_limit, upper_valid_limit=None):
    if quantification_limit < detection_limit:
        raise ValueError("quantification_limit must be >= detection_limit")
    if value <= detection_limit:
        return _result("NOT_DETECTED_WITH_LIMIT", "BELOW_OR_AT_DETECTION_LIMIT")
    if value <= quantification_limit:
        return _result("DETECTED_NOT_RELIABLY_QUANTIFIED", "BETWEEN_DETECTION_AND_QUANTIFICATION_LIMIT")
    if upper_valid_limit is not None and value > upper_valid_limit:
        return _result("ABOVE_VALID_RANGE", "MEASUREMENT_CENSORED_OR_OUT_OF_RANGE")
    return _result("QUANTIFIED_WITHIN_VALID_RANGE", "MEASUREMENT_WITHIN_QUANTITATIVE_RANGE")


def evaluate_bridge_standing(*, regime_a_valid, regime_b_valid, equivalence_challenge_performed, equivalent_within_declared_margin):
    if not regime_a_valid or not regime_b_valid:
        return _result("NOT_ESTABLISHED", "ONE_OR_BOTH_MEASUREMENT_REGIMES_INVALID")
    if not equivalence_challenge_performed:
        return _result("NOT_ESTABLISHED", "COMPARABILITY_NOT_CHALLENGED")
    if not equivalent_within_declared_margin:
        return _result("NOT_ESTABLISHED", "COMPARABILITY_FAILED")
    return _result("ESTABLISHED", "MEASUREMENT_BRIDGE_ESTABLISHED")


def evaluate_composition_standing(*, components_valid, semantic_compatible, units_compatible, timing_compatible, intended_use_compatible):
    if not components_valid:
        return _result("NOT_ESTABLISHED", "COMPONENT_STANDING_FAILED")
    if not all([semantic_compatible, units_compatible, timing_compatible, intended_use_compatible]):
        return _result("NOT_ESTABLISHED", "INTERFACE_OR_COMPOSITION_NOT_ESTABLISHED")
    return _result("ESTABLISHED", "COMPOSED_SYSTEM_COMPATIBILITY_ESTABLISHED")


def evaluate_fusion_standing(*, inputs_supportable, dependencies_characterized, uncertainty_propagated, fusion_version_known):
    if not inputs_supportable:
        return _result("NOT_ESTABLISHED", "ONE_OR_MORE_INPUTS_NOT_SUPPORTABLE")
    if not dependencies_characterized:
        return _result("DEPENDENCY_UNCERTAIN", "COMMON_DEPENDENCIES_NOT_CHARACTERIZED")
    if not uncertainty_propagated or not fusion_version_known:
        return _result("REASSESSMENT_REQUIRED", "FUSED_STATE_PROVENANCE_OR_UNCERTAINTY_INCOMPLETE")
    return _result("SUPPORTABLE", "FUSED_STATE_SUPPORTED")


def evaluate_source_attribution(*, condition_established, candidate_source_supported, alternatives_excluded):
    if not condition_established:
        return _result("NOT_ESTABLISHED", "UNDERLYING_CONDITION_NOT_ESTABLISHED")
    if not candidate_source_supported:
        return _result("SOURCE_NOT_ESTABLISHED", "SOURCE_EVIDENCE_INSUFFICIENT")
    if not alternatives_excluded:
        return _result("SOURCE_POSSIBLE", "COMPETING_SOURCES_REMAIN")
    return _result("SOURCE_SUPPORTED", "SOURCE_ATTRIBUTION_SUPPORTED")


def evaluate_time_indexed_standing(*, currently_supportable, valid_until_epoch, now_epoch):
    if not currently_supportable:
        return _result("NOT_ESTABLISHED", "CURRENT_STANDING_NOT_SUPPORTABLE")
    if now_epoch > valid_until_epoch:
        return _result("REASSESSMENT_REQUIRED", "TIME_INDEXED_STANDING_EXPIRED")
    return _result("SUPPORTABLE", "TIME_INDEXED_STANDING_CURRENT")


def evaluate_decision_policy(*, model_valid, interpretation_valid, rule_current, policy_challenged, authority_current):
    if not model_valid or not interpretation_valid:
        return _result("NOT_ESTABLISHED", "MODEL_OR_INTERPRETATION_STANDING_FAILED")
    if not rule_current:
        return _result("REASSESSMENT_REQUIRED", "DECISION_RULE_NOT_CURRENT")
    if not policy_challenged:
        return _result("NOT_ESTABLISHED", "DECISION_POLICY_NOT_VALIDATED")
    if not authority_current:
        return _result("NO_BIND", "AUTHORITY_NOT_CURRENT")
    return _result("SUPPORTABLE", "DECISION_POLICY_SUPPORTED")


def evaluate_oversight_capacity(*, qualified_human_available, evidence_presented, review_time_sufficient, workload_within_capacity, can_intervene_before_irreversible):
    checks = [qualified_human_available, evidence_presented, review_time_sufficient, workload_within_capacity, can_intervene_before_irreversible]
    if all(checks):
        return _result("SUPPORTABLE", "MEANINGFUL_HUMAN_OVERSIGHT_AVAILABLE")
    return _result("NOT_ESTABLISHED", "HUMAN_OVERSIGHT_CAPACITY_INSUFFICIENT")


def evaluate_transfer_fidelity(*, intended_quantity, delivered_quantity, tolerance_fraction, destination_verified):
    if intended_quantity <= 0 or delivered_quantity < 0 or tolerance_fraction < 0:
        raise ValueError("invalid quantity or tolerance")
    deviation = abs(delivered_quantity - intended_quantity) / intended_quantity
    if deviation > tolerance_fraction:
        return _result("NOT_ESTABLISHED", "DELIVERY_OUTSIDE_TOLERANCE", deviation_fraction=deviation)
    if not destination_verified:
        return _result("REASSESSMENT_REQUIRED", "DESTINATION_OR_OUTCOME_NOT_VERIFIED", deviation_fraction=deviation)
    return _result("SUPPORTABLE", "TRANSFER_AND_DELIVERY_SUPPORTED", deviation_fraction=deviation)
