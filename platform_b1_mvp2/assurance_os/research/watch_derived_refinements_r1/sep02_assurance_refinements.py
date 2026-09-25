"""September 2 watch-derived assurance refinements.

Difference-first experimental evaluators only. These functions extend the existing
shared assurance research surface and deliberately avoid creating duplicate runtime
engines. They create no regulatory, institutional, clinical, quality, radiation,
pharmacist, or physical execution authority.
"""

from __future__ import annotations

from typing import Iterable, Mapping


def evaluate_independent_reproduction_standing(*, frozen_package_present: bool,
                                                independent_evaluator: bool,
                                                replay_completed: bool,
                                                acceptance_criteria_frozen: bool,
                                                material_conditions_preserved: bool,
                                                result_correspondence_established: bool,
                                                disagreement_preserved: bool) -> dict:
    """A reproducible package is not independently reproduced until a separate evaluator replays it."""
    supportable = all([
        frozen_package_present,
        independent_evaluator,
        replay_completed,
        acceptance_criteria_frozen,
        material_conditions_preserved,
        result_correspondence_established,
        disagreement_preserved,
    ])
    return {
        "independent_reproduction_standing": "SUPPORTABLE" if supportable else "NOT_ESTABLISHED",
        "reproducible_package_equals_independent_reproduction": False,
        "self_replay_equals_independent_confirmation": False,
        "matching_replay_equals_safety_or_correctness": False,
        "binding_decision_made": False,
        "fail_closed": not supportable,
    }


def evaluate_assurance_test_harness_integrity(*, expected_results_frozen: bool,
                                               evidence_references_bound: bool,
                                               witness_independence_established: bool,
                                               test_vectors_frozen: bool,
                                               oracle_integrity_established: bool,
                                               receipt_trace_correspondence: bool,
                                               bypass_surface_covered: bool) -> dict:
    """A passing control test is not trustworthy when the test harness itself is compromised."""
    supportable = all([
        expected_results_frozen,
        evidence_references_bound,
        witness_independence_established,
        test_vectors_frozen,
        oracle_integrity_established,
        receipt_trace_correspondence,
        bypass_surface_covered,
    ])
    return {
        "assurance_test_harness_integrity": "SUPPORTABLE" if supportable else "NOT_ESTABLISHED",
        "control_test_pass_equals_harness_trustworthy": False,
        "evidence_generated_equals_evidence_pipeline_assured": False,
        "binding_decision_made": False,
        "fail_closed": not supportable,
    }


def evaluate_challenge_population_selection_provenance(*, population_frozen: bool,
                                                       population_digest_present: bool,
                                                       selection_method_frozen: bool,
                                                       selector_authority_bound: bool,
                                                       exclusions_recorded: bool,
                                                       selection_precommitted: bool,
                                                       tested_count: int,
                                                       population_count: int) -> dict:
    """A PASS on selected challenges must not silently expand to unexamined claim surface."""
    if tested_count < 0 or population_count < 0 or tested_count > population_count:
        raise ValueError("invalid challenge population counts")
    coverage_ratio = (tested_count / population_count) if population_count else 0.0
    provenance_ok = all([
        population_frozen,
        population_digest_present,
        selection_method_frozen,
        selector_authority_bound,
        exclusions_recorded,
        selection_precommitted,
        population_count > 0,
    ])
    return {
        "challenge_selection_provenance_standing": "SUPPORTABLE" if provenance_ok else "COMPROMISED_OR_NOT_ESTABLISHED",
        "coverage_ratio": coverage_ratio,
        "unexamined_conditions": population_count - tested_count,
        "pass_on_selected_challenges_supports_unexamined_surface": False,
        "binding_decision_made": False,
        "fail_closed": not provenance_ok,
    }


def evaluate_evidence_reconstruction_provenance(*, original_record_recovered: bool,
                                                 reconstruction_performed: bool,
                                                 original_event_time_preserved: bool,
                                                 reconstruction_time_preserved: bool,
                                                 secondary_evidence_identified: bool,
                                                 participant_confirmation_recorded: bool,
                                                 reconstruction_labeled_as_reconstruction: bool) -> dict:
    """A later reconstruction must never be laundered into the original historical record."""
    if original_record_recovered:
        standing = "ORIGINAL_RECORD_AVAILABLE"
    elif all([
        reconstruction_performed,
        original_event_time_preserved,
        reconstruction_time_preserved,
        secondary_evidence_identified,
        participant_confirmation_recorded,
        reconstruction_labeled_as_reconstruction,
    ]):
        standing = "RECONSTRUCTED_WITH_PROVENANCE"
    else:
        standing = "NOT_ESTABLISHED"
    return {
        "evidence_reconstruction_provenance_standing": standing,
        "reconstructed_record_equals_original_record": False,
        "participant_confirmation_equals_historical_continuity_proof": False,
        "binding_decision_made": False,
        "fail_closed": standing == "NOT_ESTABLISHED",
    }


def evaluate_criteria_standing(*, historical_criteria_id: str,
                               current_criteria_id: str,
                               current_criteria_authority_valid: bool,
                               risk_appetite_current: bool,
                               interpretive_frame_current: bool,
                               assumption_set_current: bool,
                               decision_boundary_current: bool,
                               monitor_set_current: bool,
                               requalification_completed_if_changed: bool) -> dict:
    """Green evidence under old criteria does not establish qualification under materially changed criteria."""
    changed = historical_criteria_id != current_criteria_id
    supportable = all([
        current_criteria_authority_valid,
        risk_appetite_current,
        interpretive_frame_current,
        assumption_set_current,
        decision_boundary_current,
        monitor_set_current,
        (not changed) or requalification_completed_if_changed,
    ])
    return {
        "criteria_standing": "SUPPORTABLE" if supportable else "REQUALIFICATION_REQUIRED",
        "criteria_changed": changed,
        "historical_green_state_automatically_inherited": False,
        "binding_decision_made": False,
        "fail_closed": not supportable,
    }


def evaluate_active_mandate_reattestation(*, mandate_record_current: bool,
                                         scope_current: bool,
                                         domain_activity_evidence: bool,
                                         live_challenge_evidence: bool,
                                         succession_evidence: bool,
                                         reattestation_due: bool) -> dict:
    """A current mandate record is not proof that the holder still has live domain standing."""
    demonstrated = domain_activity_evidence or live_challenge_evidence
    if succession_evidence:
        standing = "SUCCESSION_REQUIRED_OR_IN_PROGRESS"
    elif reattestation_due and not demonstrated:
        standing = "LAPSED"
    elif mandate_record_current and scope_current and demonstrated:
        standing = "ACTIVE"
    elif mandate_record_current and scope_current:
        standing = "DUE"
    else:
        standing = "NOT_ESTABLISHED"
    return {
        "active_mandate_reattestation_standing": standing,
        "mandate_record_current_equals_standing_demonstrated": False,
        "binding_decision_made": False,
        "fail_closed": standing != "ACTIVE",
    }


def evaluate_human_oversight_capability_preservation(*, structural_review_opportunity: bool,
                                                      actual_challenge_evidence: bool,
                                                      longitudinal_capability_signal_supportable: bool,
                                                      seeded_probe_passed: bool,
                                                      telemetry_indicator_only: bool,
                                                      independent_adjudication_available: bool) -> dict:
    """Meaningful oversight must remain demonstrable over time; telemetry alone cannot suspend authority."""
    capability = all([
        structural_review_opportunity,
        actual_challenge_evidence,
        longitudinal_capability_signal_supportable,
        seeded_probe_passed,
    ])
    return {
        "human_oversight_capability_preservation_standing": "SUPPORTABLE" if capability else "NOT_ESTABLISHED",
        "approval_event_equals_meaningful_oversight": False,
        "periodic_requalification_equals_longitudinal_capability": False,
        "telemetry_indicator_can_suspend_authority": False,
        "independent_adjudication_available": independent_adjudication_available,
        "telemetry_indicator_only": telemetry_indicator_only,
        "binding_decision_made": False,
        "fail_closed": not capability,
    }


def evaluate_human_oversight_credential_disposition(*, identity_verified: bool,
                                                     competence_current: bool,
                                                     credential_valid: bool,
                                                     scope_current: bool,
                                                     information_standing: bool,
                                                     intervention_standing: bool,
                                                     protection_standing: bool) -> dict:
    """Identity, competence, credential validity, authority scope, and practical oversight standing are distinct."""
    supportable = all([
        identity_verified,
        competence_current,
        credential_valid,
        scope_current,
        information_standing,
        intervention_standing,
        protection_standing,
    ])
    return {
        "human_oversight_standing": "SUPPORTABLE" if supportable else "NOT_ESTABLISHED",
        "credential_valid": credential_valid,
        "credential_valid_equals_current_scope_valid": False,
        "competence_restored_equals_standing_restored": False,
        "binding_decision_made": False,
        "fail_closed": not supportable,
    }


def evaluate_gate_discrimination_health(*, heterogeneous_conditions_present: bool,
                                        dispositions: Iterable[str],
                                        materially_distinct_condition_count: int,
                                        disposition_diversity_expected: bool) -> dict:
    """A syntactically functioning gate may still be ritualized across heterogeneous conditions."""
    if materially_distinct_condition_count < 0:
        raise ValueError("materially_distinct_condition_count must be non-negative")
    observed = list(dispositions)
    unique_dispositions = set(observed)
    suspicious_uniformity = bool(
        heterogeneous_conditions_present
        and disposition_diversity_expected
        and materially_distinct_condition_count > 1
        and len(unique_dispositions) <= 1
    )
    return {
        "gate_discrimination_health": "INVESTIGATION_REQUIRED" if suspicious_uniformity else "NO_POPULATION_ANOMALY_ESTABLISHED",
        "unique_disposition_count": len(unique_dispositions),
        "uniform_outcomes_prove_individual_decision_wrong": False,
        "event_to_gate_coverage_established": False,
        "binding_decision_made": False,
        "fail_closed": suspicious_uniformity,
    }


def evaluate_institutional_state_origin(*, client_claimed_state: str,
                                        authoritative_server_state: str | None,
                                        server_receipt_present: bool,
                                        finalization_authority_event_present: bool,
                                        publication_authority_event_present: bool) -> dict:
    """Browser/client state must not manufacture authoritative institutional state."""
    submitted = authoritative_server_state in {"SUBMITTED", "FINALIZED", "PUBLISHED"} and server_receipt_present
    finalized = authoritative_server_state in {"FINALIZED", "PUBLISHED"} and finalization_authority_event_present
    published = authoritative_server_state == "PUBLISHED" and publication_authority_event_present
    return {
        "institutional_submission_standing": "ESTABLISHED" if submitted else "NOT_ESTABLISHED",
        "institutional_finalization_standing": "ESTABLISHED" if finalized else "NOT_ESTABLISHED",
        "institutional_publication_standing": "ESTABLISHED" if published else "NOT_ESTABLISHED",
        "client_claimed_state": client_claimed_state,
        "client_state_equals_institutional_state": False,
        "ui_status_equals_authoritative_transition": False,
        "binding_decision_made": False,
        "fail_closed": client_claimed_state in {"SUBMITTED", "FINALIZED", "PUBLISHED"} and not submitted,
    }


def evaluate_physical_authorization_context_standing(*, entity_bound: bool,
                                                      action_bound: bool,
                                                      location_current: bool,
                                                      time_current: bool,
                                                      purpose_mission_current: bool,
                                                      authority_source_current: bool,
                                                      scope_contains_action: bool,
                                                      not_expired: bool,
                                                      current_conditions_supportable: bool) -> dict:
    """Prior authorization remains historical evidence but must still fit the exact current consequence context."""
    supportable = all([
        entity_bound,
        action_bound,
        location_current,
        time_current,
        purpose_mission_current,
        authority_source_current,
        scope_contains_action,
        not_expired,
        current_conditions_supportable,
    ])
    return {
        "physical_authorization_context_standing": "SUPPORTABLE" if supportable else "NOT_ESTABLISHED",
        "prior_authorization_historically_erased": False,
        "prior_authorization_equals_present_execution_permission": False,
        "required_behavior": "CONTINUE_ACTION_ADMISSIBILITY_EVALUATION" if supportable else "HOLD_NO_BIND_OR_DENY",
        "binding_decision_made": False,
        "fail_closed": not supportable,
    }


def evaluate_observation_event_existence(*, digital_record_authentic: bool,
                                        recorded_sample_identity_present: bool,
                                        physical_sample_collection_established: bool,
                                        measurement_event_established: bool,
                                        calculation_transformation_valid: bool,
                                        decision_context_supported: bool) -> dict:
    """An authentic record describing an observation is not proof that the physical observation occurred."""
    admissible = all([
        digital_record_authentic,
        recorded_sample_identity_present,
        physical_sample_collection_established,
        measurement_event_established,
        calculation_transformation_valid,
        decision_context_supported,
    ])
    return {
        "document_integrity_standing": "ESTABLISHED" if digital_record_authentic else "NOT_ESTABLISHED",
        "physical_sample_collection_standing": "ESTABLISHED" if physical_sample_collection_established else "NOT_ESTABLISHED",
        "measurement_event_standing": "ESTABLISHED" if measurement_event_established else "NOT_ESTABLISHED",
        "scientific_transformation_standing": "ESTABLISHED" if calculation_transformation_valid else "NOT_ESTABLISHED",
        "observation_claim_admissibility": "SUPPORTABLE" if admissible else "NOT_ESTABLISHED",
        "record_exists_equals_observation_occurred": False,
        "binding_decision_made": False,
        "fail_closed": not admissible,
    }
