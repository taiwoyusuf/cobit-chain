"""Aug. 31 watch-derived assurance refinements.

Additive bounded experiments only. These evaluators do not create binding
regulatory authority and do not replace existing COBIT-Chain shared-core or
domain-specific controls.
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable, Mapping


def evaluate_refusal_survivability(*, refusal_authority: bool,
                                   refusal_channel_available: bool,
                                   refusal_before_bind: bool,
                                   retaliation_or_penalty_exposure: bool,
                                   hierarchical_pressure_uncontrolled: bool,
                                   commercial_pressure_uncontrolled: bool,
                                   independent_escalation_available: bool,
                                   refusal_preserved: bool,
                                   alternate_route_can_bypass_refusal: bool) -> dict:
    """A nominal veto is not effective governance if refusal cannot survive to consequence."""
    coercion_exposure = any([
        retaliation_or_penalty_exposure,
        hierarchical_pressure_uncontrolled,
        commercial_pressure_uncontrolled,
    ])
    supportable = all([
        refusal_authority,
        refusal_channel_available,
        refusal_before_bind,
        independent_escalation_available,
        refusal_preserved,
        not coercion_exposure,
        not alternate_route_can_bypass_refusal,
    ])
    return {
        "refusal_survivability_standing": "SUPPORTABLE" if supportable else "NOT_ESTABLISHED",
        "coercion_exposure": coercion_exposure,
        "alternate_route_bypass": alternate_route_can_bypass_refusal,
        "required_behavior": "ALLOW_GOVERNED_REVIEW" if supportable else "HOLD_OR_ESCALATE",
        "binding_decision_made": False,
        "fail_closed": not supportable,
    }


def evaluate_repairability_routing(*, reversible: bool,
                                   reversal_completeness: bool,
                                   time_to_reverse_seconds: float | None,
                                   repair_window_seconds: float | None,
                                   external_effects_contained: bool,
                                   human_effects_contained: bool,
                                   cross_system_effects_contained: bool,
                                   irreversible_residue: bool,
                                   repair_authority_current: bool,
                                   repair_capacity_available: bool) -> dict:
    """Execution speed must reflect consequence repairability, not raw capability."""
    if time_to_reverse_seconds is not None and time_to_reverse_seconds < 0:
        raise ValueError("time_to_reverse_seconds must be non-negative")
    if repair_window_seconds is not None and repair_window_seconds < 0:
        raise ValueError("repair_window_seconds must be non-negative")
    within_window = bool(
        time_to_reverse_seconds is not None
        and repair_window_seconds is not None
        and time_to_reverse_seconds <= repair_window_seconds
    )
    highly_repairable = all([
        reversible,
        reversal_completeness,
        within_window,
        external_effects_contained,
        human_effects_contained,
        cross_system_effects_contained,
        not irreversible_residue,
        repair_authority_current,
        repair_capacity_available,
    ])
    conditionally_repairable = all([
        reversible,
        repair_authority_current,
        repair_capacity_available,
        not irreversible_residue,
    ])
    if highly_repairable:
        mode = "MACHINE_SPEED"
    elif conditionally_repairable:
        mode = "HUMAN_CONFIRMATION"
    else:
        mode = "HOLD"
    return {
        "repairability_routing_standing": "SUPPORTABLE" if mode != "HOLD" else "NOT_ESTABLISHED",
        "permitted_execution_mode": mode,
        "within_repair_window": within_window,
        "binding_decision_made": False,
        "fail_closed": mode == "HOLD",
    }


def evaluate_intent_constitution_artifact(*, artifact: Mapping[str, object],
                                          required_fields: Iterable[str],
                                          version_bound: bool,
                                          owner_authorized: bool,
                                          review_trigger_defined: bool) -> dict:
    """An instruction is not governed intent unless the required intent boundary is explicit."""
    missing = sorted(field for field in required_fields if not artifact.get(field))
    supportable = not missing and version_bound and owner_authorized and review_trigger_defined
    return {
        "intent_constitution_standing": "SUPPORTABLE" if supportable else "NOT_ESTABLISHED",
        "missing_intent_fields": missing,
        "version_bound": version_bound,
        "owner_authorized": owner_authorized,
        "review_trigger_defined": review_trigger_defined,
        "binding_decision_made": False,
        "fail_closed": not supportable,
    }


def evaluate_consequence_incapacity_challenge(*, required_routes: Iterable[str],
                                              route_consequence_possible: Mapping[str, bool]) -> dict:
    """A blocked log is not proof of incapacity; all required consequential routes must be tested."""
    required = set(required_routes)
    attempted = set(route_consequence_possible)
    missing = sorted(required - attempted)
    bypasses = sorted(route for route in required if route_consequence_possible.get(route) is True)
    if bypasses:
        standing = "FAILED_CONSEQUENCE_REACHABLE"
    elif missing:
        standing = "UNRESOLVED_INCOMPLETE_ROUTE_COVERAGE"
    else:
        standing = "ESTABLISHED_WITHIN_FROZEN_ROUTE_SET"
    return {
        "consequence_incapacity_standing": standing,
        "missing_required_routes": missing,
        "routes_where_consequence_remains_possible": bypasses,
        "proof_surface_is_proof": False,
        "binding_decision_made": False,
        "fail_closed": standing != "ESTABLISHED_WITHIN_FROZEN_ROUTE_SET",
    }


def evaluate_digital_proxy_non_authority(*, proxy_present: bool,
                                         inferred_preferences_present: bool,
                                         behavioral_prediction_present: bool,
                                         explicit_current_grant: bool,
                                         grant_scope_contains_action: bool,
                                         human_ratification_required: bool,
                                         human_ratified: bool) -> dict:
    """A person-model, inferred preference, or prediction must not manufacture authority."""
    ratification_ok = (not human_ratification_required) or human_ratified
    authority_supportable = explicit_current_grant and grant_scope_contains_action and ratification_ok
    return {
        "digital_proxy_non_authority_standing": "SUPPORTABLE" if authority_supportable else "NOT_ESTABLISHED",
        "proxy_present": proxy_present,
        "inference_present": inferred_preferences_present or behavioral_prediction_present,
        "proxy_created_authority": False,
        "authority_basis": "EXPLICIT_CURRENT_GRANT" if authority_supportable else "NOT_ESTABLISHED",
        "required_behavior": "EVALUATE_ACTION" if authority_supportable else "HOLD_OR_SEEK_GRANT",
        "binding_decision_made": False,
        "fail_closed": not authority_supportable,
    }


def evaluate_evidence_plane_survivability(*, required_evidence_service_available: bool,
                                          cached_evidence_present: bool,
                                          cached_evidence_use_authorized: bool,
                                          commit_attempted: bool,
                                          local_hold_receipt_preserved: bool,
                                          service_restored_later: bool) -> dict:
    """Evidence-plane outage must not silently convert absence of proof into permission."""
    contemporaneous_support = required_evidence_service_available or (
        cached_evidence_present and cached_evidence_use_authorized
    )
    if contemporaneous_support:
        standing = "SUPPORTABLE_WITHIN_EVIDENCE_POLICY"
        required_behavior = "CONTINUE_EVALUATION"
    else:
        standing = "NOT_ESTABLISHED"
        required_behavior = "HOLD"
    escaped_commit = commit_attempted and not contemporaneous_support
    return {
        "evidence_plane_survivability_standing": standing,
        "contemporaneous_evidence_support": contemporaneous_support,
        "commit_during_unresolved_outage": escaped_commit,
        "later_restoration_is_contemporaneous_proof": False,
        "local_hold_receipt_preserved": local_hold_receipt_preserved,
        "service_restored_later": service_restored_later,
        "required_behavior": required_behavior,
        "binding_decision_made": False,
        "fail_closed": not contemporaneous_support,
    }


def evaluate_lifecycle_exit_retirement(*, retirement_authorized: bool,
                                       active_lifecycle_authority_closed: bool,
                                       primary_route_disabled: bool,
                                       residual_execution_routes: Iterable[str],
                                       unresolved_obligations: Iterable[str],
                                       historical_record_preserved: bool,
                                       data_disposition_recorded: bool) -> dict:
    """Retirement requires route closure while history and unresolved duties remain preserved."""
    residual = sorted(set(residual_execution_routes))
    obligations = sorted(set(unresolved_obligations))
    complete = all([
        retirement_authorized,
        active_lifecycle_authority_closed,
        primary_route_disabled,
        not residual,
        not obligations,
        historical_record_preserved,
        data_disposition_recorded,
    ])
    return {
        "retirement_standing": "COMPLETE" if complete else "INCOMPLETE",
        "residual_execution_routes": residual,
        "unresolved_obligations": obligations,
        "historical_record_preserved": historical_record_preserved,
        "residual_route_action_admissibility": "DENIED" if residual else "NO_RESIDUAL_ROUTE_IDENTIFIED",
        "binding_decision_made": False,
        "fail_closed": not complete,
    }


def evaluate_persistent_memory_admissibility(*, memory_authentic: bool,
                                             provenance_bound: bool,
                                             authority_scope_current: bool,
                                             retention_state_valid: bool,
                                             mutation_lineage_preserved: bool,
                                             retrieval_custody_bound: bool,
                                             current_context_applicable: bool) -> dict:
    """Memory may remain authentic while current reliance on it is no longer admissible."""
    supportable = all([
        memory_authentic,
        provenance_bound,
        authority_scope_current,
        retention_state_valid,
        mutation_lineage_preserved,
        retrieval_custody_bound,
        current_context_applicable,
    ])
    return {
        "memory_integrity_standing": "SUPPORTABLE" if memory_authentic else "NOT_ESTABLISHED",
        "persistent_memory_admissibility": "SUPPORTABLE" if supportable else "NOT_ESTABLISHED",
        "required_behavior": "ALLOW_RELIANCE_EVALUATION" if supportable else "HOLD_PENDING_REASSESSMENT",
        "binding_decision_made": False,
        "fail_closed": not supportable,
    }


def evaluate_definition_evidence_correspondence(*, evidence_integrity_valid: bool,
                                                historical_definition_id: str,
                                                current_definition_id: str,
                                                historical_correspondence_established: bool,
                                                current_correspondence_established: bool) -> dict:
    """A definition change can break current correspondence without making historical evidence false."""
    definition_changed = historical_definition_id != current_definition_id
    current_supportable = evidence_integrity_valid and current_correspondence_established
    return {
        "evidence_integrity_standing": "SUPPORTABLE" if evidence_integrity_valid else "NOT_ESTABLISHED",
        "historical_correspondence_standing": "ESTABLISHED" if historical_correspondence_established else "NOT_ESTABLISHED",
        "definition_changed": definition_changed,
        "current_definition_correspondence": "ESTABLISHED" if current_correspondence_established else "NOT_ESTABLISHED",
        "current_reliance_standing": "SUPPORTABLE" if current_supportable else "HOLD",
        "historical_evidence_retroactively_invalidated": False,
        "binding_decision_made": False,
        "fail_closed": not current_supportable,
    }


def evaluate_outcome_next_cycle_inheritance(*, prior_evidence_integrity_valid: bool,
                                            prior_world_state_id: str,
                                            current_world_state_id: str,
                                            current_world_correspondence_established: bool,
                                            current_authority_reestablished: bool) -> dict:
    """A completed outcome can create a new reality that must be requalified before the next cycle."""
    world_changed = prior_world_state_id != current_world_state_id
    inheritable = all([
        prior_evidence_integrity_valid,
        (not world_changed) or current_world_correspondence_established,
        current_authority_reestablished,
    ])
    return {
        "prior_evidence_integrity": "SUPPORTABLE" if prior_evidence_integrity_valid else "NOT_ESTABLISHED",
        "world_state_changed": world_changed,
        "current_world_correspondence": "ESTABLISHED" if current_world_correspondence_established else "NOT_ESTABLISHED",
        "next_cycle_inheritance_standing": "SUPPORTABLE" if inheritable else "NOT_ESTABLISHED",
        "prior_authorization_automatically_inherited": False,
        "binding_decision_made": False,
        "fail_closed": not inheritable,
    }


def evaluate_measurement_semantic_standing(*, value_present: bool,
                                           quantity_identity_bound: bool,
                                           unit_identity_bound: bool,
                                           scale_bound: bool,
                                           instrument_mode_bound: bool,
                                           location_or_object_bound: bool,
                                           time_bound: bool,
                                           interpretation_basis_bound: bool) -> dict:
    """Units, scale, measurand, mode, place, time, and interpretation are part of evidence."""
    supportable = all([
        value_present,
        quantity_identity_bound,
        unit_identity_bound,
        scale_bound,
        instrument_mode_bound,
        location_or_object_bound,
        time_bound,
        interpretation_basis_bound,
    ])
    return {
        "measurement_semantic_standing": "SUPPORTABLE" if supportable else "NOT_ESTABLISHED",
        "numeric_value_alone_is_decision_grade": False,
        "binding_decision_made": False,
        "fail_closed": not supportable,
    }


def evaluate_measurement_context_representativeness(*, calibration_current: bool,
                                                    sampling_path_validated: bool,
                                                    installation_geometry_bound: bool,
                                                    critical_interaction_observable: bool,
                                                    evidence_continuity_preserved: bool,
                                                    acquisition_intrusiveness_assessed: bool) -> dict:
    """Calibration alone does not establish representative measurement in the installed context."""
    measurement_source = calibration_current
    representative = all([
        calibration_current,
        sampling_path_validated,
        installation_geometry_bound,
        critical_interaction_observable,
        evidence_continuity_preserved,
        acquisition_intrusiveness_assessed,
    ])
    return {
        "measurement_source_standing": "SUPPORTABLE" if measurement_source else "NOT_ESTABLISHED",
        "measurement_context_representativeness": "SUPPORTABLE" if representative else "NOT_ESTABLISHED",
        "calibration_equals_representativeness": False,
        "binding_decision_made": False,
        "fail_closed": not representative,
    }
