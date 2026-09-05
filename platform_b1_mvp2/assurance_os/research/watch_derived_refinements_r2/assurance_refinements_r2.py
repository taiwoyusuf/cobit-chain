"""Watch-derived assurance refinements R2.

Additive experimental controls derived from September 2026 assurance-watch
reconciliation. These functions do not create binding regulatory authority,
release product, authorize radiation work, or replace domain-specific rules.
They are intended to compose with existing COBIT-Chain/VSA standing,
authority, No-Bind, recovery, reconstruction, and RAMAT witness logic.
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable, Mapping, Sequence


def evaluate_applicability_exclusion_standing(*,
                                               exclusion_fact_present: bool,
                                               authoritative_source_present: bool,
                                               source_current: bool,
                                               object_context_bound: bool,
                                               exclusion_rule_present: bool,
                                               contradictory_applicability_resolved: bool) -> dict:
    """NOT_APPLICABLE must be earned by evidence, not inferred from silence."""
    ok = all([
        exclusion_fact_present,
        authoritative_source_present,
        source_current,
        object_context_bound,
        exclusion_rule_present,
        contradictory_applicability_resolved,
    ])
    return {
        "applicability_exclusion_standing": "ESTABLISHED" if ok else "NOT_ESTABLISHED",
        "dependency_state_permitted": "NOT_APPLICABLE" if ok else "APPLICABILITY_UNRESOLVED",
        "required_behavior": "CONTINUE_EVALUATION" if ok else "HOLD",
        "not_observed_equals_not_applicable": False,
        "binding_decision_made": False,
        "fail_closed": not ok,
    }


def evaluate_condition_coverage_standing(*,
                                         declared_conditions: Iterable[str],
                                         observed_material_conditions: Iterable[str],
                                         discovery_methods: Sequence[str],
                                         unobserved_domains: Sequence[str] = (),
                                         last_coverage_challenged_at: datetime | None = None) -> dict:
    """Passing declared conditions does not establish completeness of reality."""
    declared = set(declared_conditions)
    observed = set(observed_material_conditions)
    missing = sorted(observed - declared)
    discovery_present = bool(discovery_methods)
    bounded = discovery_present and not missing and not unobserved_domains
    if missing:
        standing = "MATERIAL_DEPENDENCY_GAP_FOUND"
    elif bounded:
        standing = "BOUNDED_COVERAGE_ESTABLISHED"
    else:
        standing = "COVERAGE_UNKNOWN"
    return {
        "condition_coverage_standing": standing,
        "declared_condition_count": len(declared),
        "observed_material_condition_count": len(observed),
        "undeclared_material_conditions": missing,
        "discovery_methods": list(discovery_methods),
        "unobserved_domains": list(unobserved_domains),
        "last_coverage_challenged_at": last_coverage_challenged_at.isoformat() if last_coverage_challenged_at else None,
        "strongest_positive_claim_permitted": bounded,
        "absolute_completeness_claimed": False,
        "binding_decision_made": False,
        "fail_closed": standing != "BOUNDED_COVERAGE_ESTABLISHED",
    }


def evaluate_observation_cadence_standing(*,
                                          observation_interval_seconds: float,
                                          material_change_horizon_seconds: float,
                                          decision_update_latency_seconds: float,
                                          maximum_unobserved_interval_seconds: float | None = None) -> dict:
    """Two fresh endpoints do not establish continuity between them."""
    values = [observation_interval_seconds, material_change_horizon_seconds, decision_update_latency_seconds]
    if any(v < 0 for v in values):
        raise ValueError("timing values must be non-negative")
    if material_change_horizon_seconds == 0:
        adequate = observation_interval_seconds == 0 and decision_update_latency_seconds == 0
    else:
        effective_gap = observation_interval_seconds + decision_update_latency_seconds
        if maximum_unobserved_interval_seconds is not None:
            if maximum_unobserved_interval_seconds < 0:
                raise ValueError("maximum_unobserved_interval_seconds must be non-negative")
            effective_gap = max(effective_gap, maximum_unobserved_interval_seconds)
        adequate = effective_gap <= material_change_horizon_seconds
    if adequate:
        standing = "ADEQUATE"
    elif observation_interval_seconds <= material_change_horizon_seconds:
        standing = "DEGRADED"
    else:
        standing = "NOT_ESTABLISHED"
    return {
        "observation_cadence_standing": standing,
        "continuity_established_from_endpoints_alone": False,
        "observation_interval_seconds": observation_interval_seconds,
        "material_change_horizon_seconds": material_change_horizon_seconds,
        "decision_update_latency_seconds": decision_update_latency_seconds,
        "aliasing_risk": not adequate,
        "required_behavior": "CONTINUE_WITHIN_BOUND" if adequate else "HOLD_OR_INCREASE_OBSERVABILITY",
        "binding_decision_made": False,
        "fail_closed": not adequate,
    }


def evaluate_authority_basis_standing(*,
                                      cryptographic_chain_intact: bool,
                                      terminal_basis_present: bool,
                                      basis_current: bool,
                                      scope_supports_action: bool,
                                      identity_binding_established: bool,
                                      delegation_depth_permitted: bool) -> dict:
    """Authentic grants do not prove the terminal issuer was entitled to grant."""
    basis_ok = all([
        terminal_basis_present,
        basis_current,
        scope_supports_action,
        identity_binding_established,
        delegation_depth_permitted,
    ])
    supportable = cryptographic_chain_intact and basis_ok
    return {
        "cryptographic_authority_chain": "INTACT" if cryptographic_chain_intact else "NOT_ESTABLISHED",
        "authority_basis_standing": "ESTABLISHED" if basis_ok else "NOT_ESTABLISHED",
        "authority_exercise_supportable": supportable,
        "required_behavior": "ALLOW_AUTHORITY_EVALUATION" if supportable else "HOLD",
        "authentic_grant_equals_legitimate_grant": False,
        "binding_decision_made": False,
        "fail_closed": not supportable,
    }


def evaluate_material_change_reachability(*,
                                          change_at: datetime,
                                          gate_received_at: datetime | None,
                                          reassessed_at: datetime | None,
                                          commit_at: datetime,
                                          propagation_path_known: bool,
                                          event_order_valid: bool = True) -> dict:
    """A material change must reach the governing route before consequence commits."""
    reached = bool(gate_received_at and gate_received_at >= change_at and gate_received_at <= commit_at)
    reassessed = bool(reassessed_at and gate_received_at and reassessed_at >= gate_received_at and reassessed_at <= commit_at)
    timely = propagation_path_known and event_order_valid and reached and reassessed
    latency = (gate_received_at - change_at).total_seconds() if gate_received_at else None
    return {
        "material_change_reachability_standing": "ESTABLISHED" if timely else "NOT_ESTABLISHED",
        "change_reached_gate_before_commit": reached,
        "reassessment_completed_before_commit": reassessed,
        "propagation_latency_seconds": latency,
        "current_source_state_equals_current_gate_state": False,
        "required_behavior": "CONTINUE_EVALUATION" if timely else "HOLD_CURRENT_STATE_UNESTABLISHED",
        "binding_decision_made": False,
        "fail_closed": not timely,
    }


def evaluate_partial_evidence_bound_soundness(*,
                                              required_segments: Iterable[str],
                                              available_segments: Iterable[str],
                                              established_claims_by_segment: Mapping[str, Iterable[str]],
                                              requested_claims: Iterable[str]) -> dict:
    """A valid fragment may support only claims established inside its evidence boundary."""
    required = set(required_segments)
    available = set(available_segments)
    requested = set(requested_claims)
    claims = set()
    for segment in available:
        claims.update(established_claims_by_segment.get(segment, ()))
    unsupported = sorted(requested - claims)
    unavailable_required = sorted(required - available)
    if unsupported:
        standing = "BOUNDED_ONLY"
    elif unavailable_required:
        standing = "ESTABLISHED_WITHIN_AVAILABLE_SEGMENTS"
    else:
        standing = "ESTABLISHED"
    return {
        "partial_evidence_bound_soundness": standing,
        "available_segments": sorted(available),
        "unavailable_required_segments": unavailable_required,
        "claims_established_within_boundary": sorted(claims),
        "requested_claims_not_established": unsupported,
        "earlier_fragment_retroactively_upgraded": False,
        "binding_decision_made": False,
        "fail_closed": bool(unsupported),
    }


def evaluate_evidence_failure_independence(*,
                                           channel_dependencies: Mapping[str, Iterable[str]],
                                           minimum_independent_channels: int = 2) -> dict:
    """Different witnesses are not independent when they share failure-critical dependencies."""
    if minimum_independent_channels < 1:
        raise ValueError("minimum_independent_channels must be positive")
    channels = sorted(channel_dependencies)
    conflicts = []
    for i, left in enumerate(channels):
        left_deps = set(channel_dependencies[left])
        for right in channels[i + 1:]:
            shared = sorted(left_deps & set(channel_dependencies[right]))
            if shared:
                conflicts.append({"channels": [left, right], "shared_dependencies": shared})
    independent_channels = len(channels) if not conflicts else 0
    supportable = independent_channels >= minimum_independent_channels
    return {
        "evidence_failure_independence_standing": "ESTABLISHED" if supportable else "NOT_ESTABLISHED",
        "channels_evaluated": channels,
        "shared_failure_dependencies": conflicts,
        "different_witness_equals_independent_failure_path": False,
        "required_behavior": "ALLOW_INDEPENDENCE_CLAIM" if supportable else "LIMIT_INDEPENDENCE_CLAIM",
        "binding_decision_made": False,
        "fail_closed": not supportable,
    }


def evaluate_aggregate_consequence_assurance(*,
                                             locally_admissible_actions: int,
                                             total_actions: int,
                                             aggregate_limit: float,
                                             aggregate_observed: float,
                                             trend_direction: str = "STABLE") -> dict:
    """Individually admissible actions can collectively create an inadmissible outcome."""
    if total_actions < 0 or locally_admissible_actions < 0:
        raise ValueError("action counts must be non-negative")
    if locally_admissible_actions > total_actions:
        raise ValueError("locally_admissible_actions cannot exceed total_actions")
    local_all_ok = total_actions > 0 and locally_admissible_actions == total_actions
    aggregate_ok = aggregate_observed <= aggregate_limit
    supportable = local_all_ok and aggregate_ok
    return {
        "aggregate_consequence_standing": "SUPPORTABLE" if supportable else "REASSESSMENT_REQUIRED",
        "all_actions_locally_admissible": local_all_ok,
        "aggregate_limit": aggregate_limit,
        "aggregate_observed": aggregate_observed,
        "trend_direction": trend_direction,
        "local_admissibility_equals_aggregate_acceptability": False,
        "historical_actions_retroactively_invalidated": False,
        "required_behavior": "CONTINUE" if supportable else "HOLD_OR_SYSTEMIC_REVIEW",
        "binding_decision_made": False,
        "fail_closed": not supportable,
    }
