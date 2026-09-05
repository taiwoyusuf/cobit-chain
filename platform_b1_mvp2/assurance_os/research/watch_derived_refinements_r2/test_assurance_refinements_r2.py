import unittest
from datetime import datetime, timedelta, timezone

from assurance_refinements_r2 import (
    evaluate_aggregate_consequence_assurance,
    evaluate_applicability_exclusion_standing,
    evaluate_authority_basis_standing,
    evaluate_condition_coverage_standing,
    evaluate_evidence_failure_independence,
    evaluate_material_change_reachability,
    evaluate_observation_cadence_standing,
    evaluate_partial_evidence_bound_soundness,
)


class WatchDerivedAssuranceRefinementsR2Tests(unittest.TestCase):
    def test_not_applicable_requires_evidence(self):
        r = evaluate_applicability_exclusion_standing(
            exclusion_fact_present=False,
            authoritative_source_present=True,
            source_current=True,
            object_context_bound=True,
            exclusion_rule_present=True,
            contradictory_applicability_resolved=True,
        )
        self.assertEqual(r["dependency_state_permitted"], "APPLICABILITY_UNRESOLVED")
        self.assertEqual(r["required_behavior"], "HOLD")

    def test_not_applicable_can_be_earned(self):
        r = evaluate_applicability_exclusion_standing(
            exclusion_fact_present=True,
            authoritative_source_present=True,
            source_current=True,
            object_context_bound=True,
            exclusion_rule_present=True,
            contradictory_applicability_resolved=True,
        )
        self.assertEqual(r["dependency_state_permitted"], "NOT_APPLICABLE")

    def test_hidden_material_condition_blocks_strongest_positive_claim(self):
        r = evaluate_condition_coverage_standing(
            declared_conditions=["C1", "C2", "C3", "C4", "C5"],
            observed_material_conditions=["C1", "C2", "C3", "C4", "C5", "C6"],
            discovery_methods=["design_review", "physical_walkdown"],
        )
        self.assertEqual(r["condition_coverage_standing"], "MATERIAL_DEPENDENCY_GAP_FOUND")
        self.assertEqual(r["undeclared_material_conditions"], ["C6"])
        self.assertFalse(r["strongest_positive_claim_permitted"])

    def test_bounded_condition_coverage_never_claims_absolute_completeness(self):
        r = evaluate_condition_coverage_standing(
            declared_conditions=["C1", "C2"],
            observed_material_conditions=["C1", "C2"],
            discovery_methods=["hazard_analysis", "physical_walkdown"],
            unobserved_domains=[],
        )
        self.assertEqual(r["condition_coverage_standing"], "BOUNDED_COVERAGE_ESTABLISHED")
        self.assertFalse(r["absolute_completeness_claimed"])

    def test_two_green_endpoints_do_not_establish_continuity_when_sampling_is_too_slow(self):
        r = evaluate_observation_cadence_standing(
            observation_interval_seconds=60,
            material_change_horizon_seconds=20,
            decision_update_latency_seconds=5,
        )
        self.assertEqual(r["observation_cadence_standing"], "NOT_ESTABLISHED")
        self.assertTrue(r["aliasing_risk"])
        self.assertFalse(r["continuity_established_from_endpoints_alone"])

    def test_fast_observation_and_update_can_be_adequate_within_declared_bound(self):
        r = evaluate_observation_cadence_standing(
            observation_interval_seconds=5,
            material_change_horizon_seconds=30,
            decision_update_latency_seconds=2,
        )
        self.assertEqual(r["observation_cadence_standing"], "ADEQUATE")

    def test_crypto_chain_does_not_replace_terminal_authority_basis(self):
        r = evaluate_authority_basis_standing(
            cryptographic_chain_intact=True,
            terminal_basis_present=False,
            basis_current=False,
            scope_supports_action=True,
            identity_binding_established=True,
            delegation_depth_permitted=True,
        )
        self.assertEqual(r["cryptographic_authority_chain"], "INTACT")
        self.assertEqual(r["authority_basis_standing"], "NOT_ESTABLISHED")
        self.assertFalse(r["authority_exercise_supportable"])

    def test_legitimate_terminal_basis_supports_bounded_authority_evaluation(self):
        r = evaluate_authority_basis_standing(
            cryptographic_chain_intact=True,
            terminal_basis_present=True,
            basis_current=True,
            scope_supports_action=True,
            identity_binding_established=True,
            delegation_depth_permitted=True,
        )
        self.assertTrue(r["authority_exercise_supportable"])

    def test_change_must_reach_gate_and_trigger_reassessment_before_commit(self):
        t0 = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)
        r = evaluate_material_change_reachability(
            change_at=t0,
            gate_received_at=t0 + timedelta(seconds=2),
            reassessed_at=t0 + timedelta(seconds=3),
            commit_at=t0 + timedelta(seconds=5),
            propagation_path_known=True,
        )
        self.assertEqual(r["material_change_reachability_standing"], "ESTABLISHED")
        self.assertTrue(r["change_reached_gate_before_commit"])

    def test_stored_change_that_arrives_after_commit_is_not_governance_reachability(self):
        t0 = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)
        r = evaluate_material_change_reachability(
            change_at=t0,
            gate_received_at=t0 + timedelta(seconds=8),
            reassessed_at=t0 + timedelta(seconds=9),
            commit_at=t0 + timedelta(seconds=5),
            propagation_path_known=True,
        )
        self.assertEqual(r["material_change_reachability_standing"], "NOT_ESTABLISHED")
        self.assertEqual(r["required_behavior"], "HOLD_CURRENT_STATE_UNESTABLISHED")

    def test_partial_evidence_cannot_support_claim_from_unavailable_segment(self):
        r = evaluate_partial_evidence_bound_soundness(
            required_segments=["A", "B", "C"],
            available_segments=["A"],
            established_claims_by_segment={"A": ["claim-a"], "B": ["claim-b"], "C": ["claim-c"]},
            requested_claims=["claim-a", "claim-c"],
        )
        self.assertEqual(r["partial_evidence_bound_soundness"], "BOUNDED_ONLY")
        self.assertEqual(r["requested_claims_not_established"], ["claim-c"])
        self.assertFalse(r["earlier_fragment_retroactively_upgraded"])

    def test_complete_evidence_segments_can_support_requested_claims(self):
        r = evaluate_partial_evidence_bound_soundness(
            required_segments=["A", "B"],
            available_segments=["A", "B"],
            established_claims_by_segment={"A": ["claim-a"], "B": ["claim-b"]},
            requested_claims=["claim-a", "claim-b"],
        )
        self.assertEqual(r["partial_evidence_bound_soundness"], "ESTABLISHED")

    def test_two_witnesses_with_shared_clock_are_not_independent_failure_paths(self):
        r = evaluate_evidence_failure_independence(
            channel_dependencies={
                "camera": ["power-a", "clock-z"],
                "particle-counter": ["power-b", "clock-z"],
            }
        )
        self.assertEqual(r["evidence_failure_independence_standing"], "NOT_ESTABLISHED")
        self.assertTrue(r["shared_failure_dependencies"])

    def test_disjoint_declared_failure_paths_can_support_bounded_independence(self):
        r = evaluate_evidence_failure_independence(
            channel_dependencies={
                "camera": ["power-a", "clock-a", "network-a"],
                "particle-counter": ["power-b", "clock-b", "network-b"],
            }
        )
        self.assertEqual(r["evidence_failure_independence_standing"], "ESTABLISHED")

    def test_all_local_actions_can_pass_while_aggregate_consequence_fails(self):
        r = evaluate_aggregate_consequence_assurance(
            locally_admissible_actions=1000,
            total_actions=1000,
            aggregate_limit=100.0,
            aggregate_observed=125.0,
            trend_direction="DETERIORATING",
        )
        self.assertTrue(r["all_actions_locally_admissible"])
        self.assertEqual(r["aggregate_consequence_standing"], "REASSESSMENT_REQUIRED")
        self.assertFalse(r["historical_actions_retroactively_invalidated"])

    def test_aggregate_within_limit_is_supportable_when_all_local_actions_are_admissible(self):
        r = evaluate_aggregate_consequence_assurance(
            locally_admissible_actions=100,
            total_actions=100,
            aggregate_limit=100.0,
            aggregate_observed=80.0,
        )
        self.assertEqual(r["aggregate_consequence_standing"], "SUPPORTABLE")


if __name__ == "__main__":
    unittest.main()
