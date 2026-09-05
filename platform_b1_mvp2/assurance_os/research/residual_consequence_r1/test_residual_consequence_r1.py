import unittest

from residual_consequence_r1 import (
    evaluate_proposition_bound_witness,
    evaluate_negative_evidence_boundary,
    evaluate_contradiction_and_independence,
    evaluate_residual_consequence_closure,
)


class ResidualConsequenceR1Tests(unittest.TestCase):
    def test_witness_cannot_support_unqualified_proposition(self):
        r = evaluate_proposition_bound_witness(
            claimed_proposition="DELIVERED_QUANTITY",
            qualified_propositions=["PRESENCE_AT_DESTINATION"],
            witness_authenticated=True,
            witness_healthy=True,
            channel_validated=True,
            observation_current=True,
            provenance_complete=True,
        )
        self.assertEqual(r["state"], "NOT_ESTABLISHED")
        self.assertEqual(r["reason"], "WITNESS_NOT_QUALIFIED_FOR_CLAIMED_PROPOSITION")
        self.assertFalse(r["binding_authority_granted"])

    def test_stale_witness_requires_reassessment(self):
        r = evaluate_proposition_bound_witness(
            claimed_proposition="AREA_CLEAR",
            qualified_propositions=["AREA_CLEAR"],
            witness_authenticated=True,
            witness_healthy=True,
            channel_validated=True,
            observation_current=False,
            provenance_complete=True,
        )
        self.assertEqual(r["state"], "REASSESSMENT_REQUIRED")

    def test_not_detected_is_not_absent(self):
        r = evaluate_negative_evidence_boundary(
            observation_result="NOT_DETECTED",
            opportunity_to_observe_established=True,
            detection_capability_established=True,
            detection_limit_appropriate=True,
            observation_window_adequate=True,
        )
        self.assertEqual(r["state"], "UNKNOWN")
        self.assertFalse(r["absence_established"])

    def test_claimed_absence_requires_complete_negative_evidence_basis(self):
        r = evaluate_negative_evidence_boundary(
            observation_result="ABSENT",
            opportunity_to_observe_established=True,
            detection_capability_established=False,
            detection_limit_appropriate=True,
            observation_window_adequate=True,
        )
        self.assertEqual(r["state"], "NOT_ESTABLISHED")
        self.assertFalse(r["absence_established"])

    def test_unavailable_evidence_service_is_not_no_contradiction(self):
        r = evaluate_negative_evidence_boundary(
            observation_result="NOT_OBSERVED",
            opportunity_to_observe_established=True,
            detection_capability_established=True,
            detection_limit_appropriate=True,
            observation_window_adequate=True,
            evidence_service_available=False,
        )
        self.assertEqual(r["state"], "UNKNOWN")
        self.assertFalse(r["contradiction_free_established"])

    def test_conflicting_evidence_is_preserved(self):
        r = evaluate_contradiction_and_independence(
            evidence_records=[
                {"record_id": "W1", "stance": "SUPPORTS", "failure_domain_id": "FD-A"},
                {"record_id": "W2", "stance": "CONTRADICTS", "failure_domain_id": "FD-B"},
            ]
        )
        self.assertEqual(r["state"], "CONTRADICTED")
        self.assertIn("W1", r["supporting_records"])
        self.assertIn("W2", r["contradicting_records"])

    def test_shared_failure_domain_does_not_become_two_independent_votes(self):
        r = evaluate_contradiction_and_independence(
            evidence_records=[
                {"record_id": "A", "stance": "SUPPORTS", "failure_domain_id": "SHARED-NET"},
                {"record_id": "B", "stance": "SUPPORTS", "failure_domain_id": "SHARED-NET"},
            ]
        )
        self.assertEqual(r["state"], "SUPPORTABLE")
        self.assertEqual(r["apparent_support_count"], 2)
        self.assertEqual(r["independent_support_count"], 1)

    def test_unknown_failure_domain_prevents_independence_claim(self):
        r = evaluate_contradiction_and_independence(
            evidence_records=[
                {"record_id": "A", "stance": "SUPPORTS", "failure_domain_id": "FD-1"},
                {"record_id": "B", "stance": "SUPPORTS"},
            ]
        )
        self.assertEqual(r["state"], "DEPENDENCY_UNCERTAIN")

    def test_contradiction_service_failure_is_unknown_not_clean(self):
        r = evaluate_contradiction_and_independence(
            evidence_records=[{"record_id": "A", "stance": "SUPPORTS", "failure_domain_id": "FD-1"}],
            contradiction_service_available=False,
        )
        self.assertEqual(r["state"], "UNKNOWN")
        self.assertFalse(r["contradiction_free_established"])

    def test_execution_success_without_physical_outcome_does_not_close_consequence(self):
        r = evaluate_residual_consequence_closure(
            prior_permission_current=True,
            execution_receipt_succeeded=True,
            physical_outcome_observed=False,
            intended_outcome_established=False,
            residual_effects_present=False,
            blocking_obligations_open=False,
            current_world_correspondence_established=True,
            criteria_current=True,
            evidence_current=True,
            authority_current=True,
            independent_reverification_required=False,
            independent_reverification_established=False,
            history_preserved=True,
        )
        self.assertEqual(r["state"], "RECLOSURE_NOT_ESTABLISHED")
        self.assertIn("PHYSICAL_OUTCOME_NOT_OBSERVED", r["reasons"])
        self.assertIn("INTENDED_OUTCOME_NOT_ESTABLISHED", r["reasons"])

    def test_yesterdays_permission_does_not_support_current_reclosure(self):
        r = evaluate_residual_consequence_closure(
            prior_permission_current=False,
            execution_receipt_succeeded=True,
            physical_outcome_observed=True,
            intended_outcome_established=True,
            residual_effects_present=False,
            blocking_obligations_open=False,
            current_world_correspondence_established=True,
            criteria_current=True,
            evidence_current=True,
            authority_current=True,
            independent_reverification_required=False,
            independent_reverification_established=False,
            history_preserved=True,
        )
        self.assertEqual(r["state"], "RECLOSURE_NOT_ESTABLISHED")
        self.assertIn("CURRENT_PERMISSION_OR_STANDING_NOT_ESTABLISHED", r["reasons"])

    def test_residual_effect_blocks_reclosure_even_after_successful_execution(self):
        r = evaluate_residual_consequence_closure(
            prior_permission_current=True,
            execution_receipt_succeeded=True,
            physical_outcome_observed=True,
            intended_outcome_established=True,
            residual_effects_present=True,
            blocking_obligations_open=False,
            current_world_correspondence_established=True,
            criteria_current=True,
            evidence_current=True,
            authority_current=True,
            independent_reverification_required=False,
            independent_reverification_established=False,
            history_preserved=True,
        )
        self.assertEqual(r["state"], "RECLOSURE_NOT_ESTABLISHED")
        self.assertIn("RESIDUAL_CONSEQUENCE_REMAINS", r["reasons"])

    def test_independent_reverification_requirement_fails_closed(self):
        r = evaluate_residual_consequence_closure(
            prior_permission_current=True,
            execution_receipt_succeeded=True,
            physical_outcome_observed=True,
            intended_outcome_established=True,
            residual_effects_present=False,
            blocking_obligations_open=False,
            current_world_correspondence_established=True,
            criteria_current=True,
            evidence_current=True,
            authority_current=True,
            independent_reverification_required=True,
            independent_reverification_established=False,
            history_preserved=True,
        )
        self.assertEqual(r["state"], "RECLOSURE_NOT_ESTABLISHED")
        self.assertIn("INDEPENDENT_REVERIFICATION_NOT_ESTABLISHED", r["reasons"])

    def test_full_reclosure_still_requires_separate_authority_and_action_admissibility(self):
        r = evaluate_residual_consequence_closure(
            prior_permission_current=True,
            execution_receipt_succeeded=True,
            physical_outcome_observed=True,
            intended_outcome_established=True,
            residual_effects_present=False,
            blocking_obligations_open=False,
            current_world_correspondence_established=True,
            criteria_current=True,
            evidence_current=True,
            authority_current=True,
            independent_reverification_required=True,
            independent_reverification_established=True,
            history_preserved=True,
        )
        self.assertEqual(r["state"], "RECLOSURE_SUPPORTABLE")
        self.assertEqual(r["no_bind_state"], "SEPARATE_AUTHORITY_AND_ACTION_ADMISSIBILITY_REQUIRED")
        self.assertFalse(r["binding_authority_granted"])
        self.assertFalse(r["historical_facts_rewritten"])
        self.assertFalse(r["irlt_mag_state_changed"])


if __name__ == "__main__":
    unittest.main()
