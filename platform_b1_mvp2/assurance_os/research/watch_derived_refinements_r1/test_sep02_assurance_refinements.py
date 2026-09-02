import unittest

from sep02_assurance_refinements import (
    evaluate_active_mandate_reattestation,
    evaluate_assurance_test_harness_integrity,
    evaluate_challenge_population_selection_provenance,
    evaluate_criteria_standing,
    evaluate_evidence_reconstruction_provenance,
    evaluate_gate_discrimination_health,
    evaluate_human_oversight_capability_preservation,
    evaluate_human_oversight_credential_disposition,
    evaluate_independent_reproduction_standing,
    evaluate_institutional_state_origin,
    evaluate_observation_event_existence,
    evaluate_physical_authorization_context_standing,
)


class Sep02AssuranceRefinementsTests(unittest.TestCase):
    def test_replayable_package_is_not_independent_reproduction(self):
        r = evaluate_independent_reproduction_standing(
            frozen_package_present=True,
            independent_evaluator=False,
            replay_completed=True,
            acceptance_criteria_frozen=True,
            material_conditions_preserved=True,
            result_correspondence_established=True,
            disagreement_preserved=True,
        )
        self.assertEqual(r["independent_reproduction_standing"], "NOT_ESTABLISHED")
        self.assertFalse(r["self_replay_equals_independent_confirmation"])

    def test_corrupt_oracle_breaks_test_harness_standing(self):
        r = evaluate_assurance_test_harness_integrity(
            expected_results_frozen=True,
            evidence_references_bound=True,
            witness_independence_established=True,
            test_vectors_frozen=True,
            oracle_integrity_established=False,
            receipt_trace_correspondence=True,
            bypass_surface_covered=True,
        )
        self.assertEqual(r["assurance_test_harness_integrity"], "NOT_ESTABLISHED")

    def test_selected_challenges_do_not_cover_unexamined_population(self):
        r = evaluate_challenge_population_selection_provenance(
            population_frozen=True,
            population_digest_present=True,
            selection_method_frozen=True,
            selector_authority_bound=True,
            exclusions_recorded=True,
            selection_precommitted=True,
            tested_count=4,
            population_count=10,
        )
        self.assertEqual(r["challenge_selection_provenance_standing"], "SUPPORTABLE")
        self.assertEqual(r["unexamined_conditions"], 6)
        self.assertFalse(r["pass_on_selected_challenges_supports_unexamined_surface"])

    def test_reconstructed_record_remains_reconstructed(self):
        r = evaluate_evidence_reconstruction_provenance(
            original_record_recovered=False,
            reconstruction_performed=True,
            original_event_time_preserved=True,
            reconstruction_time_preserved=True,
            secondary_evidence_identified=True,
            participant_confirmation_recorded=True,
            reconstruction_labeled_as_reconstruction=True,
        )
        self.assertEqual(r["evidence_reconstruction_provenance_standing"], "RECONSTRUCTED_WITH_PROVENANCE")
        self.assertFalse(r["reconstructed_record_equals_original_record"])

    def test_changed_criteria_require_requalification(self):
        r = evaluate_criteria_standing(
            historical_criteria_id="K1",
            current_criteria_id="K2",
            current_criteria_authority_valid=True,
            risk_appetite_current=True,
            interpretive_frame_current=True,
            assumption_set_current=True,
            decision_boundary_current=True,
            monitor_set_current=True,
            requalification_completed_if_changed=False,
        )
        self.assertEqual(r["criteria_standing"], "REQUALIFICATION_REQUIRED")
        self.assertFalse(r["historical_green_state_automatically_inherited"])

    def test_renew_button_does_not_restore_hollow_mandate(self):
        r = evaluate_active_mandate_reattestation(
            mandate_record_current=True,
            scope_current=True,
            domain_activity_evidence=False,
            live_challenge_evidence=False,
            succession_evidence=False,
            reattestation_due=True,
        )
        self.assertEqual(r["active_mandate_reattestation_standing"], "LAPSED")

    def test_longitudinal_oversight_failure_is_not_hidden_by_requalification(self):
        r = evaluate_human_oversight_capability_preservation(
            structural_review_opportunity=True,
            actual_challenge_evidence=True,
            longitudinal_capability_signal_supportable=False,
            seeded_probe_passed=False,
            telemetry_indicator_only=True,
            independent_adjudication_available=True,
        )
        self.assertEqual(r["human_oversight_capability_preservation_standing"], "NOT_ESTABLISHED")
        self.assertFalse(r["telemetry_indicator_can_suspend_authority"])

    def test_valid_credential_can_coexist_with_failed_oversight_standing(self):
        r = evaluate_human_oversight_credential_disposition(
            identity_verified=True,
            competence_current=True,
            credential_valid=True,
            scope_current=True,
            information_standing=False,
            intervention_standing=False,
            protection_standing=False,
        )
        self.assertTrue(r["credential_valid"])
        self.assertEqual(r["human_oversight_standing"], "NOT_ESTABLISHED")

    def test_uniform_gate_behavior_across_heterogeneous_cases_requires_investigation(self):
        r = evaluate_gate_discrimination_health(
            heterogeneous_conditions_present=True,
            dispositions=["ALLOW", "ALLOW", "ALLOW", "ALLOW"],
            materially_distinct_condition_count=4,
            disposition_diversity_expected=True,
        )
        self.assertEqual(r["gate_discrimination_health"], "INVESTIGATION_REQUIRED")
        self.assertFalse(r["uniform_outcomes_prove_individual_decision_wrong"])

    def test_client_cannot_manufacture_submission_state(self):
        r = evaluate_institutional_state_origin(
            client_claimed_state="FINALIZED",
            authoritative_server_state=None,
            server_receipt_present=False,
            finalization_authority_event_present=False,
            publication_authority_event_present=False,
        )
        self.assertEqual(r["institutional_submission_standing"], "NOT_ESTABLISHED")
        self.assertTrue(r["fail_closed"])

    def test_authority_context_change_before_consequence_withdraws_standing(self):
        r = evaluate_physical_authorization_context_standing(
            entity_bound=True,
            action_bound=True,
            location_current=False,
            time_current=True,
            purpose_mission_current=True,
            authority_source_current=True,
            scope_contains_action=True,
            not_expired=True,
            current_conditions_supportable=True,
        )
        self.assertEqual(r["physical_authorization_context_standing"], "NOT_ESTABLISHED")
        self.assertFalse(r["prior_authorization_historically_erased"])

    def test_authentic_record_does_not_prove_sample_was_collected(self):
        r = evaluate_observation_event_existence(
            digital_record_authentic=True,
            recorded_sample_identity_present=True,
            physical_sample_collection_established=False,
            measurement_event_established=False,
            calculation_transformation_valid=True,
            decision_context_supported=True,
        )
        self.assertEqual(r["document_integrity_standing"], "ESTABLISHED")
        self.assertEqual(r["physical_sample_collection_standing"], "NOT_ESTABLISHED")
        self.assertEqual(r["observation_claim_admissibility"], "NOT_ESTABLISHED")


if __name__ == "__main__":
    unittest.main()
