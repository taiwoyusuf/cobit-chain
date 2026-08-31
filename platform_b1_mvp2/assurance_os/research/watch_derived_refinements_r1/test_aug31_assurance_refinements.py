import unittest

from aug31_assurance_refinements import (
    evaluate_consequence_incapacity_challenge,
    evaluate_definition_evidence_correspondence,
    evaluate_digital_proxy_non_authority,
    evaluate_evidence_plane_survivability,
    evaluate_intent_constitution_artifact,
    evaluate_lifecycle_exit_retirement,
    evaluate_measurement_context_representativeness,
    evaluate_measurement_semantic_standing,
    evaluate_outcome_next_cycle_inheritance,
    evaluate_persistent_memory_admissibility,
    evaluate_refusal_survivability,
    evaluate_repairability_routing,
)


class Aug31AssuranceRefinementsTests(unittest.TestCase):
    def test_refusal_must_survive_bypass_and_pressure(self):
        r = evaluate_refusal_survivability(
            refusal_authority=True,
            refusal_channel_available=True,
            refusal_before_bind=True,
            retaliation_or_penalty_exposure=False,
            hierarchical_pressure_uncontrolled=False,
            commercial_pressure_uncontrolled=False,
            independent_escalation_available=True,
            refusal_preserved=True,
            alternate_route_can_bypass_refusal=True,
        )
        self.assertEqual(r["refusal_survivability_standing"], "NOT_ESTABLISHED")

    def test_low_repairability_forces_hold(self):
        r = evaluate_repairability_routing(
            reversible=False,
            reversal_completeness=False,
            time_to_reverse_seconds=None,
            repair_window_seconds=60,
            external_effects_contained=False,
            human_effects_contained=False,
            cross_system_effects_contained=False,
            irreversible_residue=True,
            repair_authority_current=True,
            repair_capacity_available=True,
        )
        self.assertEqual(r["permitted_execution_mode"], "HOLD")

    def test_instruction_is_not_governed_intent(self):
        required = ["intent_objective", "authorized_outcome", "prohibited_outcomes"]
        r = evaluate_intent_constitution_artifact(
            artifact={"intent_objective": "inspect", "authorized_outcome": "report"},
            required_fields=required,
            version_bound=True,
            owner_authorized=True,
            review_trigger_defined=True,
        )
        self.assertEqual(r["missing_intent_fields"], ["prohibited_outcomes"])

    def test_consequence_incapacity_requires_route_complete_challenge(self):
        r = evaluate_consequence_incapacity_challenge(
            required_routes=["normal", "alternate", "replay"],
            route_consequence_possible={"normal": False, "alternate": False},
        )
        self.assertEqual(r["consequence_incapacity_standing"], "UNRESOLVED_INCOMPLETE_ROUTE_COVERAGE")

    def test_digital_proxy_never_manufactures_authority(self):
        r = evaluate_digital_proxy_non_authority(
            proxy_present=True,
            inferred_preferences_present=True,
            behavioral_prediction_present=True,
            explicit_current_grant=False,
            grant_scope_contains_action=False,
            human_ratification_required=True,
            human_ratified=False,
        )
        self.assertFalse(r["proxy_created_authority"])
        self.assertEqual(r["authority_basis"], "NOT_ESTABLISHED")

    def test_evidence_outage_does_not_fall_back_to_unauthorized_cache(self):
        r = evaluate_evidence_plane_survivability(
            required_evidence_service_available=False,
            cached_evidence_present=True,
            cached_evidence_use_authorized=False,
            commit_attempted=True,
            local_hold_receipt_preserved=True,
            service_restored_later=True,
        )
        self.assertEqual(r["required_behavior"], "HOLD")
        self.assertTrue(r["commit_during_unresolved_outage"])
        self.assertFalse(r["later_restoration_is_contemporaneous_proof"])

    def test_retirement_incomplete_when_residual_route_survives(self):
        r = evaluate_lifecycle_exit_retirement(
            retirement_authorized=True,
            active_lifecycle_authority_closed=True,
            primary_route_disabled=True,
            residual_execution_routes=["scheduled_job"],
            unresolved_obligations=[],
            historical_record_preserved=True,
            data_disposition_recorded=True,
        )
        self.assertEqual(r["retirement_standing"], "INCOMPLETE")
        self.assertEqual(r["residual_route_action_admissibility"], "DENIED")

    def test_authentic_memory_can_be_inadmissible_now(self):
        r = evaluate_persistent_memory_admissibility(
            memory_authentic=True,
            provenance_bound=True,
            authority_scope_current=True,
            retention_state_valid=True,
            mutation_lineage_preserved=True,
            retrieval_custody_bound=True,
            current_context_applicable=False,
        )
        self.assertEqual(r["memory_integrity_standing"], "SUPPORTABLE")
        self.assertEqual(r["persistent_memory_admissibility"], "NOT_ESTABLISHED")

    def test_definition_change_does_not_retroactively_invalidate_evidence(self):
        r = evaluate_definition_evidence_correspondence(
            evidence_integrity_valid=True,
            historical_definition_id="D1",
            current_definition_id="D2",
            historical_correspondence_established=True,
            current_correspondence_established=False,
        )
        self.assertEqual(r["current_reliance_standing"], "HOLD")
        self.assertFalse(r["historical_evidence_retroactively_invalidated"])

    def test_new_world_state_blocks_automatic_next_cycle_inheritance(self):
        r = evaluate_outcome_next_cycle_inheritance(
            prior_evidence_integrity_valid=True,
            prior_world_state_id="A",
            current_world_state_id="B",
            current_world_correspondence_established=False,
            current_authority_reestablished=True,
        )
        self.assertEqual(r["next_cycle_inheritance_standing"], "NOT_ESTABLISHED")
        self.assertFalse(r["prior_authorization_automatically_inherited"])

    def test_wrong_unit_semantics_blocks_measurement_standing(self):
        r = evaluate_measurement_semantic_standing(
            value_present=True,
            quantity_identity_bound=True,
            unit_identity_bound=False,
            scale_bound=True,
            instrument_mode_bound=True,
            location_or_object_bound=True,
            time_bound=True,
            interpretation_basis_bound=True,
        )
        self.assertEqual(r["measurement_semantic_standing"], "NOT_ESTABLISHED")

    def test_calibration_does_not_replace_representativeness(self):
        r = evaluate_measurement_context_representativeness(
            calibration_current=True,
            sampling_path_validated=False,
            installation_geometry_bound=True,
            critical_interaction_observable=True,
            evidence_continuity_preserved=True,
            acquisition_intrusiveness_assessed=True,
        )
        self.assertEqual(r["measurement_source_standing"], "SUPPORTABLE")
        self.assertEqual(r["measurement_context_representativeness"], "NOT_ESTABLISHED")


if __name__ == "__main__":
    unittest.main()
