import unittest

from physical_evidence_standing import (
    evaluate_operating_envelope,
    evaluate_observation_channel,
    evaluate_temporal_resolution,
    evaluate_detectability,
    evaluate_bridge_standing,
    evaluate_composition_standing,
    evaluate_fusion_standing,
    evaluate_source_attribution,
    evaluate_time_indexed_standing,
    evaluate_decision_policy,
    evaluate_oversight_capacity,
    evaluate_transfer_fidelity,
)


class PhysicalEvidenceStandingTests(unittest.TestCase):
    def test_state_conditioned_confidence(self):
        r = evaluate_operating_envelope(calibrated=True, authenticated=True, healthy=True, inside_validated_state_space=False)
        self.assertEqual(r["state"], "REASSESSMENT_REQUIRED")

    def test_structural_change_blocks_silent_envelope_inheritance(self):
        r = evaluate_operating_envelope(
            calibrated=True,
            authenticated=True,
            healthy=True,
            inside_validated_state_space=True,
            structural_change_detected=True,
        )
        self.assertEqual(r["state"], "REASSESSMENT_REQUIRED")
        self.assertEqual(r["reason"], "STRUCTURAL_OPERATING_REGIME_CHANGED")

    def test_bifurcation_requires_reassessment(self):
        r = evaluate_operating_envelope(
            calibrated=True,
            authenticated=True,
            healthy=True,
            inside_validated_state_space=True,
            bifurcation_detected=True,
        )
        self.assertEqual(r["state"], "REASSESSMENT_REQUIRED")
        self.assertEqual(r["reason"], "OPERATING_REGIME_BIFURCATED")

    def test_envelope_identity_change_requires_reassessment(self):
        r = evaluate_operating_envelope(
            calibrated=True,
            authenticated=True,
            healthy=True,
            inside_validated_state_space=True,
            qualified_envelope_id="E1",
            current_envelope_id="E2",
        )
        self.assertEqual(r["state"], "REASSESSMENT_REQUIRED")
        self.assertEqual(r["reason"], "QUALIFIED_OPERATING_ENVELOPE_ID_CHANGED")

    def test_no_supportable_corridor_fails_closed(self):
        r = evaluate_operating_envelope(
            calibrated=True,
            authenticated=True,
            healthy=True,
            inside_validated_state_space=True,
            corridor_supported=False,
        )
        self.assertEqual(r["state"], "NOT_ESTABLISHED")
        self.assertEqual(r["reason"], "NO_SUPPORTABLE_OPERATING_CORRIDOR")

    def test_observation_channel_fidelity(self):
        r = evaluate_observation_channel(channel_validated=True, transport_loss_material=True, witness_perturbation_material=False)
        self.assertEqual(r["state"], "REASSESSMENT_REQUIRED")

    def test_temporal_resolution_aliasing(self):
        r = evaluate_temporal_resolution(sensor_response_seconds=1, sampling_interval_seconds=300, event_timescale_seconds=18)
        self.assertEqual(r["state"], "NOT_ESTABLISHED")

    def test_detection_limit_is_not_zero(self):
        r = evaluate_detectability(value=0.5, detection_limit=1.0, quantification_limit=2.0)
        self.assertEqual(r["state"], "NOT_DETECTED_WITH_LIMIT")

    def test_bridge_requires_equivalence_challenge(self):
        r = evaluate_bridge_standing(regime_a_valid=True, regime_b_valid=True, equivalence_challenge_performed=False, equivalent_within_declared_margin=False)
        self.assertEqual(r["state"], "NOT_ESTABLISHED")

    def test_component_validity_does_not_establish_composition(self):
        r = evaluate_composition_standing(components_valid=True, semantic_compatible=False, units_compatible=True, timing_compatible=True, intended_use_compatible=True)
        self.assertEqual(r["state"], "NOT_ESTABLISHED")

    def test_fusion_requires_dependency_characterization(self):
        r = evaluate_fusion_standing(inputs_supportable=True, dependencies_characterized=False, uncertainty_propagated=True, fusion_version_known=True)
        self.assertEqual(r["state"], "DEPENDENCY_UNCERTAIN")

    def test_source_attribution_preserves_alternatives(self):
        r = evaluate_source_attribution(condition_established=True, candidate_source_supported=True, alternatives_excluded=False)
        self.assertEqual(r["state"], "SOURCE_POSSIBLE")

    def test_time_indexed_standing_expires(self):
        r = evaluate_time_indexed_standing(currently_supportable=True, valid_until_epoch=10, now_epoch=11)
        self.assertEqual(r["state"], "REASSESSMENT_REQUIRED")

    def test_model_validity_does_not_establish_policy(self):
        r = evaluate_decision_policy(model_valid=True, interpretation_valid=True, rule_current=True, policy_challenged=False, authority_current=True)
        self.assertEqual(r["state"], "NOT_ESTABLISHED")

    def test_human_in_loop_requires_capacity(self):
        r = evaluate_oversight_capacity(qualified_human_available=True, evidence_presented=True, review_time_sufficient=False, workload_within_capacity=True, can_intervene_before_irreversible=True)
        self.assertEqual(r["state"], "NOT_ESTABLISHED")

    def test_prepared_is_not_delivered(self):
        r = evaluate_transfer_fidelity(intended_quantity=100, delivered_quantity=76, tolerance_fraction=0.05, destination_verified=True)
        self.assertEqual(r["state"], "NOT_ESTABLISHED")


if __name__ == "__main__":
    unittest.main()
