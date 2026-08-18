import unittest

from structural_standing import (
    evaluate_interacting_decisions,
    evaluate_operating_envelope,
    evaluate_replay_legitimacy,
)


class StructuralStandingTests(unittest.TestCase):
    def test_structural_change_blocks_even_when_values_green(self):
        result = evaluate_operating_envelope({
            "qualified_envelope_id": "E1",
            "current_envelope_id": "E1",
            "corridor_supported": True,
            "current_values_within_limits": True,
            "structural_change_detected": True,
        })
        self.assertEqual(result["standing"], "ENVELOPE_CHANGED")
        self.assertEqual(result["routing"], "REQUALIFICATION_REQUIRED")

    def test_bifurcation_requires_requalification(self):
        result = evaluate_operating_envelope({
            "qualified_envelope_id": "E1",
            "current_envelope_id": "E1",
            "corridor_supported": True,
            "bifurcation_detected": True,
        })
        self.assertEqual(result["standing"], "REGIME_BIFURCATED")

    def test_no_supportable_corridor_holds(self):
        result = evaluate_operating_envelope({
            "qualified_envelope_id": "E1",
            "current_envelope_id": "E1",
            "corridor_supported": False,
        })
        self.assertEqual(result["standing"], "NO_SUPPORTABLE_OPERATING_CORRIDOR")
        self.assertEqual(result["routing"], "HOLD_NO_BIND")

    def test_parametric_drift_can_remain_within_envelope(self):
        result = evaluate_operating_envelope({
            "qualified_envelope_id": "E1",
            "current_envelope_id": "E1",
            "corridor_supported": True,
            "parametric_drift_detected": True,
        })
        self.assertEqual(result["standing"], "PARAMETRIC_DRIFT_WITHIN_ENVELOPE")

    def test_stable_envelope(self):
        result = evaluate_operating_envelope({
            "qualified_envelope_id": "E1",
            "current_envelope_id": "E1",
            "corridor_supported": True,
        })
        self.assertEqual(result["standing"], "ENVELOPE_STABLE")

    def test_replay_does_not_establish_current_legitimacy(self):
        result = evaluate_replay_legitimacy({
            "replay_succeeded": True,
            "current_basis_established": False,
            "custody_complete": True,
            "record_present": True,
            "record_current": True,
            "record_applicable": True,
            "inference_supported": True,
            "reliance_permitted": True,
            "action_admissible": False,
        })
        self.assertEqual(result["standing"], "REPLAY_VALID_LEGITIMACY_NOT_ESTABLISHED")

    def test_proof_can_exist_with_incomplete_custody(self):
        result = evaluate_replay_legitimacy({
            "replay_succeeded": False,
            "current_basis_established": True,
            "custody_complete": False,
            "record_present": True,
            "record_current": True,
            "record_applicable": True,
            "inference_supported": True,
            "reliance_permitted": True,
            "action_admissible": False,
        })
        self.assertEqual(result["standing"], "PROOF_PRESENT_CUSTODY_INCOMPLETE")

    def test_illegal_promotion_to_consequence_is_blocked(self):
        result = evaluate_replay_legitimacy({
            "replay_succeeded": True,
            "current_basis_established": True,
            "custody_complete": True,
            "record_present": True,
            "record_current": False,
            "record_applicable": True,
            "inference_supported": True,
            "reliance_permitted": True,
            "action_admissible": True,
        })
        self.assertEqual(result["standing"], "ILLEGAL_PROMOTION_TO_CONSEQUENCE")
        self.assertEqual(result["routing"], "HOLD_NO_BIND")

    def test_legitimacy_chain_does_not_create_action_authority(self):
        result = evaluate_replay_legitimacy({
            "replay_succeeded": True,
            "current_basis_established": True,
            "custody_complete": True,
            "record_present": True,
            "record_current": True,
            "record_applicable": True,
            "inference_supported": True,
            "reliance_permitted": True,
            "action_admissible": False,
        })
        self.assertEqual(result["standing"], "LEGITIMACY_CHAIN_ESTABLISHED")
        self.assertEqual(result["routing"], "SEPARATE_ACTION_ADMISSIBILITY_REQUIRED")

    def test_individually_valid_decisions_need_interaction_assessment(self):
        result = evaluate_interacting_decisions({
            "decisions": [
                {"decision_id": "A", "individually_valid": True},
                {"decision_id": "B", "individually_valid": True},
            ],
            "interaction_assessed": False,
        })
        self.assertEqual(result["standing"], "INTERACTION_STANDING_NOT_ESTABLISHED")

    def test_individually_valid_decisions_can_be_incompatible_together(self):
        result = evaluate_interacting_decisions({
            "decisions": [
                {"decision_id": "A", "individually_valid": True},
                {"decision_id": "B", "individually_valid": True},
            ],
            "interaction_assessed": True,
            "interaction_basis_current": True,
            "intended_outcome_compatible": False,
        })
        self.assertEqual(result["standing"], "COMPOSITE_CONDITION_INCOMPATIBLE")
        self.assertEqual(result["routing"], "HOLD_NO_BIND")

    def test_interacting_decisions_supportable_without_execution_authority(self):
        result = evaluate_interacting_decisions({
            "decisions": [
                {"decision_id": "A", "individually_valid": True},
                {"decision_id": "B", "individually_valid": True},
            ],
            "interaction_assessed": True,
            "interaction_basis_current": True,
            "intended_outcome_compatible": True,
            "emergent_exposure": False,
        })
        self.assertEqual(result["standing"], "INTERACTING_DECISION_CONDITION_SUPPORTABLE")
        self.assertEqual(result["routing"], "SEPARATE_ACTION_ADMISSIBILITY_REQUIRED")


if __name__ == "__main__":
    unittest.main()
