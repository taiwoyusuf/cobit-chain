import unittest

from aug18_absorbed_refinements import (
    evaluate_interacting_decision_condition,
    evaluate_replay_legitimacy_and_promotion,
)


class Aug18AbsorbedRefinementTests(unittest.TestCase):
    def test_replay_success_does_not_establish_current_legitimacy(self):
        r = evaluate_replay_legitimacy_and_promotion(
            replay_succeeded=True,
            current_basis_established=False,
            custody_complete=True,
            record_present=True,
            record_current=True,
            record_applicable=True,
            inference_supported=True,
            reliance_permitted=True,
            action_admissible=False,
        )
        self.assertEqual(r["replay_legitimacy_standing"], "REPLAY_VALID_LEGITIMACY_NOT_ESTABLISHED")

    def test_persisted_record_cannot_be_promoted_with_stale_basis(self):
        r = evaluate_replay_legitimacy_and_promotion(
            replay_succeeded=True,
            current_basis_established=False,
            custody_complete=True,
            record_present=True,
            record_current=False,
            record_applicable=True,
            inference_supported=True,
            reliance_permitted=True,
            action_admissible=True,
        )
        self.assertEqual(r["replay_legitimacy_standing"], "ILLEGAL_PROMOTION_TO_CONSEQUENCE")
        self.assertEqual(r["required_behavior"], "HOLD_NO_BIND")

    def test_proof_presence_does_not_establish_custody(self):
        r = evaluate_replay_legitimacy_and_promotion(
            replay_succeeded=False,
            current_basis_established=True,
            custody_complete=False,
            record_present=True,
            record_current=True,
            record_applicable=True,
            inference_supported=True,
            reliance_permitted=True,
            action_admissible=False,
        )
        self.assertEqual(r["replay_legitimacy_standing"], "PROOF_PRESENT_CUSTODY_INCOMPLETE")

    def test_valid_decisions_require_interaction_assessment(self):
        r = evaluate_interacting_decision_condition(
            decisions=[{"decision_id": "A", "individually_valid": True}, {"decision_id": "B", "individually_valid": True}],
            interaction_assessed=False,
            interaction_basis_current=True,
            intended_outcome_compatible=True,
            emergent_exposure=False,
        )
        self.assertEqual(r["interacting_decision_condition_standing"], "INTERACTION_STANDING_NOT_ESTABLISHED")

    def test_valid_decisions_can_be_incompatible_together(self):
        r = evaluate_interacting_decision_condition(
            decisions=[{"decision_id": "A", "individually_valid": True}, {"decision_id": "B", "individually_valid": True}],
            interaction_assessed=True,
            interaction_basis_current=True,
            intended_outcome_compatible=False,
            emergent_exposure=True,
        )
        self.assertEqual(r["interacting_decision_condition_standing"], "COMPOSITE_CONDITION_INCOMPATIBLE")
        self.assertEqual(r["required_behavior"], "HOLD_NO_BIND")

    def test_supportable_interaction_still_needs_separate_action_admissibility(self):
        r = evaluate_interacting_decision_condition(
            decisions=[{"decision_id": "A", "individually_valid": True}, {"decision_id": "B", "individually_valid": True}],
            interaction_assessed=True,
            interaction_basis_current=True,
            intended_outcome_compatible=True,
            emergent_exposure=False,
        )
        self.assertEqual(r["interacting_decision_condition_standing"], "INTERACTING_DECISION_CONDITION_SUPPORTABLE")
        self.assertEqual(r["required_behavior"], "SEPARATE_ACTION_ADMISSIBILITY_REQUIRED")


if __name__ == "__main__":
    unittest.main()
