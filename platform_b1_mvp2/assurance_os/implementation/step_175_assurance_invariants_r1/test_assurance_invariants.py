import unittest

from assurance_invariants import (
    classify_absence,
    evaluate_control_basis,
    examine_partial_evidence,
    evaluate_intervention_viability,
    evaluate_restraint_claim,
    evaluate_trust_anchor_succession,
)


class AssuranceInvariantTests(unittest.TestCase):
    def test_absence_unresolved_is_preserved(self):
        result = classify_absence(observed=False, search_sufficient=False)
        self.assertEqual(result["state"], "ABSENCE_UNRESOLVED")
        self.assertTrue(result["fail_closed"])

    def test_established_absence_requires_sufficient_search(self):
        result = classify_absence(observed=False, search_sufficient=True)
        self.assertEqual(result["state"], "ABSENT_ESTABLISHED")
        self.assertTrue(result["established_absence"])

    def test_control_execution_cannot_substitute_for_control_basis(self):
        result = evaluate_control_basis([
            {
                "name": "policy_source",
                "required": True,
                "present": True,
                "current": False,
                "integrity": True,
                "agrees": True,
            }
        ])
        self.assertEqual(result["standing"], "REASSESSMENT_REQUIRED")
        self.assertTrue(result["fail_closed"])

    def test_unresolved_required_basis_is_not_established(self):
        result = evaluate_control_basis([
            {
                "name": "authority_mapping",
                "required": True,
                "present": False,
                "search_sufficient": False,
                "current": False,
                "integrity": False,
                "agrees": False,
            }
        ])
        self.assertEqual(result["standing"], "NOT_ESTABLISHED")
        self.assertEqual(result["unresolved"], ["authority_mapping"])

    def test_partial_evidence_does_not_expose_unsupported_certainty(self):
        result = examine_partial_evidence(
            prior_state="NOT_ESTABLISHED",
            required_dimensions=["identity", "currency", "authority"],
            evidence=[
                {"dimension": "identity", "state": "ESTABLISHED"},
                {"dimension": "currency", "state": "ESTABLISHED"},
            ],
        )
        self.assertEqual(result["resulting_state"], "NOT_ESTABLISHED")
        self.assertEqual(result["missing_required_dimensions"], ["authority"])

    def test_new_conflict_can_narrow_prior_support(self):
        result = examine_partial_evidence(
            prior_state="SUPPORTABLE",
            required_dimensions=["identity", "currency"],
            evidence=[
                {"dimension": "identity", "state": "ESTABLISHED"},
                {"dimension": "currency", "state": "CONFLICTING"},
            ],
        )
        self.assertEqual(result["resulting_state"], "NOT_ESTABLISHED")

    def test_authority_does_not_make_late_intervention_viable(self):
        result = evaluate_intervention_viability(
            authority_valid=True,
            consequence_alterable=False,
            intervention_window_open=False,
        )
        self.assertEqual(result["state"], "INTERVENTION_NOT_VIABLE")

    def test_blocked_action_is_not_harm_prevention(self):
        result = evaluate_restraint_claim(
            action_blocked=True,
            alternate_paths_excluded=False,
            consequence_observed_prevented=False,
        )
        self.assertEqual(result["state"], "ACTION_BLOCKED_ONLY")

    def test_verified_restraint_requires_consequence_evidence(self):
        result = evaluate_restraint_claim(
            action_blocked=True,
            alternate_paths_excluded=True,
            consequence_observed_prevented=True,
        )
        self.assertEqual(result["state"], "VERIFIED_RESTRAINT")

    def test_unrelated_successor_cannot_inherit_historical_checkpoint(self):
        result = evaluate_trust_anchor_succession(
            predecessor_anchor="K1",
            successor_anchor="K2",
            predecessor_authorized=True,
            successor_cryptographically_capable=True,
            succession_event_present=False,
            succession_event_authenticated=False,
            succession_scope_valid=False,
            succession_current=False,
        )
        self.assertEqual(result["successor_authority_standing"], "NOT_ESTABLISHED")
        self.assertEqual(result["reason"], "SUCCESSION_EVENT_NOT_ESTABLISHED")
        self.assertTrue(result["fail_closed"])

    def test_authenticated_current_scoped_succession_can_be_supportable(self):
        result = evaluate_trust_anchor_succession(
            predecessor_anchor="K1",
            successor_anchor="K2",
            predecessor_authorized=True,
            successor_cryptographically_capable=True,
            succession_event_present=True,
            succession_event_authenticated=True,
            succession_scope_valid=True,
            succession_current=True,
        )
        self.assertEqual(result["successor_authority_standing"], "SUPPORTABLE")
        self.assertTrue(result["succession_established"])


if __name__ == "__main__":
    unittest.main()
