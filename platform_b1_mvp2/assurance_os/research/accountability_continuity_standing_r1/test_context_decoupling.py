import unittest

from accountability_continuity_standing import SUPPORTABLE, evaluate_accountability_continuity
from test_accountability_continuity_standing import BASE_ACCOUNTABILITY, BASE_HANDOFF, BASE_EVIDENCE


class AccountabilityContextDecouplingTests(unittest.TestCase):
    def test_missing_responsibility_metadata_does_not_defeat_accountability(self):
        r = evaluate_accountability_continuity(
            responsibility_context={},
            accountability_state=dict(BASE_ACCOUNTABILITY),
            handoff_state=dict(BASE_HANDOFF),
            evidence_state=dict(BASE_EVIDENCE),
        )
        self.assertEqual(r["accountability_continuity_standing"], SUPPORTABLE)
        self.assertIsNone(r["responsible_party_count"])
        self.assertIsNone(r["shared_responsibility_declared"])
        self.assertIsNone(r["responsibility_assignment_complete"])

    def test_missing_execution_actor_traceability_does_not_defeat_accountability(self):
        evidence = dict(BASE_EVIDENCE)
        evidence.pop("execution_actor_traceable")
        r = evaluate_accountability_continuity(
            responsibility_context={},
            accountability_state=dict(BASE_ACCOUNTABILITY),
            handoff_state=dict(BASE_HANDOFF),
            evidence_state=evidence,
        )
        self.assertEqual(r["accountability_continuity_standing"], SUPPORTABLE)
        self.assertIsNone(r["execution_actor_traceable"])

    def test_false_execution_actor_traceability_does_not_substitute_or_defeat_accountability(self):
        evidence = dict(BASE_EVIDENCE)
        evidence["execution_actor_traceable"] = False
        r = evaluate_accountability_continuity(
            responsibility_context={},
            accountability_state=dict(BASE_ACCOUNTABILITY),
            handoff_state=dict(BASE_HANDOFF),
            evidence_state=evidence,
        )
        self.assertEqual(r["accountability_continuity_standing"], SUPPORTABLE)
        self.assertFalse(r["execution_actor_traceable"])
        self.assertFalse(r["responsibility_treated_as_accountability"])


if __name__ == "__main__":
    unittest.main()
