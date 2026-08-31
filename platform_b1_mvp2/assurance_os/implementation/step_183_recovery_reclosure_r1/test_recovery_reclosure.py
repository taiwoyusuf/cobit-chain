import unittest

from recovery_reclosure import evaluate_recovery_reclosure


class RecoveryReclosureTests(unittest.TestCase):
    def setUp(self):
        self.prior = {"correspondence_standing": "OUTCOME_DIVERGED"}
        self.recovery = {"recovery_standing": "RECOVERED_WITHIN_DECLARED_SCOPE"}
        self.disposition = {"disposition_standing": "CLOSED_WITH_EVIDENCE"}
        self.reclosure = {
            "historical_event_preserved": True,
            "current_world_correspondence_established": True,
            "criteria_current": True,
            "authority_current": True,
            "required_evidence_current": True,
            "reclosure_baseline_established": True,
            "independent_outcome_reverified": True,
        }

    def evaluate(self, **kwargs):
        return evaluate_recovery_reclosure(
            prior_outcome_result=kwargs.get("prior", self.prior),
            recovery_result=kwargs.get("recovery", self.recovery),
            disposition_result=kwargs.get("disposition", self.disposition),
            residual_obligations=kwargs.get("obligations", []),
            reclosure_evidence=kwargs.get("reclosure", self.reclosure),
            reclosure_required=kwargs.get("required", True),
            independent_outcome_reverification_required=kwargs.get("independent_required", False),
        )

    def test_full_reclosure_supports_return_to_reliance_without_rewriting_history(self):
        result = self.evaluate()
        self.assertEqual(result["reclosure_standing"], "RECLOSURE_SUPPORTABLE")
        self.assertTrue(result["return_to_reliance_supportable"])
        self.assertFalse(result["historical_facts_rewritten"])
        self.assertFalse(result["binding_authority_granted"])

    def test_partial_recovery_does_not_establish_reclosure(self):
        recovery = {"recovery_standing": "PARTIAL"}
        result = self.evaluate(recovery=recovery)
        self.assertEqual(result["reclosure_standing"], "RECOVERY_NOT_ESTABLISHED")
        self.assertEqual(result["no_bind_state"], "ACTIVE")

    def test_open_disposition_blocks_reclosure(self):
        disposition = {"disposition_standing": "OPEN_GOVERNED_CONDITION"}
        result = self.evaluate(disposition=disposition)
        self.assertEqual(result["reclosure_standing"], "DISPOSITION_NOT_CLOSED")

    def test_blocking_residual_obligation_blocks_reclosure(self):
        obligations = [{"obligation_id": "CAPA-1", "blocking": True, "closed": False}]
        result = self.evaluate(obligations=obligations)
        self.assertEqual(result["reclosure_standing"], "BLOCKING_RESIDUAL_OBLIGATION_OPEN")
        self.assertEqual(result["blocking_obligations"], ["CAPA-1"])

    def test_nonblocking_obligation_survives_reentry_without_being_erased(self):
        obligations = [{"obligation_id": "FOLLOWUP-1", "blocking": False, "closed": False}]
        result = self.evaluate(obligations=obligations)
        self.assertEqual(result["reclosure_standing"], "RECLOSURE_SUPPORTABLE")
        self.assertEqual(result["open_obligations_preserved"], ["FOLLOWUP-1"])

    def test_current_world_correspondence_is_required(self):
        evidence = dict(self.reclosure)
        evidence["current_world_correspondence_established"] = False
        result = self.evaluate(reclosure=evidence)
        self.assertEqual(result["reclosure_standing"], "CURRENT_WORLD_CORRESPONDENCE_NOT_ESTABLISHED")

    def test_current_authority_is_required(self):
        evidence = dict(self.reclosure)
        evidence["authority_current"] = False
        result = self.evaluate(reclosure=evidence)
        self.assertEqual(result["reclosure_standing"], "CURRENT_AUTHORITY_NOT_ESTABLISHED")

    def test_definition_or_criteria_must_be_current(self):
        evidence = dict(self.reclosure)
        evidence["criteria_current"] = False
        result = self.evaluate(reclosure=evidence)
        self.assertEqual(result["reclosure_standing"], "CURRENT_CRITERIA_NOT_ESTABLISHED")

    def test_independent_outcome_reverification_can_be_required(self):
        evidence = dict(self.reclosure)
        evidence["independent_outcome_reverified"] = False
        result = self.evaluate(reclosure=evidence, independent_required=True)
        self.assertEqual(result["reclosure_standing"], "INDEPENDENT_OUTCOME_REVERIFICATION_NOT_ESTABLISHED")

    def test_history_preservation_is_a_precondition(self):
        evidence = dict(self.reclosure)
        evidence["historical_event_preserved"] = False
        result = self.evaluate(reclosure=evidence)
        self.assertEqual(result["reclosure_standing"], "HISTORICAL_EVENT_PRESERVATION_NOT_ESTABLISHED")

    def test_reclosure_not_required_does_not_grant_authority(self):
        result = self.evaluate(required=False)
        self.assertEqual(result["reclosure_standing"], "NOT_APPLICABLE")
        self.assertFalse(result["binding_authority_granted"])


if __name__ == "__main__":
    unittest.main()
