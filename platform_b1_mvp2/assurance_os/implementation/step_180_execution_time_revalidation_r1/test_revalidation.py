import unittest

from revalidation import evaluate_execution_time_revalidation


BASE_PRIOR = {
    "enforcement_decision": "ADMISSIBLE",
    "no_bind_state": "INACTIVE",
}

BASE_EVALUATED = {
    "object_hash": "OBJ-A",
    "authority_current": True,
    "evidence_digest": "E1",
    "criteria_version": "C1",
    "configuration_hash": "CFG1",
    "environment_context_hash": "ENV1",
}


class ExecutionTimeRevalidationTests(unittest.TestCase):
    def _run(self, *, current=None, materiality=None, age=10, max_age=100,
             prior=None, evaluated=None):
        return evaluate_execution_time_revalidation(
            prior_enforcement_result=BASE_PRIOR if prior is None else prior,
            evaluated_snapshot=BASE_EVALUATED if evaluated is None else evaluated,
            current_snapshot=dict(BASE_EVALUATED) if current is None else current,
            materiality_by_dimension={} if materiality is None else materiality,
            decision_age_ms=age,
            max_decision_age_ms=max_age,
        )

    def test_unchanged_current_state_remains_admissible(self):
        result = self._run()
        self.assertEqual(result["execution_time_decision"], "ADMISSIBLE")
        self.assertEqual(result["execution_time_standing"], "SUPPORTABLE")

    def test_prior_non_admissible_cannot_be_revalidated_into_admissible(self):
        result = self._run(prior={"enforcement_decision": "NOT_ADMISSIBLE"})
        self.assertEqual(result["execution_time_decision"], "NOT_ADMISSIBLE")
        self.assertIn("PRIOR_DECISION_NOT_ADMISSIBLE", result["reasons"])

    def test_stale_prior_decision_fails_closed(self):
        result = self._run(age=101, max_age=100)
        self.assertEqual(result["execution_time_decision"], "NOT_ADMISSIBLE")
        self.assertIn("PRIOR_DECISION_STALE", result["reasons"])

    def test_authority_withdrawal_before_commit_blocks(self):
        current = dict(BASE_EVALUATED)
        current["authority_current"] = False
        result = self._run(current=current)
        self.assertIn("AUTHORITY_NOT_CURRENT_AT_COMMIT", result["reasons"])

    def test_object_change_is_never_hidden_by_materiality(self):
        current = dict(BASE_EVALUATED)
        current["object_hash"] = "OBJ-B"
        result = self._run(current=current, materiality={"object_hash": "IMMATERIAL"})
        self.assertIn("OBJECT_CHANGED_AFTER_EVALUATION", result["reasons"])
        self.assertEqual(result["execution_time_decision"], "NOT_ADMISSIBLE")

    def test_material_evidence_change_requires_reassessment(self):
        current = dict(BASE_EVALUATED)
        current["evidence_digest"] = "E2"
        result = self._run(current=current, materiality={"evidence_digest": "MATERIAL"})
        self.assertIn("evidence_digest", result["material_changes"])
        self.assertEqual(result["execution_time_standing"], "REASSESSMENT_REQUIRED")

    def test_unclassified_change_fails_closed(self):
        current = dict(BASE_EVALUATED)
        current["criteria_version"] = "C2"
        result = self._run(current=current)
        self.assertIn("criteria_version", result["unclassified_changes"])
        self.assertEqual(result["no_bind_state"], "ACTIVE")

    def test_declared_immaterial_change_can_preserve_standing(self):
        current = dict(BASE_EVALUATED)
        current["configuration_hash"] = "CFG2"
        result = self._run(current=current, materiality={"configuration_hash": "IMMATERIAL"})
        self.assertEqual(result["execution_time_decision"], "ADMISSIBLE")
        self.assertIn("configuration_hash", result["immaterial_changes"])

    def test_material_environment_change_blocks_green_values(self):
        current = dict(BASE_EVALUATED)
        current["environment_context_hash"] = "ENV2"
        result = self._run(current=current, materiality={"environment_context_hash": "MATERIAL"})
        self.assertEqual(result["execution_time_decision"], "NOT_ADMISSIBLE")
        self.assertIn("ENVIRONMENT_CONTEXT_HASH_MATERIAL_CHANGE_REQUIRES_REASSESSMENT", result["reasons"])

    def test_multiple_changes_are_evaluated_independently(self):
        current = dict(BASE_EVALUATED)
        current["criteria_version"] = "C2"
        current["configuration_hash"] = "CFG2"
        result = self._run(
            current=current,
            materiality={
                "criteria_version": "MATERIAL",
                "configuration_hash": "IMMATERIAL",
            },
        )
        self.assertEqual(result["material_changes"], ["criteria_version"])
        self.assertEqual(result["immaterial_changes"], ["configuration_hash"])
        self.assertEqual(result["execution_time_decision"], "NOT_ADMISSIBLE")

    def test_missing_current_snapshot_dimension_fails_closed(self):
        current = dict(BASE_EVALUATED)
        del current["evidence_digest"]
        result = self._run(current=current)
        self.assertIn("EVIDENCE_DIGEST_SNAPSHOT_MISSING", result["reasons"])

    def test_prior_decision_is_preserved_as_history_when_withdrawn(self):
        current = dict(BASE_EVALUATED)
        current["criteria_version"] = "C2"
        result = self._run(current=current, materiality={"criteria_version": "MATERIAL"})
        self.assertTrue(result["prior_decision_preserved_as_history"])
        self.assertFalse(result["binding_authority_granted"])
        self.assertFalse(result["physical_action_executed"])


if __name__ == "__main__":
    unittest.main()
