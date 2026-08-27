import unittest

from commit_execution_outcome_correspondence import evaluate_commit_execution_outcome_correspondence


class CommitExecutionOutcomeCorrespondenceTests(unittest.TestCase):
    def setUp(self):
        self.prior = {
            "atomic_commit_standing": "SUPPORTABLE",
            "commit_decision": "COMMIT_ROUTE_ADMISSIBLE",
            "no_bind_state": "INACTIVE",
        }
        self.expected = {
            "action_id": "ACT-1",
            "transaction_id": "TX-1",
            "object_hash": "OBJ-A",
            "target": "TARGET-1",
            "destination": "DEST-1",
            "intended_outcome": "OUTCOME-OK",
        }
        self.commit = {
            "transaction_id": "TX-1",
            "object_hash": "OBJ-A",
            "commit_status": "COMMITTED",
        }
        self.execution = {
            "action_id": "ACT-1",
            "transaction_id": "TX-1",
            "object_hash": "OBJ-A",
            "target": "TARGET-1",
            "destination": "DEST-1",
            "execution_status": "SUCCEEDED",
        }
        self.outcome = {
            "action_id": "ACT-1",
            "transaction_id": "TX-1",
            "object_hash": "OBJ-A",
            "target": "TARGET-1",
            "destination": "DEST-1",
            "outcome_status": "OBSERVED",
            "observed_outcome": "OUTCOME-OK",
        }

    def evaluate(self, **kwargs):
        return evaluate_commit_execution_outcome_correspondence(
            prior_commit_result=kwargs.get("prior", self.prior),
            commit_receipt=kwargs.get("commit", self.commit),
            execution_receipt=kwargs.get("execution", self.execution),
            outcome_evidence=kwargs.get("outcome", self.outcome),
            expected=kwargs.get("expected", self.expected),
        )

    def test_full_exact_route_supports_outcome_correspondence(self):
        result = self.evaluate()
        self.assertEqual(result["correspondence_standing"], "OUTCOME_CORRESPONDENCE_SUPPORTABLE")
        self.assertTrue(result["intended_outcome_established"])
        self.assertEqual(result["no_bind_state"], "INACTIVE")

    def test_step181_not_admissible_blocks_correspondence(self):
        prior = dict(self.prior)
        prior["commit_decision"] = "NOT_ADMISSIBLE"
        result = self.evaluate(prior=prior)
        self.assertEqual(result["correspondence_standing"], "PRIOR_COMMIT_ROUTE_NOT_ADMISSIBLE")

    def test_missing_commit_receipt_does_not_infer_commit(self):
        result = evaluate_commit_execution_outcome_correspondence(
            prior_commit_result=self.prior, commit_receipt=None,
            execution_receipt=self.execution, outcome_evidence=self.outcome,
            expected=self.expected)
        self.assertEqual(result["correspondence_standing"], "COMMIT_NOT_ESTABLISHED")
        self.assertIsNone(result["commit_occurred"])

    def test_transaction_mismatch_in_commit_receipt_is_blocked(self):
        commit = dict(self.commit)
        commit["transaction_id"] = "TX-2"
        result = self.evaluate(commit=commit)
        self.assertIn("COMMIT_RECEIPT_TRANSACTION_ID_MISMATCH", result["reasons"])

    def test_object_mismatch_in_commit_receipt_is_blocked(self):
        commit = dict(self.commit)
        commit["object_hash"] = "OBJ-B"
        result = self.evaluate(commit=commit)
        self.assertEqual(result["correspondence_standing"], "COMMIT_CORRESPONDENCE_MISMATCH")

    def test_commit_without_execution_receipt_preserves_commit_fact(self):
        result = evaluate_commit_execution_outcome_correspondence(
            prior_commit_result=self.prior, commit_receipt=self.commit,
            execution_receipt=None, outcome_evidence=self.outcome,
            expected=self.expected)
        self.assertEqual(result["correspondence_standing"], "COMMITTED_EXECUTION_NOT_ESTABLISHED")
        self.assertTrue(result["historical_facts"]["commit_occurred"])
        self.assertIsNone(result["execution_succeeded"])

    def test_explicit_execution_failure_is_preserved(self):
        execution = dict(self.execution)
        execution["execution_status"] = "FAILED"
        result = self.evaluate(execution=execution)
        self.assertEqual(result["correspondence_standing"], "COMMITTED_EXECUTION_FAILED")
        self.assertTrue(result["commit_occurred"])
        self.assertFalse(result["execution_succeeded"])

    def test_execution_action_mismatch_is_blocked(self):
        execution = dict(self.execution)
        execution["action_id"] = "ACT-2"
        result = self.evaluate(execution=execution)
        self.assertIn("EXECUTION_RECEIPT_ACTION_ID_MISMATCH", result["reasons"])

    def test_wrong_execution_destination_is_blocked(self):
        execution = dict(self.execution)
        execution["destination"] = "DEST-2"
        result = self.evaluate(execution=execution)
        self.assertEqual(result["correspondence_standing"], "EXECUTION_CORRESPONDENCE_MISMATCH")

    def test_missing_outcome_evidence_preserves_execution_fact(self):
        result = evaluate_commit_execution_outcome_correspondence(
            prior_commit_result=self.prior, commit_receipt=self.commit,
            execution_receipt=self.execution, outcome_evidence=None,
            expected=self.expected)
        self.assertEqual(result["correspondence_standing"], "EXECUTED_OUTCOME_NOT_ESTABLISHED")
        self.assertTrue(result["historical_facts"]["execution_succeeded"])
        self.assertIsNone(result["intended_outcome_established"])

    def test_intended_and_observed_outcome_divergence_is_explicit(self):
        outcome = dict(self.outcome)
        outcome["observed_outcome"] = "OUTCOME-DIVERGED"
        result = self.evaluate(outcome=outcome)
        self.assertEqual(result["correspondence_standing"], "OUTCOME_DIVERGED")
        self.assertFalse(result["intended_outcome_established"])

    def test_outcome_divergence_does_not_rewrite_commit_or_execution_history(self):
        outcome = dict(self.outcome)
        outcome["observed_outcome"] = "OUTCOME-DIVERGED"
        result = self.evaluate(outcome=outcome)
        self.assertTrue(result["historical_facts"]["commit_occurred"])
        self.assertTrue(result["historical_facts"]["execution_succeeded"])
        self.assertFalse(result["binding_authority_granted"])


if __name__ == "__main__":
    unittest.main()
