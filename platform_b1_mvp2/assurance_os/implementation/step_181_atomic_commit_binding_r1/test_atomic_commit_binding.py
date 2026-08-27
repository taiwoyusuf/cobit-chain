import unittest

from atomic_commit_binding import issue_commit_binding_token, verify_atomic_commit


class AtomicCommitBindingTests(unittest.TestCase):
    def setUp(self):
        self.revalidation = {
            "execution_time_decision": "ADMISSIBLE",
            "no_bind_state": "INACTIVE",
        }
        self.snapshot = {
            "object_hash": "OBJ-A",
            "authority_current": True,
            "evidence_digest": "E1",
            "criteria_version": "C1",
            "configuration_hash": "CFG1",
            "environment_context_hash": "ENV1",
        }

    def token(self):
        return issue_commit_binding_token(
            revalidation_result=self.revalidation,
            current_snapshot=self.snapshot,
            action_id="ACT-1",
            transaction_id="TX-1",
            commit_nonce="N-1",
        )

    def verify(self, token=None, snapshot=None, **kwargs):
        return verify_atomic_commit(
            token=token or self.token(),
            commit_snapshot=snapshot or dict(self.snapshot),
            action_id=kwargs.get("action_id", "ACT-1"),
            transaction_id=kwargs.get("transaction_id", "TX-1"),
            commit_nonce=kwargs.get("commit_nonce", "N-1"),
            token_consumed=kwargs.get("token_consumed", False),
        )

    def test_exact_frozen_state_can_reach_commit_route(self):
        result = self.verify()
        self.assertEqual(result["commit_decision"], "COMMIT_ROUTE_ADMISSIBLE")
        self.assertTrue(result["evaluated_to_committed_binding_verified"])

    def test_object_substitution_after_revalidation_is_blocked(self):
        changed = dict(self.snapshot)
        changed["object_hash"] = "OBJ-B"
        result = self.verify(snapshot=changed)
        self.assertEqual(result["commit_decision"], "NOT_ADMISSIBLE")
        self.assertIn("OBJECT_CHANGED_BETWEEN_REVALIDATION_AND_COMMIT", result["reasons"])

    def test_evidence_mutation_after_revalidation_is_blocked(self):
        changed = dict(self.snapshot)
        changed["evidence_digest"] = "E2"
        result = self.verify(snapshot=changed)
        self.assertIn("COMMIT_STATE_CHANGED_AFTER_REVALIDATION", result["reasons"])

    def test_configuration_mutation_after_revalidation_is_blocked(self):
        changed = dict(self.snapshot)
        changed["configuration_hash"] = "CFG2"
        self.assertEqual(self.verify(snapshot=changed)["no_bind_state"], "ACTIVE")

    def test_environment_mutation_after_revalidation_is_blocked(self):
        changed = dict(self.snapshot)
        changed["environment_context_hash"] = "ENV2"
        self.assertEqual(self.verify(snapshot=changed)["commit_decision"], "NOT_ADMISSIBLE")

    def test_authority_withdrawal_after_revalidation_is_blocked(self):
        changed = dict(self.snapshot)
        changed["authority_current"] = False
        self.assertEqual(self.verify(snapshot=changed)["commit_decision"], "NOT_ADMISSIBLE")

    def test_action_substitution_is_blocked(self):
        result = self.verify(action_id="ACT-2")
        self.assertIn("ACTION_CHANGED_AFTER_REVALIDATION", result["reasons"])

    def test_transaction_substitution_is_blocked(self):
        result = self.verify(transaction_id="TX-2")
        self.assertIn("TRANSACTION_CHANGED_AFTER_REVALIDATION", result["reasons"])

    def test_nonce_substitution_is_blocked(self):
        result = self.verify(commit_nonce="N-2")
        self.assertIn("COMMIT_NONCE_MISMATCH", result["reasons"])

    def test_replayed_commit_token_is_blocked(self):
        result = self.verify(token_consumed=True)
        self.assertIn("COMMIT_TOKEN_REPLAY_PROHIBITED", result["reasons"])

    def test_failed_revalidation_cannot_issue_token(self):
        failed = {"execution_time_decision": "NOT_ADMISSIBLE", "no_bind_state": "ACTIVE"}
        token = issue_commit_binding_token(
            revalidation_result=failed,
            current_snapshot=self.snapshot,
            action_id="ACT-1",
            transaction_id="TX-1",
            commit_nonce="N-1",
        )
        self.assertEqual(token["token_state"], "NOT_ISSUED")

    def test_missing_snapshot_dimension_prevents_token_issue(self):
        incomplete = dict(self.snapshot)
        incomplete.pop("criteria_version")
        token = issue_commit_binding_token(
            revalidation_result=self.revalidation,
            current_snapshot=incomplete,
            action_id="ACT-1",
            transaction_id="TX-1",
            commit_nonce="N-1",
        )
        self.assertEqual(token["token_state"], "NOT_ISSUED")


if __name__ == "__main__":
    unittest.main()
