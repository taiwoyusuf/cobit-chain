import unittest

from test_accountability_commit_time_revalidation import STEP180, STEP186, SNAPSHOT, binding_for, run


class Step187StaticHardeningTests(unittest.TestCase):
    def test_missing_step186_digest_fails_closed(self):
        b = binding_for(); b.pop("step186_result_digest")
        self.assertIn("COMMIT_BINDING_STEP186_RESULT_DIGEST_MISSING_OR_INVALID", run(binding=b)["reasons"])
        self.assertIn("COMMIT_BINDING_STEP_186_PAYLOAD_DIGEST_MISMATCH", run(binding=b)["reasons"])

    def test_missing_current_snapshot_digest_fails_closed(self):
        b = binding_for(); b.pop("current_snapshot_digest")
        self.assertIn("COMMIT_BINDING_CURRENT_SNAPSHOT_DIGEST_MISSING_OR_INVALID", run(binding=b)["reasons"])
        self.assertIn("COMMIT_BINDING_CURRENT_SNAPSHOT_DIGEST_MISMATCH", run(binding=b)["reasons"])

    def test_missing_source_identity_fails_closed(self):
        b = binding_for(); b.pop("step180_evaluator_blob")
        self.assertIn("COMMIT_BINDING_STEP180_EVALUATOR_BLOB_MISSING_OR_INVALID", run(binding=b)["reasons"])
        self.assertIn("STEP_180_EVALUATOR_IDENTITY_MISMATCH", run(binding=b)["reasons"])

    def test_non_json_upstream_payload_fails_closed_without_exception(self):
        s = dict(STEP186); s["non_json_value"] = {1, 2, 3}
        b = binding_for(STEP186, STEP180, SNAPSHOT)
        r = run(step186=s, binding=b)
        self.assertIn("STEP_186_PAYLOAD_DIGEST_NOT_COMPUTABLE", r["reasons"])
        self.assertEqual(r["commit_time_decision"], "NOT_SUPPORTABLE")

    def test_step186_revalidation_requirement_must_be_explicit(self):
        s = dict(STEP186); s.pop("separate_execution_time_revalidation_required")
        self.assertIn("STEP_186_EXECUTION_REVALIDATION_REQUIREMENT_NOT_ESTABLISHED", run(step186=s)["reasons"])

    def test_step186_history_boundary_violation_blocks(self):
        s = dict(STEP186); s["historical_facts_rewritten"] = True
        self.assertIn("STEP_186_HISTORY_BOUNDARY_INVALID", run(step186=s)["reasons"])

    def test_step180_supportable_change_classification_must_reconcile(self):
        s = dict(STEP180)
        s["changed_dimensions"] = ["criteria_version"]
        s["immaterial_changes"] = []
        self.assertIn("STEP_180_SUPPORTABLE_CHANGE_CLASSIFICATION_INCONSISTENT", run(step180=s)["reasons"])


if __name__ == "__main__":
    unittest.main()
