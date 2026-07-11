import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CLOSEOUT_DIR = REPO_ROOT / "platform_b1_mvp2" / "closeout"


class WorkflowDependencyChainCloseoutTests(unittest.TestCase):
    def test_closeout_json_parses(self):
        closeout_path = CLOSEOUT_DIR / "workflow_dependency_chain_closeout.json"

        with closeout_path.open("r", encoding="utf-8-sig") as handle:
            closeout = json.load(handle)

        self.assertEqual(
            closeout["closeout_name"],
            "Platform B1 MVP2 Workflow Dependency Assurance Chain Closeout",
        )
        self.assertEqual(closeout["closeout_status"], "VALIDATED_LOCAL_MVP2_CHAIN")
        self.assertEqual(closeout["feature_id"], "workflow_dependency_assurance_lens")
        self.assertEqual(closeout["primary_case"], "Middleware Verified / LIS Held")

    def test_closeout_preserves_chain_and_outputs(self):
        closeout_path = CLOSEOUT_DIR / "workflow_dependency_chain_closeout.json"

        with closeout_path.open("r", encoding="utf-8-sig") as handle:
            closeout = json.load(handle)

        self.assertIn("mock data", closeout["validated_chain"])
        self.assertIn("evaluator", closeout["validated_chain"])
        self.assertIn("Thread D2 display fixture", closeout["validated_chain"])

        required_outputs = [
            "WORKFLOW APPEARS COMPLETE BUT BLOCKED",
            "LIS HOLD DETECTED",
            "MIDDLEWARE VERIFIED ONLY",
            "MANDATORY FIELD MISSING",
            "SECONDARY REVIEW REQUIRED",
            "RESULT RELEASE NOT ADMISSIBLE",
            "AUDIT EVIDENCE NOT READY",
        ]

        for output in required_outputs:
            self.assertIn(output, closeout["primary_outputs"])

    def test_closeout_boundary(self):
        closeout_path = CLOSEOUT_DIR / "workflow_dependency_chain_closeout.json"

        with closeout_path.open("r", encoding="utf-8-sig") as handle:
            closeout = json.load(handle)

        boundary = closeout["boundary"]

        self.assertTrue(boundary["local_closeout_only"])
        self.assertFalse(boundary["platform_b_v1_change"])
        self.assertFalse(boundary["thread_d_v1_change"])
        self.assertFalse(boundary["azure_deployment"])
        self.assertFalse(boundary["mvp3_activation"])
        self.assertFalse(boundary["real_phi"])
        self.assertFalse(boundary["real_gmp_production_data"])

    def test_closeout_artifacts_exist(self):
        closeout_path = CLOSEOUT_DIR / "workflow_dependency_chain_closeout.json"

        with closeout_path.open("r", encoding="utf-8-sig") as handle:
            closeout = json.load(handle)

        for relative_path in closeout["validated_artifacts"]:
            artifact_path = REPO_ROOT / relative_path
            self.assertTrue(artifact_path.exists(), f"Missing artifact: {relative_path}")


if __name__ == "__main__":
    unittest.main()
