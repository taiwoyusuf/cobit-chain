import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EVALUATOR_DIR = REPO_ROOT / "platform_b1_mvp2" / "evaluators"
MOCK_DATA_DIR = REPO_ROOT / "platform_b1_mvp2" / "mock_data"

sys.path.insert(0, str(EVALUATOR_DIR))

from workflow_dependency_evaluator import evaluate_file, evaluate_workflow_dependency


class WorkflowDependencyEvaluatorTests(unittest.TestCase):
    def test_prakriti_middleware_verified_lis_held_case(self):
        mock_path = MOCK_DATA_DIR / "prakriti_middleware_verified_lis_held.json"
        result = evaluate_file(mock_path)

        self.assertEqual(result["feature_name"], "Workflow Dependency Assurance Lens")
        self.assertEqual(result["status"], "WORKFLOW APPEARS COMPLETE BUT BLOCKED")
        self.assertEqual(result["reason"], "LIS HOLD DETECTED")
        self.assertEqual(result["required_action"], "SECONDARY REVIEW REQUIRED")
        self.assertEqual(result["evidence_state"], "AUDIT EVIDENCE NOT READY")
        self.assertEqual(result["severity"], "red")

        self.assertIn("LIS HOLD DETECTED", result["outputs"])
        self.assertIn("MIDDLEWARE VERIFIED ONLY", result["outputs"])
        self.assertIn("MANDATORY FIELD MISSING", result["outputs"])
        self.assertIn("RESULT RELEASE NOT ADMISSIBLE", result["outputs"])

    def test_clean_workflow_returns_complete(self):
        record = {
            "workflow_id": "wf-clean-001",
            "case_name": "Clean workflow",
            "checks": {
                "lis_status": "RELEASED",
                "middleware_status": "VERIFIED",
                "mandatory_field_status": "COMPLETE",
                "mapping_status": "MATCHED",
                "identity_match_status": "MATCHED",
                "interface_latency_status": "NORMAL",
                "communication_path_status": "AVAILABLE",
                "shift_site_drift_status": "NO DRIFT",
                "manual_entry_risk": "LOW",
                "secondary_review_status": "NOT REQUIRED",
                "audit_evidence_status": "READY"
            },
            "result": {},
            "outputs": [],
            "guardrail": "mock"
        }

        result = evaluate_workflow_dependency(record)

        self.assertEqual(result["status"], "WORKFLOW COMPLETE")
        self.assertEqual(result["reason"], "DEPENDENCY CHAIN READY")
        self.assertEqual(result["required_action"], "NO ACTION REQUIRED")
        self.assertEqual(result["evidence_state"], "AUDIT EVIDENCE READY")
        self.assertEqual(result["severity"], "green")
        self.assertIn("WORKFLOW COMPLETE", result["outputs"])

    def test_mapping_conflict_blocks_workflow(self):
        record = {
            "workflow_id": "wf-map-001",
            "case_name": "Mapping conflict",
            "checks": {
                "lis_status": "READY",
                "middleware_status": "VERIFIED",
                "mandatory_field_status": "COMPLETE",
                "mapping_status": "CONFLICT",
                "identity_match_status": "MATCHED",
                "interface_latency_status": "NORMAL",
                "communication_path_status": "AVAILABLE",
                "shift_site_drift_status": "NO DRIFT",
                "manual_entry_risk": "LOW",
                "secondary_review_status": "REQUIRED",
                "audit_evidence_status": "NOT READY"
            },
            "result": {},
            "outputs": [],
            "guardrail": "mock"
        }

        result = evaluate_workflow_dependency(record)

        self.assertEqual(result["status"], "WORKFLOW APPEARS COMPLETE BUT BLOCKED")
        self.assertEqual(result["reason"], "MAPPING CONFLICT")
        self.assertIn("MAPPING CONFLICT", result["outputs"])
        self.assertIn("RESULT RELEASE NOT ADMISSIBLE", result["outputs"])


if __name__ == "__main__":
    unittest.main()
