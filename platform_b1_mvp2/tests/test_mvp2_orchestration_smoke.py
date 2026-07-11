import unittest

from platform_b1_mvp2.tests.run_mvp2_orchestration_smoke import run_orchestration_smoke


class MVP2OrchestrationSmokeTests(unittest.TestCase):
    def test_orchestration_smoke_passes(self):
        result = run_orchestration_smoke()

        self.assertEqual(result["smoke_status"], "PASS")
        self.assertEqual(result["feature_name"], "Workflow Dependency Assurance Lens")
        self.assertEqual(result["feature_id"], "workflow_dependency_assurance_lens")
        self.assertEqual(result["primary_case"], "Middleware Verified / LIS Held")

    def test_orchestration_preserves_core_outputs(self):
        result = run_orchestration_smoke()

        required_outputs = [
            "WORKFLOW APPEARS COMPLETE BUT BLOCKED",
            "LIS HOLD DETECTED",
            "MIDDLEWARE VERIFIED ONLY",
            "MANDATORY FIELD MISSING",
            "SECONDARY REVIEW REQUIRED",
            "RESULT RELEASE NOT ADMISSIBLE",
        ]

        for output in required_outputs:
            self.assertIn(output, result["outputs"])

    def test_orchestration_aligns_evaluator_to_d2_fixture(self):
        result = run_orchestration_smoke()

        self.assertEqual(result["headline"], "WORKFLOW APPEARS COMPLETE BUT BLOCKED")
        self.assertEqual(result["reason"], "LIS HOLD DETECTED")
        self.assertEqual(result["required_action"], "SECONDARY REVIEW REQUIRED")
        self.assertEqual(result["evidence_state"], "AUDIT EVIDENCE NOT READY")
        self.assertEqual(result["severity"], "red")

    def test_orchestration_guardrails_are_present(self):
        result = run_orchestration_smoke()
        boundary_text = " ".join(result["boundary"])

        self.assertIn("No Azure deployment", boundary_text)
        self.assertIn("No Platform B v1 change", boundary_text)
        self.assertIn("No Thread D v1 change", boundary_text)
        self.assertIn("Official records remain in source systems", boundary_text)
        self.assertIn("Glasses do not release results", boundary_text)


if __name__ == "__main__":
    unittest.main()
