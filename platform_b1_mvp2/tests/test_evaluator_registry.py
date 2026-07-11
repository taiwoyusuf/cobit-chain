import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EVALUATOR_DIR = REPO_ROOT / "platform_b1_mvp2" / "evaluators"

sys.path.insert(0, str(EVALUATOR_DIR))

from evaluator_registry import get_workflow_dependency_evaluator, list_evaluators, load_registry


class EvaluatorRegistryTests(unittest.TestCase):
    def test_registry_json_parses(self):
        registry_path = EVALUATOR_DIR / "evaluator_registry.json"

        with registry_path.open("r", encoding="utf-8-sig") as handle:
            registry = json.load(handle)

        self.assertEqual(registry["registry_name"], "Platform B1 MVP2 Evaluator Registry")
        self.assertEqual(registry["registry_status"], "MVP2 LOCAL PREVIEW")
        self.assertIn("evaluators", registry)
        self.assertGreaterEqual(len(registry["evaluators"]), 1)

    def test_workflow_dependency_registry_entry(self):
        evaluator = get_workflow_dependency_evaluator()

        self.assertEqual(evaluator["feature_id"], "workflow_dependency_assurance_lens")
        self.assertEqual(evaluator["feature_name"], "Workflow Dependency Assurance Lens")
        self.assertEqual(evaluator["depth"], "deep")
        self.assertEqual(evaluator["status"], "ACTIVE_MVP2_LOCAL")
        self.assertEqual(evaluator["primary_case"], "Middleware Verified / LIS Held")

        self.assertIn("workflow_dependency_evaluator.py", evaluator["evaluator_module"])
        self.assertIn("workflow_dependency_d2_display_fixture.json", evaluator["d2_display_fixture"])

    def test_registry_preserves_required_outputs_and_guardrail(self):
        evaluator = get_workflow_dependency_evaluator()

        required_outputs = [
            "WORKFLOW APPEARS COMPLETE BUT BLOCKED",
            "LIS HOLD DETECTED",
            "MIDDLEWARE VERIFIED ONLY",
            "MANDATORY FIELD MISSING",
            "SECONDARY REVIEW REQUIRED",
            "RESULT RELEASE NOT ADMISSIBLE",
        ]

        for output in required_outputs:
            self.assertIn(output, evaluator["primary_outputs"])

        self.assertIn("Platform B1 evaluates", evaluator["guardrail"])
        self.assertIn("Thread D2 displays", evaluator["guardrail"])
        self.assertIn("Official records remain in source systems", evaluator["guardrail"])
        self.assertIn("Glasses do not release results", evaluator["guardrail"])

    def test_list_evaluators(self):
        registry = load_registry()
        evaluators = list_evaluators(registry)

        self.assertEqual(len(evaluators), 1)
        self.assertEqual(evaluators[0]["feature_id"], "workflow_dependency_assurance_lens")


if __name__ == "__main__":
    unittest.main()
