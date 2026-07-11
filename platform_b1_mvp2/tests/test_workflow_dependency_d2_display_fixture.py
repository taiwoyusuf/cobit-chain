import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UI_CONTRACTS_DIR = REPO_ROOT / "platform_b1_mvp2" / "ui_contracts"


class WorkflowDependencyD2DisplayFixtureTests(unittest.TestCase):
    def test_d2_fixture_contains_required_display_fields(self):
        fixture_path = UI_CONTRACTS_DIR / "workflow_dependency_d2_display_fixture.json"

        with fixture_path.open("r", encoding="utf-8-sig") as handle:
            fixture = json.load(handle)

        required_fields = [
            "card_id",
            "feature_name",
            "display_mode",
            "headline",
            "reason",
            "required_action",
            "evidence_state",
            "severity",
            "badge",
            "outputs",
            "context",
            "guardrail",
        ]

        for field in required_fields:
            self.assertIn(field, fixture)

    def test_d2_fixture_matches_prakriti_blocked_workflow_output(self):
        fixture_path = UI_CONTRACTS_DIR / "workflow_dependency_d2_display_fixture.json"

        with fixture_path.open("r", encoding="utf-8-sig") as handle:
            fixture = json.load(handle)

        self.assertEqual(fixture["feature_name"], "Workflow Dependency Assurance Lens")
        self.assertEqual(fixture["case_name"], "Middleware Verified / LIS Held")
        self.assertEqual(fixture["headline"], "WORKFLOW APPEARS COMPLETE BUT BLOCKED")
        self.assertEqual(fixture["reason"], "LIS HOLD DETECTED")
        self.assertEqual(fixture["required_action"], "SECONDARY REVIEW REQUIRED")
        self.assertEqual(fixture["evidence_state"], "AUDIT EVIDENCE NOT READY")
        self.assertEqual(fixture["severity"], "red")
        self.assertEqual(fixture["badge"], "MVP2 PREVIEW")

        self.assertIn("MIDDLEWARE VERIFIED ONLY", fixture["outputs"])
        self.assertIn("MANDATORY FIELD MISSING", fixture["outputs"])
        self.assertIn("RESULT RELEASE NOT ADMISSIBLE", fixture["outputs"])

    def test_d2_fixture_preserves_display_guardrail(self):
        fixture_path = UI_CONTRACTS_DIR / "workflow_dependency_d2_display_fixture.json"

        with fixture_path.open("r", encoding="utf-8-sig") as handle:
            fixture = json.load(handle)

        guardrail = fixture["guardrail"]

        self.assertIn("Thread D2 displays Platform B1 output", guardrail)
        self.assertIn("Thread D2 does not release results", guardrail)
        self.assertIn("Official records remain in source systems", guardrail)


if __name__ == "__main__":
    unittest.main()
