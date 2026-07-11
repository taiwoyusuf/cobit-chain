import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"
RESULT_DIR = ROOT / "validation" / "result_fixtures"
RESULT_JSON = RESULT_DIR / "platform_b1_local_validation_result_summary_fixture.json"
RESULT_MD = RESULT_DIR / "PLATFORM_B1_LOCAL_VALIDATION_RESULT_SUMMARY_FIXTURE.md"


class PlatformB1LocalValidationResultSummaryFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with RESULT_JSON.open("r", encoding="utf-8-sig") as handle:
            cls.fixture = json.load(handle)

    def test_fixture_identity_is_locked(self):
        self.assertEqual(
            self.fixture["fixture_name"],
            "Platform B1 Local Validation Bundle Result Summary Fixture",
        )
        self.assertEqual(
            self.fixture["fixture_status"],
            "LOCKED_RESULT_SUMMARY_FIXTURE_ONLY",
        )
        self.assertEqual(self.fixture["workstream"], "Platform B1 / MVP2")
        self.assertEqual(
            self.fixture["source_bundle"],
            "Platform B1 / MVP2 Local Validation Bundle",
        )

    def test_summary_state_preserves_passed_local_validation(self):
        summary = self.fixture["summary_state"]

        self.assertEqual(summary["overall_status"], "PASSED")
        self.assertEqual(summary["validation_count"], 4)
        self.assertEqual(summary["failed_validation_count"], 0)
        self.assertEqual(summary["result_admissibility"], "LOCAL_VALIDATION_SUMMARY_ONLY")
        self.assertEqual(summary["azure_deployment_status"], "NOT_DEPLOYED")
        self.assertEqual(summary["platform_b_v1_impact"], "NONE")
        self.assertEqual(summary["thread_d_v1_impact"], "NONE")
        self.assertEqual(summary["mvp3_activation"], "NONE")

    def test_validated_commands_are_locked(self):
        command_ids = [command["id"] for command in self.fixture["validated_commands"]]

        self.assertIn("digital_twin_object_model_unit_test", command_ids)
        self.assertIn("digital_twin_mock_fixtures_unit_test", command_ids)
        self.assertIn("digital_twin_mock_fixture_validator_cli", command_ids)
        self.assertIn("digital_twin_mock_fixture_validator_unit_test", command_ids)
        self.assertEqual(len(command_ids), 4)

        for command in self.fixture["validated_commands"]:
            self.assertEqual(command["expected_status"], "PASSED")

    def test_assurance_signals_are_preserved(self):
        signals = " ".join(self.fixture["assurance_signals"])

        self.assertIn("PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED", signals)
        self.assertIn("DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED", signals)
        self.assertIn("AI OUTPUT HASHED", signals)
        self.assertIn("HASH VERIFIED", signals)
        self.assertIn("AGENT ACTION NOT ADMISSIBLE", signals)
        self.assertIn("RAMAT VISION DISPLAY READY", signals)
        self.assertIn("PLATFORM B1 DECISION DISPLAYED", signals)

    def test_display_summary_is_preview_only(self):
        display = self.fixture["display_summary"]

        self.assertEqual(display["thread_d2_display_status"], "PREVIEW_READY")
        self.assertEqual(display["ramat_vision_display_status"], "DISPLAY_READY")
        self.assertIn("local validation bundle passed", display["headline"].lower())
        self.assertIn("local validation summary only", display["quality_message"])
        self.assertIn("not a GMP approval", display["quality_message"])
        self.assertIn("not a", display["quality_message"])
        self.assertIn("Quality Unit replacement", display["quality_message"])

    def test_boundary_is_preserved(self):
        boundary = " ".join(self.fixture["boundary"])

        self.assertIn("Result summary fixture only", boundary)
        self.assertIn("Local validation evidence only", boundary)
        self.assertIn("No Azure deployment", boundary)
        self.assertIn("No Azure Digital Twins deployment", boundary)
        self.assertIn("No Platform B v1 change", boundary)
        self.assertIn("No Thread D v1 change", boundary)
        self.assertIn("No PHI", boundary)
        self.assertIn("No company production data", boundary)
        self.assertIn("No product release decision", boundary)
        self.assertIn("No GMP approval decision", boundary)
        self.assertIn("No source-system override", boundary)
        self.assertIn("No Quality Unit replacement", boundary)
        self.assertIn("Platform B1 evaluates", boundary)
        self.assertIn("Thread D2 displays", boundary)
        self.assertIn("RAMAT Vision displays only", boundary)

    def test_markdown_preserves_result_summary_terms(self):
        text = RESULT_MD.read_text(encoding="utf-8-sig")

        self.assertIn("LOCKED RESULT SUMMARY FIXTURE ONLY", text)
        self.assertIn("PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED", text)
        self.assertIn("DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED", text)
        self.assertIn("AI OUTPUT HASHED", text)
        self.assertIn("HASH VERIFIED", text)
        self.assertIn("RAMAT VISION DISPLAY READY", text)
        self.assertIn("PLATFORM B1 DECISION DISPLAYED", text)
        self.assertIn("No product release decision", text)
        self.assertIn("No source-system override", text)


if __name__ == "__main__":
    unittest.main()
