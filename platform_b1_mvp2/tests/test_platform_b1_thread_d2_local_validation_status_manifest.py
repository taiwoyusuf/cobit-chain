import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"
MANIFEST_JSON = (
    ROOT
    / "validation"
    / "status_manifest"
    / "platform_b1_thread_d2_local_validation_status_manifest.json"
)
MANIFEST_MD = (
    ROOT
    / "validation"
    / "status_manifest"
    / "PLATFORM_B1_THREAD_D2_LOCAL_VALIDATION_STATUS_MANIFEST.md"
)


class PlatformB1ThreadD2LocalValidationStatusManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST_JSON.read_text(encoding="utf-8-sig"))
        cls.markdown = MANIFEST_MD.read_text(encoding="utf-8-sig")

    def test_manifest_identity_is_locked(self):
        self.assertEqual(
            self.manifest["manifest_name"],
            "Platform B1 / Thread D2 Local Validation Status Manifest",
        )
        self.assertEqual(
            self.manifest["manifest_status"],
            "LOCKED_LOCAL_VALIDATION_STATUS_MANIFEST_ONLY",
        )
        self.assertEqual(
            self.manifest["manifest_type"],
            "LOCAL_VALIDATION_STATUS_SNAPSHOT",
        )

    def test_validation_status_is_locked(self):
        self.assertEqual(self.manifest["overall_status"], "PASSED")
        self.assertEqual(self.manifest["validation_count"], 8)
        self.assertEqual(self.manifest["failed_validation_count"], 0)
        self.assertEqual(self.manifest["azure_deployment_status"], "NOT_DEPLOYED")
        self.assertEqual(self.manifest["azure_digital_twins_status"], "NOT_DEPLOYED")
        self.assertEqual(self.manifest["platform_b_v1_impact"], "NONE")
        self.assertEqual(self.manifest["thread_d_v1_impact"], "NONE")
        self.assertEqual(self.manifest["mvp3_activation"], "NONE")

    def test_workstreams_are_preserved(self):
        workstreams = " ".join(self.manifest["workstreams"])

        self.assertIn("Platform B1 / MVP2", workstreams)
        self.assertIn("Thread D2 — RAMAT Vision Advanced Assurance Preview", workstreams)

    def test_validated_commands_are_locked(self):
        commands = self.manifest["validated_commands"]

        self.assertEqual(len(commands), 8)
        self.assertIn("digital_twin_object_model_unit_test", commands)
        self.assertIn("digital_twin_mock_fixtures_unit_test", commands)
        self.assertIn("digital_twin_mock_fixture_validator_cli", commands)
        self.assertIn("digital_twin_mock_fixture_validator_unit_test", commands)
        self.assertIn("result_summary_fixture_validator_cli", commands)
        self.assertIn("result_summary_fixture_validator_unit_test", commands)
        self.assertIn("thread_d2_ramat_vision_display_fixture_validator_cli", commands)
        self.assertIn("thread_d2_ramat_vision_display_fixture_validator_unit_test", commands)

    def test_required_assurance_signals_are_preserved(self):
        signals = " ".join(self.manifest["required_assurance_signals"])

        self.assertIn("PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED", signals)
        self.assertIn("DIGITAL TWIN OBJECT MODEL VALIDATED", signals)
        self.assertIn("DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED", signals)
        self.assertIn("LOCAL VALIDATION RESULT SUMMARY FIXTURE VALIDATION PASSED", signals)
        self.assertIn("THREAD D2 RAMAT VISION DISPLAY FIXTURE VALIDATION PASSED", signals)
        self.assertIn("AI OUTPUT HASHED", signals)
        self.assertIn("HASH VERIFIED", signals)
        self.assertIn("AGENT ACTION NOT ADMISSIBLE", signals)
        self.assertIn("RAMAT VISION DISPLAY READY", signals)
        self.assertIn("PLATFORM B1 DECISION DISPLAYED", signals)

    def test_thread_d2_state_is_non_authoritative(self):
        state = self.manifest["thread_d2_status"]

        self.assertEqual(state["display_fixture_status"], "LOCKED_THREAD_D2_DISPLAY_FIXTURE_ONLY")
        self.assertEqual(state["display_validator_status"], "LOCKED_THREAD_D2_DISPLAY_FIXTURE_VALIDATOR_ONLY")
        self.assertEqual(state["ramat_vision_display_status"], "DISPLAY_READY")
        self.assertEqual(state["platform_b1_decision_status"], "DISPLAYED_ONLY")
        self.assertEqual(state["operator_action_status"], "NOT_AUTHORIZED_BY_DISPLAY")
        self.assertEqual(state["quality_unit_status"], "NOT_REPLACED")
        self.assertEqual(state["source_system_status"], "NOT_OVERRIDDEN")

    def test_boundary_is_preserved(self):
        boundary = " ".join(self.manifest["boundary"])

        self.assertIn("Local validation status manifest only", boundary)
        self.assertIn("No Azure deployment", boundary)
        self.assertIn("No Azure Digital Twins deployment", boundary)
        self.assertIn("No Platform B v1 change", boundary)
        self.assertIn("No Thread D v1 change", boundary)
        self.assertIn("No MVP3 activation", boundary)
        self.assertIn("No real production system connection", boundary)
        self.assertIn("No real glasses hardware integration", boundary)
        self.assertIn("No real Halo hardware integration", boundary)
        self.assertIn("No PHI", boundary)
        self.assertIn("No company production data", boundary)
        self.assertIn("No product release decision", boundary)
        self.assertIn("No GMP approval decision", boundary)
        self.assertIn("No source-system override", boundary)
        self.assertIn("No Quality Unit replacement", boundary)
        self.assertIn("No regulated action execution", boundary)
        self.assertIn("No binding operational consequence", boundary)

    def test_markdown_preserves_status_terms(self):
        text = self.markdown

        self.assertIn("LOCKED LOCAL VALIDATION STATUS MANIFEST ONLY", text)
        self.assertIn("LOCAL_VALIDATION_STATUS_SNAPSHOT", text)
        self.assertIn("Validation count: 8", text)
        self.assertIn("Failed validation count: 0", text)
        self.assertIn("THREAD D2 RAMAT VISION DISPLAY FIXTURE VALIDATION PASSED", text)
        self.assertIn("RAMAT VISION DISPLAY READY", text)
        self.assertIn("PLATFORM B1 DECISION DISPLAYED", text)
        self.assertIn("No Azure deployment", text)
        self.assertIn("No Platform B v1 change", text)
        self.assertIn("No Thread D v1 change", text)
        self.assertIn("No real Halo hardware integration", text)
        self.assertIn("No Quality Unit replacement", text)


if __name__ == "__main__":
    unittest.main()
