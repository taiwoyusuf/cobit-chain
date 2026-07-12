import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = (
    REPO_ROOT
    / "platform_b1_mvp2"
    / "validation"
    / "status_manifest"
    / "validator"
    / "platform_b1_thread_d2_local_validation_status_manifest_validator.py"
)


def load_validator_module():
    spec = importlib.util.spec_from_file_location(
        "platform_b1_thread_d2_local_validation_status_manifest_validator",
        VALIDATOR_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PlatformB1ThreadD2LocalValidationStatusManifestValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = load_validator_module()
        cls.report = cls.validator.validate_status_manifest()

    def test_validator_identity_is_locked(self):
        self.assertEqual(
            self.report["validator_name"],
            "Platform B1 Thread D2 Local Validation Status Manifest Validator",
        )
        self.assertEqual(
            self.report["validator_status"],
            "LOCKED_LOCAL_VALIDATION_STATUS_MANIFEST_VALIDATOR_ONLY",
        )

    def test_status_manifest_validation_passes(self):
        self.assertTrue(self.report["passed"])
        self.assertEqual(self.report["errors"], [])

    def test_required_validated_commands_are_locked(self):
        commands = self.report["required_validated_commands"]

        self.assertEqual(len(commands), 8)
        self.assertIn("digital_twin_object_model_unit_test", commands)
        self.assertIn("digital_twin_mock_fixtures_unit_test", commands)
        self.assertIn("digital_twin_mock_fixture_validator_cli", commands)
        self.assertIn("digital_twin_mock_fixture_validator_unit_test", commands)
        self.assertIn("result_summary_fixture_validator_cli", commands)
        self.assertIn("result_summary_fixture_validator_unit_test", commands)
        self.assertIn("thread_d2_ramat_vision_display_fixture_validator_cli", commands)
        self.assertIn("thread_d2_ramat_vision_display_fixture_validator_unit_test", commands)

    def test_required_assurance_signals_are_locked(self):
        signals = " ".join(self.report["required_assurance_signals"])

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

    def test_thread_d2_status_requirements_are_locked(self):
        state = self.report["required_thread_d2_status"]

        self.assertEqual(state["display_fixture_status"], "LOCKED_THREAD_D2_DISPLAY_FIXTURE_ONLY")
        self.assertEqual(state["display_validator_status"], "LOCKED_THREAD_D2_DISPLAY_FIXTURE_VALIDATOR_ONLY")
        self.assertEqual(state["ramat_vision_display_status"], "DISPLAY_READY")
        self.assertEqual(state["platform_b1_decision_status"], "DISPLAYED_ONLY")
        self.assertEqual(state["operator_action_status"], "NOT_AUTHORIZED_BY_DISPLAY")
        self.assertEqual(state["quality_unit_status"], "NOT_REPLACED")
        self.assertEqual(state["source_system_status"], "NOT_OVERRIDDEN")

    def test_boundary_mode_preserves_guardrails(self):
        boundary = " ".join(self.report["boundary_mode"])

        self.assertIn("Local validation status manifest validator only", boundary)
        self.assertIn("Local validation evidence only", boundary)
        self.assertIn("No Azure deployment", boundary)
        self.assertIn("No Azure Digital Twins deployment", boundary)
        self.assertIn("No Platform B v1 change", boundary)
        self.assertIn("No Thread D v1 change", boundary)
        self.assertIn("No MVP3 activation", boundary)
        self.assertIn("No real glasses hardware integration", boundary)
        self.assertIn("No real Halo hardware integration", boundary)
        self.assertIn("No product release decision", boundary)
        self.assertIn("No GMP approval decision", boundary)
        self.assertIn("No Quality Unit replacement", boundary)


if __name__ == "__main__":
    unittest.main()
