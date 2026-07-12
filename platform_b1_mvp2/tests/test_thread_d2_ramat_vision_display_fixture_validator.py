import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = (
    REPO_ROOT
    / "platform_b1_mvp2"
    / "thread_d2_ramat_vision_preview"
    / "validator"
    / "thread_d2_ramat_vision_display_fixture_validator.py"
)


def load_validator_module():
    spec = importlib.util.spec_from_file_location(
        "thread_d2_ramat_vision_display_fixture_validator",
        VALIDATOR_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ThreadD2RamatVisionDisplayFixtureValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = load_validator_module()
        cls.report = cls.validator.validate_display_fixture()

    def test_validator_identity_is_locked(self):
        self.assertEqual(
            self.report["validator_name"],
            "Thread D2 RAMAT Vision Display Fixture Validator",
        )
        self.assertEqual(
            self.report["validator_status"],
            "LOCKED_THREAD_D2_DISPLAY_FIXTURE_VALIDATOR_ONLY",
        )

    def test_display_fixture_validation_passes(self):
        self.assertTrue(self.report["passed"])
        self.assertEqual(self.report["errors"], [])

    def test_required_assurance_signals_are_locked(self):
        signals = " ".join(self.report["required_assurance_signals"])

        self.assertIn("PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED", signals)
        self.assertIn("DIGITAL TWIN OBJECT MODEL VALIDATED", signals)
        self.assertIn("DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED", signals)
        self.assertIn("LOCAL VALIDATION RESULT SUMMARY FIXTURE VALIDATION PASSED", signals)
        self.assertIn("AI OUTPUT HASHED", signals)
        self.assertIn("HASH VERIFIED", signals)
        self.assertIn("AGENT ACTION NOT ADMISSIBLE", signals)
        self.assertIn("RAMAT VISION DISPLAY READY", signals)
        self.assertIn("PLATFORM B1 DECISION DISPLAYED", signals)

    def test_required_card_titles_are_locked(self):
        card_titles = " ".join(self.report["required_card_titles"])

        self.assertIn("PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED", card_titles)
        self.assertIn("EVIDENCE INTEGRITY SIGNALS PRESENT", card_titles)
        self.assertIn("AGENT ACTION NOT ADMISSIBLE", card_titles)
        self.assertIn("RAMAT VISION DISPLAYS ONLY", card_titles)

    def test_display_state_requirements_are_locked(self):
        display_state = self.report["required_display_state"]

        self.assertEqual(display_state["thread_d2_display_status"], "PREVIEW_READY")
        self.assertEqual(display_state["ramat_vision_display_status"], "DISPLAY_READY")
        self.assertEqual(display_state["platform_b1_decision_status"], "DISPLAYED_ONLY")
        self.assertEqual(display_state["operator_action_status"], "NOT_AUTHORIZED_BY_DISPLAY")
        self.assertEqual(display_state["quality_unit_status"], "NOT_REPLACED")
        self.assertEqual(display_state["source_system_status"], "NOT_OVERRIDDEN")

    def test_source_validation_summary_requirements_are_locked(self):
        summary = self.report["required_source_validation_summary"]

        self.assertEqual(summary["overall_status"], "PASSED")
        self.assertEqual(summary["validation_count"], 6)
        self.assertEqual(summary["failed_validation_count"], 0)
        self.assertEqual(summary["result_admissibility"], "LOCAL_VALIDATION_SUMMARY_ONLY")
        self.assertEqual(summary["azure_deployment_status"], "NOT_DEPLOYED")
        self.assertEqual(summary["platform_b_v1_impact"], "NONE")
        self.assertEqual(summary["thread_d_v1_impact"], "NONE")
        self.assertEqual(summary["mvp3_activation"], "NONE")

    def test_boundary_mode_preserves_guardrails(self):
        boundary = " ".join(self.report["boundary_mode"])

        self.assertIn("Thread D2 display fixture validator only", boundary)
        self.assertIn("RAMAT Vision preview display only", boundary)
        self.assertIn("No Azure deployment", boundary)
        self.assertIn("No Platform B v1 change", boundary)
        self.assertIn("No Thread D v1 change", boundary)
        self.assertIn("No real glasses hardware integration", boundary)
        self.assertIn("No real Halo hardware integration", boundary)
        self.assertIn("No product release decision", boundary)
        self.assertIn("No GMP approval decision", boundary)
        self.assertIn("No Quality Unit replacement", boundary)


if __name__ == "__main__":
    unittest.main()
