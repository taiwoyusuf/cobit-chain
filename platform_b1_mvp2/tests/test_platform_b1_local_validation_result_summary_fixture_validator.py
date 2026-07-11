import importlib.util
import sys
import unittest
from copy import deepcopy
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"
VALIDATOR_PATH = (
    ROOT
    / "validation"
    / "result_fixtures"
    / "validator"
    / "result_summary_fixture_validator.py"
)


def load_validator_module():
    spec = importlib.util.spec_from_file_location(
        "result_summary_fixture_validator",
        VALIDATOR_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PlatformB1LocalValidationResultSummaryFixtureValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = load_validator_module()

    def test_validator_module_loads(self):
        self.assertEqual(
            self.validator.VALIDATOR_NAME,
            "Platform B1 Local Validation Result Summary Fixture Validator",
        )
        self.assertEqual(
            self.validator.VALIDATOR_STATUS,
            "LOCKED_RESULT_SUMMARY_FIXTURE_VALIDATOR_ONLY",
        )

    def test_default_result_summary_fixture_passes(self):
        report = self.validator.validate_default_result_summary()

        self.assertTrue(report["passed"])
        self.assertEqual(report["errors"], [])
        self.assertEqual(
            report["fixture"],
            "platform_b1_local_validation_result_summary_fixture.json",
        )

    def test_validator_rejects_missing_ai_output_hashed_signal(self):
        fixture = self.validator.load_result_summary_fixture()
        fixture = deepcopy(fixture)

        fixture["assurance_signals"] = [
            signal
            for signal in fixture["assurance_signals"]
            if signal != "AI OUTPUT HASHED"
        ]

        errors = self.validator.validate_result_summary_fixture(fixture)
        combined = " ".join(errors)

        self.assertIn("AI OUTPUT HASHED", combined)

    def test_validator_rejects_missing_validated_command(self):
        fixture = self.validator.load_result_summary_fixture()
        fixture = deepcopy(fixture)

        fixture["validated_commands"] = [
            command
            for command in fixture["validated_commands"]
            if command["id"] != "digital_twin_mock_fixture_validator_cli"
        ]

        errors = self.validator.validate_result_summary_fixture(fixture)
        combined = " ".join(errors)

        self.assertIn("digital_twin_mock_fixture_validator_cli", combined)

    def test_validator_rejects_failed_summary_state(self):
        fixture = self.validator.load_result_summary_fixture()
        fixture = deepcopy(fixture)

        fixture["summary_state"]["overall_status"] = "FAILED"
        fixture["summary_state"]["failed_validation_count"] = 1

        errors = self.validator.validate_result_summary_fixture(fixture)
        combined = " ".join(errors)

        self.assertIn("summary_state.overall_status must be PASSED", combined)
        self.assertIn("summary_state.failed_validation_count must be 0", combined)

    def test_validator_rejects_non_preview_display_status(self):
        fixture = self.validator.load_result_summary_fixture()
        fixture = deepcopy(fixture)

        fixture["display_summary"]["thread_d2_display_status"] = "PRODUCTION_ACTIVE"
        fixture["display_summary"]["ramat_vision_display_status"] = "APPROVAL_READY"

        errors = self.validator.validate_result_summary_fixture(fixture)
        combined = " ".join(errors)

        self.assertIn("display_summary.thread_d2_display_status must be PREVIEW_READY", combined)
        self.assertIn("display_summary.ramat_vision_display_status must be DISPLAY_READY", combined)

    def test_validator_rejects_missing_no_product_release_boundary(self):
        fixture = self.validator.load_result_summary_fixture()
        fixture = deepcopy(fixture)

        fixture["boundary"] = [
            item
            for item in fixture["boundary"]
            if item != "No product release decision."
        ]

        errors = self.validator.validate_result_summary_fixture(fixture)
        combined = " ".join(errors)

        self.assertIn("No product release decision", combined)

    def test_validator_rejects_quality_unit_replacement(self):
        fixture = self.validator.load_result_summary_fixture()
        fixture = deepcopy(fixture)

        fixture["boundary"] = [
            item
            for item in fixture["boundary"]
            if item != "No Quality Unit replacement."
        ]

        errors = self.validator.validate_result_summary_fixture(fixture)
        combined = " ".join(errors)

        self.assertIn("No Quality Unit replacement", combined)


if __name__ == "__main__":
    unittest.main()
