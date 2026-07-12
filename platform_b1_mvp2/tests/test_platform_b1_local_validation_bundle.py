import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"
BUNDLE_PATH = ROOT / "validation" / "platform_b1_local_validation_bundle.py"
BUNDLE_MD = ROOT / "validation" / "PLATFORM_B1_LOCAL_VALIDATION_BUNDLE.md"


def load_bundle_module():
    spec = importlib.util.spec_from_file_location(
        "platform_b1_local_validation_bundle",
        BUNDLE_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PlatformB1LocalValidationBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = load_bundle_module()

    def test_bundle_identity_is_locked(self):
        self.assertEqual(
            self.bundle.BUNDLE_NAME,
            "Platform B1 / MVP2 Local Validation Bundle",
        )
        self.assertEqual(
            self.bundle.BUNDLE_STATUS,
            "LOCKED_LOCAL_VALIDATION_BUNDLE_ONLY",
        )

    def test_commands_are_locked(self):
        command_ids = [command.id for command in self.bundle.COMMANDS]

        self.assertEqual(len(command_ids), 6)
        self.assertIn("digital_twin_object_model_unit_test", command_ids)
        self.assertIn("digital_twin_mock_fixtures_unit_test", command_ids)
        self.assertIn("digital_twin_mock_fixture_validator_cli", command_ids)
        self.assertIn("digital_twin_mock_fixture_validator_unit_test", command_ids)
        self.assertIn("result_summary_fixture_validator_cli", command_ids)
        self.assertIn("result_summary_fixture_validator_unit_test", command_ids)

    def test_assurance_outputs_are_preserved(self):
        outputs = " ".join(self.bundle.ASSURANCE_OUTPUTS)

        self.assertIn("PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED", outputs)
        self.assertIn("DIGITAL TWIN OBJECT MODEL VALIDATED", outputs)
        self.assertIn("DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED", outputs)
        self.assertIn("LOCAL VALIDATION RESULT SUMMARY FIXTURE VALIDATION PASSED", outputs)
        self.assertIn("AI OUTPUT HASHED", outputs)
        self.assertIn("HASH VERIFIED", outputs)
        self.assertIn("AGENT ACTION NOT ADMISSIBLE", outputs)
        self.assertIn("RAMAT VISION DISPLAY READY", outputs)
        self.assertIn("PLATFORM B1 DECISION DISPLAYED", outputs)

    def test_boundary_is_preserved(self):
        boundary = " ".join(self.bundle.BOUNDARY)

        self.assertIn("Local validation bundle only", boundary)
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

    def test_bundle_execution_passes(self):
        report = self.bundle.run_bundle()

        self.assertTrue(report["passed"], report)
        self.assertEqual(report["pass_signal"], "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED")
        self.assertEqual(report["validation_count"], 6)
        self.assertEqual(report["failed_validation_count"], 0)

        command_ids = [result["id"] for result in report["results"]]
        self.assertIn("result_summary_fixture_validator_cli", command_ids)
        self.assertIn("result_summary_fixture_validator_unit_test", command_ids)

    def test_markdown_preserves_bundle_terms(self):
        text = BUNDLE_MD.read_text(encoding="utf-8-sig")

        self.assertIn("LOCKED LOCAL VALIDATION BUNDLE ONLY", text)
        self.assertIn("PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED", text)
        self.assertIn("digital_twin_object_model_unit_test", text)
        self.assertIn("digital_twin_mock_fixtures_unit_test", text)
        self.assertIn("digital_twin_mock_fixture_validator_cli", text)
        self.assertIn("digital_twin_mock_fixture_validator_unit_test", text)
        self.assertIn("result_summary_fixture_validator_cli", text)
        self.assertIn("result_summary_fixture_validator_unit_test", text)
        self.assertIn("LOCAL VALIDATION RESULT SUMMARY FIXTURE VALIDATION PASSED", text)
        self.assertIn("AI OUTPUT HASHED", text)
        self.assertIn("HASH VERIFIED", text)
        self.assertIn("RAMAT VISION DISPLAY READY", text)
        self.assertIn("No product release decision", text)
        self.assertIn("No source-system override", text)


if __name__ == "__main__":
    unittest.main()
