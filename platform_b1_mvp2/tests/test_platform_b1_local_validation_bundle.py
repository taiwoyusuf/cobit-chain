import importlib.util
import json
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_PATH = (
    REPO_ROOT
    / "platform_b1_mvp2"
    / "validation"
    / "platform_b1_local_validation_bundle.py"
)


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
        cls.report = cls.bundle.run_bundle()

    def test_bundle_identity_is_locked(self):
        self.assertEqual(
            self.bundle.BUNDLE_NAME,
            "Platform B1 / MVP2 Local Validation Bundle",
        )
        self.assertEqual(
            self.bundle.BUNDLE_STATUS,
            "LOCKED_LOCAL_VALIDATION_BUNDLE_ONLY",
        )
        self.assertEqual(
            self.bundle.PASS_SIGNAL,
            "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED",
        )

    def test_bundle_has_eight_locked_commands(self):
        command_ids = [command.id for command in self.bundle.COMMANDS]

        self.assertEqual(len(command_ids), 8)
        self.assertEqual(
            command_ids,
            [
                "digital_twin_object_model_unit_test",
                "digital_twin_mock_fixtures_unit_test",
                "digital_twin_mock_fixture_validator_cli",
                "digital_twin_mock_fixture_validator_unit_test",
                "result_summary_fixture_validator_cli",
                "result_summary_fixture_validator_unit_test",
                "thread_d2_ramat_vision_display_fixture_validator_cli",
                "thread_d2_ramat_vision_display_fixture_validator_unit_test",
            ],
        )

    def test_validator_paths_are_correct(self):
        commands = {
            command.id: " ".join(command.command)
            for command in self.bundle.COMMANDS
        }

        self.assertIn(
            "regulated_operations_digital_twin",
            commands["digital_twin_mock_fixture_validator_cli"],
        )
        self.assertIn(
            "digital_twin_mock_fixture_validator.py",
            commands["digital_twin_mock_fixture_validator_cli"],
        )
        self.assertNotIn(
            "validation digital_twin mock_fixtures",
            commands["digital_twin_mock_fixture_validator_cli"].replace("\\", " "),
        )

        self.assertIn(
            "result_summary_fixture_validator.py",
            commands["result_summary_fixture_validator_cli"],
        )

        self.assertIn(
            "thread_d2_ramat_vision_display_fixture_validator.py",
            commands["thread_d2_ramat_vision_display_fixture_validator_cli"],
        )

    def test_assurance_outputs_are_preserved(self):
        outputs = " ".join(self.bundle.ASSURANCE_OUTPUTS)

        self.assertIn("PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED", outputs)
        self.assertIn("DIGITAL TWIN OBJECT MODEL VALIDATED", outputs)
        self.assertIn("DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED", outputs)
        self.assertIn("LOCAL VALIDATION RESULT SUMMARY FIXTURE VALIDATION PASSED", outputs)
        self.assertIn("THREAD D2 RAMAT VISION DISPLAY FIXTURE VALIDATION PASSED", outputs)
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
        self.assertIn("No MVP3 activation", boundary)
        self.assertIn("No real production system connection", boundary)
        self.assertIn("No PHI", boundary)
        self.assertIn("No company production data", boundary)
        self.assertIn("No real glasses hardware integration", boundary)
        self.assertIn("No real Halo hardware integration", boundary)
        self.assertIn("No product release decision", boundary)
        self.assertIn("No GMP approval decision", boundary)
        self.assertIn("No source-system override", boundary)
        self.assertIn("No Quality Unit replacement", boundary)
        self.assertIn("Platform B1 evaluates", boundary)
        self.assertIn("Thread D2 displays", boundary)
        self.assertIn("RAMAT Vision displays only", boundary)

    def test_run_bundle_passes(self):
        self.assertTrue(self.report["passed"])
        self.assertEqual(self.report["pass_signal"], "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED")
        self.assertEqual(self.report["validation_count"], 8)
        self.assertEqual(self.report["failed_validation_count"], 0)

        result_ids = [result["id"] for result in self.report["results"]]
        self.assertIn("thread_d2_ramat_vision_display_fixture_validator_cli", result_ids)
        self.assertIn("thread_d2_ramat_vision_display_fixture_validator_unit_test", result_ids)

        for result in self.report["results"]:
            self.assertTrue(result["passed"], result)

    def test_bundle_report_is_json_serializable(self):
        json.dumps(self.report)


if __name__ == "__main__":
    unittest.main()
