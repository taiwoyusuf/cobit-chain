import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"
BUNDLE_PATH = ROOT / "validation" / "platform_b1_local_validation_bundle.py"


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

    def test_bundle_module_loads(self):
        self.assertEqual(
            self.bundle.BUNDLE_NAME,
            "Platform B1 / MVP2 Local Validation Bundle",
        )
        self.assertEqual(
            self.bundle.BUNDLE_STATUS,
            "LOCKED_LOCAL_VALIDATION_BUNDLE_ONLY",
        )

    def test_validation_commands_are_locked(self):
        command_ids = [command["id"] for command in self.bundle.VALIDATION_COMMANDS]

        self.assertIn("digital_twin_object_model_unit_test", command_ids)
        self.assertIn("digital_twin_mock_fixtures_unit_test", command_ids)
        self.assertIn("digital_twin_mock_fixture_validator_cli", command_ids)
        self.assertIn("digital_twin_mock_fixture_validator_unit_test", command_ids)
        self.assertEqual(len(command_ids), 4)

    def test_boundary_is_preserved(self):
        boundary = " ".join(self.bundle.BOUNDARY)

        self.assertIn("Local validation bundle only", boundary)
        self.assertIn("No Azure deployment", boundary)
        self.assertIn("No Azure Digital Twins deployment", boundary)
        self.assertIn("No Platform B v1 change", boundary)
        self.assertIn("No Thread D v1 change", boundary)
        self.assertIn("No PHI", boundary)
        self.assertIn("No company production data", boundary)
        self.assertIn("No product release decision", boundary)
        self.assertIn("No source-system override", boundary)
        self.assertIn("No Quality Unit replacement", boundary)
        self.assertIn("Platform B1 evaluates", boundary)
        self.assertIn("Thread D2 displays", boundary)
        self.assertIn("RAMAT Vision displays only", boundary)

    def test_bundle_runs_successfully(self):
        report = self.bundle.run_validation_bundle()

        self.assertTrue(report["passed"])
        self.assertEqual(report["validation_count"], 4)

        result_ids = [result["id"] for result in report["results"]]
        self.assertIn("digital_twin_object_model_unit_test", result_ids)
        self.assertIn("digital_twin_mock_fixtures_unit_test", result_ids)
        self.assertIn("digital_twin_mock_fixture_validator_cli", result_ids)
        self.assertIn("digital_twin_mock_fixture_validator_unit_test", result_ids)

        for result in report["results"]:
            self.assertTrue(result["passed"])
            self.assertEqual(result["returncode"], 0)


if __name__ == "__main__":
    unittest.main()

