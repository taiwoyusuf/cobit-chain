import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_SCRIPT = REPO_ROOT / "platform_b1_mvp2" / "validation" / "platform_b1_local_validation_bundle.py"


class PlatformB1LocalValidationBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        completed = subprocess.run(
            [sys.executable, str(BUNDLE_SCRIPT)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        cls.returncode = completed.returncode
        cls.stdout = completed.stdout
        cls.stderr = completed.stderr
        cls.combined = completed.stdout + "\n" + completed.stderr

    def test_bundle_runs_successfully(self):
        self.assertEqual(self.returncode, 0, self.combined)

    def test_bundle_validation_count_is_nine(self):
        self.assertRegex(self.stdout, r'"validation_count":\s*9')
        self.assertRegex(self.stdout, r'"failed_validation_count":\s*0')

    def test_bundle_preserves_validation_commands(self):
        required_commands = [
            "digital_twin_object_model_unit_test",
            "digital_twin_mock_fixtures_unit_test",
            "digital_twin_mock_fixture_validator_cli",
            "digital_twin_mock_fixture_validator_unit_test",
            "result_summary_fixture_validator_cli",
            "result_summary_fixture_validator_unit_test",
            "thread_d2_ramat_vision_display_fixture_validator_cli",
            "thread_d2_ramat_vision_display_fixture_validator_unit_test",
            "status_manifest_validator_cli",
        ]

        for command in required_commands:
            self.assertIn(command, self.stdout)

    def test_bundle_preserves_required_pass_signals(self):
        required_signals = [
            "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED",
            "DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED",
            "LOCAL VALIDATION RESULT SUMMARY FIXTURE VALIDATION PASSED",
            "THREAD D2 RAMAT VISION DISPLAY FIXTURE VALIDATION PASSED",
            "PLATFORM B1 THREAD D2 LOCAL VALIDATION STATUS MANIFEST VALIDATION PASSED",
        ]

        for signal in required_signals:
            self.assertIn(signal, self.combined)

    def test_bundle_preserves_thread_d2_display_signals(self):
        self.assertIn("RAMAT VISION DISPLAY READY", self.combined)
        self.assertIn("PLATFORM B1 DECISION DISPLAYED", self.combined)

    def test_bundle_preserves_non_admissibility_signal(self):
        self.assertIn("AGENT ACTION NOT ADMISSIBLE", self.combined)


if __name__ == "__main__":
    unittest.main()
