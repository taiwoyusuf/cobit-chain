import subprocess
import sys
import unittest
from pathlib import Path

from platform_b1_mvp2.validation.status_manifest.validator import (
    platform_b1_thread_d2_local_validation_status_manifest_validator as validator,
)


class PlatformB1ThreadD2LocalValidationStatusManifestValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = validator.validate_status_manifest()
        cls.manifest = validator._load_manifest()
        cls.manifest_text = validator.MANIFEST_JSON.read_text(encoding="utf-8-sig")

    def test_validator_identity_is_locked(self):
        self.assertEqual(
            self.result["validator_name"],
            "Platform B1 Thread D2 Local Validation Status Manifest Validator",
        )
        self.assertEqual(
            self.result["validator_status"],
            "LOCKED_LOCAL_VALIDATION_STATUS_MANIFEST_VALIDATOR_ONLY",
        )

    def test_validator_passes(self):
        self.assertTrue(self.result["passed"], self.result["errors"])
        self.assertEqual(self.result["errors"], [])

    def test_validation_count_is_locked_at_11(self):
        self.assertEqual(self.manifest["validation_count"], 11)
        self.assertEqual(self.manifest["failed_validation_count"], 0)
        self.assertEqual(self.manifest["overall_status"], "PASSED")
        self.assertEqual(self.result["validation_count_expected"], 11)
        self.assertEqual(self.result["failed_validation_count_expected"], 0)

    def test_validated_commands_are_locked(self):
        self.assertEqual(len(self.manifest["validated_commands"]), 11)
        for command_id in validator.REQUIRED_VALIDATED_COMMANDS:
            with self.subTest(command_id):
                self.assertIn(command_id, self.manifest["validated_commands"])
                self.assertIn(command_id, self.manifest_text)

    def test_assurance_signal_fields_are_normalized(self):
        self.assertIn("assurance_signals", self.manifest)
        self.assertIn("assurance_outputs", self.manifest)
        for signal in validator.REQUIRED_ASSURANCE_SIGNALS:
            with self.subTest(signal):
                self.assertIn(signal, self.manifest["assurance_signals"])
                self.assertIn(signal, self.manifest["assurance_outputs"])
                self.assertIn(signal, self.manifest_text)

    def test_evidence_ledger_validator_command_and_signal_are_present(self):
        self.assertIn(
            "local_validation_evidence_ledger_validator_cli",
            self.manifest["validated_commands"],
        )
        self.assertIn(
            "PLATFORM B1 LOCAL VALIDATION EVIDENCE LEDGER VALIDATION PASSED",
            self.manifest["assurance_signals"],
        )
        self.assertIn(
            "PLATFORM B1 LOCAL VALIDATION EVIDENCE LEDGER VALIDATION PASSED",
            self.manifest["assurance_outputs"],
        )

    def test_thread_d2_status_is_preserved(self):
        for key, expected_value in validator.REQUIRED_THREAD_D2_STATUS.items():
            with self.subTest(key):
                self.assertEqual(self.manifest["thread_d2_status"][key], expected_value)

    def test_boundary_is_preserved(self):
        boundary_text = " ".join(
            self.manifest.get("boundary_mode", []) + self.manifest.get("boundary", [])
        )
        for boundary in validator.REQUIRED_BOUNDARY:
            with self.subTest(boundary):
                self.assertIn(boundary, boundary_text)

    def test_validator_cli_emits_pass_signal(self):
        completed = subprocess.run(
            [sys.executable, str(Path(validator.__file__).resolve())],
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn(
            "PLATFORM B1 THREAD D2 LOCAL VALIDATION STATUS MANIFEST VALIDATION PASSED",
            completed.stdout,
        )
        self.assertIn(
            "local_validation_evidence_ledger_validator_cli",
            completed.stdout,
        )
        self.assertIn(
            "PLATFORM B1 LOCAL VALIDATION EVIDENCE LEDGER VALIDATION PASSED",
            completed.stdout,
        )


if __name__ == "__main__":
    unittest.main()

