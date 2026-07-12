import json
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
        cls.manifest_text = validator.MANIFEST_PATH.read_text(encoding="utf-8-sig")
        cls.manifest = json.loads(cls.manifest_text)

    def test_validator_identity_is_locked(self):
        self.assertEqual(
            self.result["validator_name"],
            "Platform B1 Thread D2 Local Validation Status Manifest Validator",
        )
        self.assertEqual(
            self.result["validator_status"],
            "LOCKED_LOCAL_VALIDATION_STATUS_MANIFEST_VALIDATOR_ONLY",
        )

    def test_status_manifest_validator_passes(self):
        self.assertTrue(self.result["passed"], self.result["errors"])
        self.assertEqual(self.result["errors"], [])

    def test_status_manifest_reflects_validation_count_10(self):
        self.assertIn('"validation_count": 10', self.manifest_text)
        self.assertIn('"failed_validation_count": 0', self.manifest_text)
        self.assertEqual(self.result["validation_count_expected"], 10)
        self.assertEqual(self.result["failed_validation_count_expected"], 0)

    def test_required_command_ids_are_locked_at_10(self):
        self.assertEqual(len(validator.REQUIRED_VALIDATED_COMMANDS), 10)

        for command_id in validator.REQUIRED_VALIDATED_COMMANDS:
            with self.subTest(command_id):
                self.assertIn(command_id, self.manifest_text)

        self.assertIn(
            "agentic_ambient_ai_vendor_assurance_passport_validator_cli",
            validator.REQUIRED_VALIDATED_COMMANDS,
        )

    def test_required_assurance_signals_include_agentic_ambient_ai_signal(self):
        self.assertIn(
            "AGENTIC AMBIENT AI VENDOR ASSURANCE PASSPORT VALIDATION PASSED",
            validator.REQUIRED_ASSURANCE_SIGNALS,
        )

        for signal in validator.REQUIRED_ASSURANCE_SIGNALS:
            with self.subTest(signal):
                self.assertIn(signal, self.manifest_text)

    def test_thread_d2_boundary_status_is_preserved(self):
        for status_value in validator.REQUIRED_THREAD_D2_STATUS.values():
            with self.subTest(status_value):
                self.assertIn(status_value, self.manifest_text)

    def test_boundary_terms_are_preserved(self):
        required_terms = [
            "No Azure deployment.",
            "No Azure Digital Twins deployment.",
            "No Platform B v1 change.",
            "No Thread D v1 change.",
            "No MVP3 activation.",
            "No PHI.",
            "No company production data.",
            "No regulated action execution.",
            "No binding operational consequence.",
        ]

        for term in required_terms:
            with self.subTest(term):
                self.assertIn(term, self.manifest_text)

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
            "agentic_ambient_ai_vendor_assurance_passport_validator_cli",
            completed.stdout,
        )
        self.assertIn(
            "AGENTIC AMBIENT AI VENDOR ASSURANCE PASSPORT VALIDATION PASSED",
            completed.stdout,
        )


if __name__ == "__main__":
    unittest.main()
