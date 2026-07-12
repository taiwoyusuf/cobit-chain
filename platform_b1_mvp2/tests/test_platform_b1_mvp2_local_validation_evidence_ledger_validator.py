import subprocess
import sys
import unittest
from pathlib import Path

from platform_b1_mvp2.validation.evidence_ledger.validator import (
    platform_b1_mvp2_local_validation_evidence_ledger_validator as validator,
)


class PlatformB1MVP2LocalValidationEvidenceLedgerValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = validator.validate_evidence_ledger()
        cls.ledger = validator._load_ledger()
        cls.ledger_text = validator.LEDGER_JSON.read_text(encoding="utf-8-sig")
        cls.markdown_text = validator.LEDGER_MD.read_text(encoding="utf-8-sig")

    def test_validator_identity_is_locked(self):
        self.assertEqual(
            self.result["validator_name"],
            "Platform B1 / MVP2 Local Validation Evidence Ledger Validator",
        )
        self.assertEqual(
            self.result["validator_status"],
            "LOCKED_LOCAL_VALIDATION_EVIDENCE_LEDGER_VALIDATOR_ONLY",
        )

    def test_validator_passes(self):
        self.assertTrue(self.result["passed"], self.result["errors"])
        self.assertEqual(self.result["errors"], [])

    def test_validation_count_is_locked_at_11(self):
        self.assertEqual(self.ledger["validation_count"], 11)
        self.assertEqual(self.ledger["failed_validation_count"], 0)
        self.assertEqual(self.ledger["overall_status"], "PASSED")
        self.assertEqual(self.result["validation_count_expected"], 11)
        self.assertEqual(self.result["failed_validation_count_expected"], 0)

    def test_validated_commands_are_preserved(self):
        self.assertEqual(len(self.ledger["validated_commands"]), 11)
        for command_id in validator.REQUIRED_VALIDATED_COMMANDS:
            with self.subTest(command_id):
                self.assertIn(command_id, self.ledger["validated_commands"])
                self.assertIn(command_id, self.markdown_text)

    def test_assurance_signals_are_preserved(self):
        for signal in validator.REQUIRED_ASSURANCE_SIGNALS:
            with self.subTest(signal):
                self.assertIn(signal, self.ledger["assurance_signals"])
                self.assertIn(signal, self.ledger["assurance_outputs"])
                self.assertIn(signal, self.markdown_text)

    def test_doctrine_is_preserved(self):
        doctrine_text = " ".join(self.ledger["doctrine"])
        for doctrine in validator.REQUIRED_DOCTRINE:
            with self.subTest(doctrine):
                self.assertIn(doctrine, doctrine_text)
                self.assertIn(doctrine, self.markdown_text)

    def test_boundary_is_preserved(self):
        boundary_text = " ".join(self.ledger["boundary"])
        for boundary in validator.REQUIRED_BOUNDARY:
            with self.subTest(boundary):
                self.assertIn(boundary, boundary_text)
                self.assertIn(boundary, self.markdown_text)

    def test_evidence_objects_are_preserved(self):
        for evidence_object in validator.REQUIRED_EVIDENCE_OBJECTS:
            with self.subTest(evidence_object):
                self.assertIn(evidence_object, self.ledger["evidence_objects"])
                self.assertIn(evidence_object, self.markdown_text)

    def test_validator_cli_emits_pass_signal(self):
        completed = subprocess.run(
            [sys.executable, str(Path(validator.__file__).resolve())],
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn(
            "PLATFORM B1 LOCAL VALIDATION EVIDENCE LEDGER VALIDATION PASSED",
            completed.stdout,
        )
        self.assertIn("local_validation_evidence_ledger_validator_cli", completed.stdout)


if __name__ == "__main__":
    unittest.main()

