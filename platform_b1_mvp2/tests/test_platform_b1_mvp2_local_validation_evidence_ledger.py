import json
import unittest

from platform_b1_mvp2.validation.evidence_ledger.validator import (
    platform_b1_mvp2_local_validation_evidence_ledger_validator as validator,
)


class PlatformB1MVP2LocalValidationEvidenceLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = validator._load_ledger()
        cls.ledger_text = validator.LEDGER_JSON.read_text(encoding="utf-8-sig")
        cls.markdown_text = validator.LEDGER_MD.read_text(encoding="utf-8-sig")

    def test_ledger_status_is_locked(self):
        self.assertEqual(
            self.ledger["ledger_status"],
            "LOCKED_LOCAL_VALIDATION_EVIDENCE_LEDGER_ONLY",
        )

    def test_validation_state_is_11_and_passed(self):
        self.assertEqual(self.ledger["validation_count"], 11)
        self.assertEqual(self.ledger["failed_validation_count"], 0)
        self.assertEqual(self.ledger["overall_status"], "PASSED")
        self.assertEqual(
            self.ledger["pass_signal"],
            "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED",
        )

    def test_validated_commands_are_present(self):
        self.assertEqual(len(self.ledger["validated_commands"]), 11)
        for command_id in validator.REQUIRED_VALIDATED_COMMANDS:
            with self.subTest(command_id):
                self.assertIn(command_id, self.ledger["validated_commands"])
                self.assertIn(command_id, self.markdown_text)

    def test_assurance_signals_are_present(self):
        for signal in validator.REQUIRED_ASSURANCE_SIGNALS:
            with self.subTest(signal):
                self.assertIn(signal, self.ledger["assurance_signals"])
                self.assertIn(signal, self.ledger["assurance_outputs"])
                self.assertIn(signal, self.markdown_text)

    def test_doctrine_is_present(self):
        doctrine_text = " ".join(self.ledger["doctrine"])
        for doctrine in validator.REQUIRED_DOCTRINE:
            with self.subTest(doctrine):
                self.assertIn(doctrine, doctrine_text)
                self.assertIn(doctrine, self.markdown_text)

    def test_boundary_is_present(self):
        boundary_text = " ".join(self.ledger["boundary"])
        for boundary in validator.REQUIRED_BOUNDARY:
            with self.subTest(boundary):
                self.assertIn(boundary, boundary_text)
                self.assertIn(boundary, self.markdown_text)

    def test_evidence_objects_are_present(self):
        for evidence_object in validator.REQUIRED_EVIDENCE_OBJECTS:
            with self.subTest(evidence_object):
                self.assertIn(evidence_object, self.ledger["evidence_objects"])
                self.assertIn(evidence_object, self.markdown_text)


if __name__ == "__main__":
    unittest.main()

