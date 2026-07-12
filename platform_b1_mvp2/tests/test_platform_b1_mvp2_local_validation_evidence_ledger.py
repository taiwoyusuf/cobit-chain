import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEDGER_JSON = ROOT / "validation" / "evidence_ledger" / "platform_b1_mvp2_local_validation_evidence_ledger.json"
LEDGER_MD = ROOT / "validation" / "evidence_ledger" / "PLATFORM_B1_MVP2_LOCAL_VALIDATION_EVIDENCE_LEDGER.md"


class PlatformB1MVP2LocalValidationEvidenceLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = json.loads(LEDGER_JSON.read_text(encoding="utf-8-sig"))
        cls.ledger_text = LEDGER_JSON.read_text(encoding="utf-8-sig")
        cls.markdown_text = LEDGER_MD.read_text(encoding="utf-8-sig")

    def test_ledger_identity_is_locked(self):
        self.assertEqual(
            self.ledger["ledger_name"],
            "Platform B1 / MVP2 Local Validation Evidence Ledger",
        )
        self.assertEqual(
            self.ledger["ledger_status"],
            "LOCKED_LOCAL_VALIDATION_EVIDENCE_LEDGER_ONLY",
        )
        self.assertEqual(self.ledger["ledger_version"], "1.0")

    def test_validation_count_is_locked_at_10(self):
        self.assertEqual(self.ledger["validation_count"], 10)
        self.assertEqual(self.ledger["failed_validation_count"], 0)
        self.assertEqual(self.ledger["overall_status"], "PASSED")
        self.assertEqual(
            self.ledger["pass_signal"],
            "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED",
        )

    def test_validated_commands_are_locked(self):
        self.assertEqual(len(self.ledger["validated_commands"]), 10)
        self.assertIn(
            "agentic_ambient_ai_vendor_assurance_passport_validator_cli",
            self.ledger["validated_commands"],
        )
        self.assertIn("status_manifest_validator_cli", self.ledger["validated_commands"])

    def test_assurance_signals_are_preserved(self):
        required_signals = [
            "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED",
            "PLATFORM B1 THREAD D2 LOCAL VALIDATION STATUS MANIFEST VALIDATION PASSED",
            "THREAD D2 RAMAT VISION DISPLAY FIXTURE VALIDATION PASSED",
            "AGENTIC AMBIENT AI VENDOR ASSURANCE PASSPORT VALIDATION PASSED",
            "AI OUTPUT HASHED",
            "HASH VERIFIED",
            "AGENT ACTION NOT ADMISSIBLE",
            "RAMAT VISION DISPLAY READY",
            "PLATFORM B1 DECISION DISPLAYED",
        ]

        for signal in required_signals:
            with self.subTest(signal):
                self.assertIn(signal, self.ledger["assurance_signals"])
                self.assertIn(signal, self.markdown_text)

    def test_doctrine_is_preserved(self):
        required_doctrine = [
            "Platform B1 evaluates.",
            "Thread D2 displays.",
            "RAMAT Vision displays only.",
            "Any device may witness.",
            "Official records remain in source systems.",
            "Humans remain accountable.",
            "Silence is not consent.",
            "AI output is not binding without evidence, authority, review, and accountability.",
        ]

        doctrine_text = " ".join(self.ledger["doctrine"])

        for doctrine in required_doctrine:
            with self.subTest(doctrine):
                self.assertIn(doctrine, doctrine_text)
                self.assertIn(doctrine, self.markdown_text)

    def test_boundaries_are_preserved(self):
        required_boundaries = [
            "No architecture change.",
            "No Platform B v1 change.",
            "No Thread D v1 change.",
            "No MVP3 activation.",
            "No Azure deployment.",
            "No Azure Digital Twins deployment.",
            "No real production system connection.",
            "No PHI.",
            "No company production data.",
            "No regulated action execution.",
            "No binding operational consequence.",
        ]

        boundary_text = " ".join(self.ledger["boundary"])

        for boundary in required_boundaries:
            with self.subTest(boundary):
                self.assertIn(boundary, boundary_text)
                self.assertIn(boundary, self.markdown_text)

    def test_evidence_objects_are_referenced(self):
        required_objects = [
            "platform_b1_local_validation_bundle.py",
            "PLATFORM_B1_LOCAL_VALIDATION_BUNDLE.md",
            "platform_b1_thread_d2_local_validation_status_manifest.json",
            "platform_b1_thread_d2_local_validation_status_manifest_validator.py",
            "platform_b1_agentic_ambient_ai_vendor_assurance_passport.json",
            "platform_b1_agentic_ambient_ai_vendor_assurance_passport_validator.py",
        ]

        for evidence_object in required_objects:
            with self.subTest(evidence_object):
                self.assertIn(evidence_object, self.ledger["evidence_objects_referenced"])
                self.assertIn(evidence_object, self.markdown_text)


if __name__ == "__main__":
    unittest.main()
