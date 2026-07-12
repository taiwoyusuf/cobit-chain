import unittest
from pathlib import Path

from platform_b1_mvp2.research_watch.validator.platform_b1_agentic_ambient_ai_vendor_assurance_passport_validator import (
    EXPECTED_AUDIT_TRAIL,
    EXPECTED_DOMAINS,
    EXPECTED_OUTPUTS,
    PASS_SIGNAL,
    validate_passport,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"

VALIDATOR_MD = ROOT / "research_watch" / "validator" / "PLATFORM_B1_AGENTIC_AMBIENT_AI_VENDOR_ASSURANCE_PASSPORT_VALIDATOR.md"


class PlatformB1AgenticAmbientAIVendorAssurancePassportValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = validate_passport()
        cls.validator_markdown = VALIDATOR_MD.read_text(encoding="utf-8-sig")

    def test_validator_passes(self):
        self.assertTrue(self.result["passed"], self.result["errors"])
        self.assertEqual(self.result["errors"], [])

    def test_validator_identity_is_locked(self):
        self.assertEqual(
            self.result["validator_name"],
            "Platform B1 Agentic & Ambient AI Vendor Assurance Passport Validator",
        )
        self.assertEqual(
            self.result["validator_status"],
            "LOCKED_AGENTIC_AMBIENT_AI_VENDOR_ASSURANCE_PASSPORT_VALIDATOR_ONLY",
        )
        self.assertEqual(
            self.result["passport"],
            "platform_b1_agentic_ambient_ai_vendor_assurance_passport.json",
        )

    def test_expected_domain_count_is_locked(self):
        self.assertEqual(len(EXPECTED_DOMAINS), 12)
        self.assertEqual(self.result["required_domain_count"], 12)
        self.assertIn("Human Authority and No-Bind Governance", EXPECTED_DOMAINS)
        self.assertIn("Evidence Capture and Audit Reconstruction", EXPECTED_DOMAINS)
        self.assertIn("Exit, Continuity, Data Return, and Decommissioning", EXPECTED_DOMAINS)

    def test_required_outputs_are_locked(self):
        self.assertEqual(len(EXPECTED_OUTPUTS), 14)
        self.assertEqual(self.result["required_outputs"], EXPECTED_OUTPUTS)
        self.assertIn("NO-BIND GOVERNANCE REQUIRED", EXPECTED_OUTPUTS)
        self.assertIn("ACTION NOT ADMISSIBLE WITHOUT EVIDENCE", EXPECTED_OUTPUTS)
        self.assertIn("AI OUTPUT NOT BINDING", EXPECTED_OUTPUTS)

    def test_minimum_audit_trail_is_locked(self):
        self.assertEqual(len(EXPECTED_AUDIT_TRAIL), 16)
        self.assertEqual(self.result["minimum_audit_trail"], EXPECTED_AUDIT_TRAIL)
        self.assertIn("human_reviewer_id_or_role", EXPECTED_AUDIT_TRAIL)
        self.assertIn("reviewer_qualification_status", EXPECTED_AUDIT_TRAIL)
        self.assertIn("review_started_timestamp", EXPECTED_AUDIT_TRAIL)
        self.assertIn("review_completed_timestamp", EXPECTED_AUDIT_TRAIL)
        self.assertIn("authority_basis", EXPECTED_AUDIT_TRAIL)
        self.assertIn("no_bind_state", EXPECTED_AUDIT_TRAIL)
        self.assertIn("evidence_hash", EXPECTED_AUDIT_TRAIL)

    def test_boundary_modes_are_locked(self):
        boundary = " ".join(self.result["boundary_mode"])
        self.assertIn("No Platform B v1 change", boundary)
        self.assertIn("No Thread D v1 change", boundary)
        self.assertIn("No Platform B1 local validation bundle count change", boundary)
        self.assertIn("No Azure deployment", boundary)
        self.assertIn("No Azure Digital Twins deployment", boundary)
        self.assertIn("No real EHR integration", boundary)
        self.assertIn("No PHI", boundary)
        self.assertIn("No company production data", boundary)
        self.assertIn("No clinical decision support claim", boundary)
        self.assertIn("No patient-specific medical decision", boundary)
        self.assertIn("No regulated action execution", boundary)
        self.assertIn("No binding operational consequence", boundary)

    def test_validator_markdown_preserves_pass_signal_and_boundaries(self):
        self.assertIn(PASS_SIGNAL, self.validator_markdown)
        self.assertIn("Validator only", self.validator_markdown)
        self.assertIn("Local research watch only", self.validator_markdown)
        self.assertIn("No Platform B v1 change", self.validator_markdown)
        self.assertIn("No Thread D v1 change", self.validator_markdown)
        self.assertIn("No Platform B1 local validation bundle count change", self.validator_markdown)
        self.assertIn("No Azure deployment", self.validator_markdown)
        self.assertIn("No Azure Digital Twins deployment", self.validator_markdown)
        self.assertIn("No real EHR integration", self.validator_markdown)
        self.assertIn("No clinical decision support claim", self.validator_markdown)
        self.assertIn("No patient-specific medical decision", self.validator_markdown)


if __name__ == "__main__":
    unittest.main()
