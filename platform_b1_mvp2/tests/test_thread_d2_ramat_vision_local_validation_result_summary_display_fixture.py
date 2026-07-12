import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"
DISPLAY_JSON = (
    ROOT
    / "thread_d2_ramat_vision_preview"
    / "platform_b1_local_validation_result_summary_display_fixture.json"
)
DISPLAY_MD = (
    ROOT
    / "thread_d2_ramat_vision_preview"
    / "PLATFORM_B1_LOCAL_VALIDATION_RESULT_SUMMARY_DISPLAY_FIXTURE.md"
)


class ThreadD2RamatVisionLocalValidationResultSummaryDisplayFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(DISPLAY_JSON.read_text(encoding="utf-8-sig"))
        cls.markdown = DISPLAY_MD.read_text(encoding="utf-8-sig")

    def test_fixture_identity_is_locked(self):
        self.assertEqual(
            self.fixture["display_fixture_name"],
            "Thread D2 RAMAT Vision Local Validation Result Summary Display Fixture",
        )
        self.assertEqual(
            self.fixture["fixture_status"],
            "LOCKED_THREAD_D2_DISPLAY_FIXTURE_ONLY",
        )
        self.assertEqual(
            self.fixture["workstream"],
            "Thread D2 — RAMAT Vision Advanced Assurance Preview",
        )
        self.assertEqual(self.fixture["source_workstream"], "Platform B1 / MVP2")

    def test_source_summary_state_is_preview_only(self):
        summary = self.fixture["source_validation_summary"]

        self.assertEqual(summary["overall_status"], "PASSED")
        self.assertEqual(summary["validation_count"], 6)
        self.assertEqual(summary["failed_validation_count"], 0)
        self.assertEqual(summary["result_admissibility"], "LOCAL_VALIDATION_SUMMARY_ONLY")
        self.assertEqual(summary["azure_deployment_status"], "NOT_DEPLOYED")
        self.assertEqual(summary["platform_b_v1_impact"], "NONE")
        self.assertEqual(summary["thread_d_v1_impact"], "NONE")
        self.assertEqual(summary["mvp3_activation"], "NONE")

    def test_display_state_is_non_authoritative(self):
        state = self.fixture["display_state"]

        self.assertEqual(state["thread_d2_display_status"], "PREVIEW_READY")
        self.assertEqual(state["ramat_vision_display_status"], "DISPLAY_READY")
        self.assertEqual(state["platform_b1_decision_status"], "DISPLAYED_ONLY")
        self.assertEqual(state["operator_action_status"], "NOT_AUTHORIZED_BY_DISPLAY")
        self.assertEqual(state["quality_unit_status"], "NOT_REPLACED")
        self.assertEqual(state["source_system_status"], "NOT_OVERRIDDEN")

    def test_ramat_vision_cards_are_present(self):
        cards = self.fixture["ramat_vision_cards"]
        card_titles = {card["card_title"] for card in cards}

        self.assertEqual(len(cards), 4)
        self.assertIn("PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED", card_titles)
        self.assertIn("EVIDENCE INTEGRITY SIGNALS PRESENT", card_titles)
        self.assertIn("AGENT ACTION NOT ADMISSIBLE", card_titles)
        self.assertIn("RAMAT VISION DISPLAYS ONLY", card_titles)

    def test_required_assurance_signals_are_preserved(self):
        signals = " ".join(self.fixture["required_assurance_signals"])

        self.assertIn("PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED", signals)
        self.assertIn("DIGITAL TWIN OBJECT MODEL VALIDATED", signals)
        self.assertIn("DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED", signals)
        self.assertIn("LOCAL VALIDATION RESULT SUMMARY FIXTURE VALIDATION PASSED", signals)
        self.assertIn("AI OUTPUT HASHED", signals)
        self.assertIn("HASH VERIFIED", signals)
        self.assertIn("AGENT ACTION NOT ADMISSIBLE", signals)
        self.assertIn("RAMAT VISION DISPLAY READY", signals)
        self.assertIn("PLATFORM B1 DECISION DISPLAYED", signals)

    def test_display_doctrine_is_preserved(self):
        doctrine = " ".join(self.fixture["display_doctrine"])

        self.assertIn("Platform B1 evaluates", doctrine)
        self.assertIn("Thread D2 displays", doctrine)
        self.assertIn("RAMAT Vision displays only", doctrine)
        self.assertIn("Any device may witness", doctrine)
        self.assertIn("Official records remain in source systems", doctrine)
        self.assertIn("Humans remain accountable", doctrine)

    def test_boundary_is_preserved(self):
        boundary = " ".join(self.fixture["boundary"])

        self.assertIn("Thread D2 display fixture only", boundary)
        self.assertIn("RAMAT Vision preview display only", boundary)
        self.assertIn("No Azure deployment", boundary)
        self.assertIn("No Azure Digital Twins deployment", boundary)
        self.assertIn("No Platform B v1 change", boundary)
        self.assertIn("No Thread D v1 change", boundary)
        self.assertIn("No real glasses hardware integration", boundary)
        self.assertIn("No real Halo hardware integration", boundary)
        self.assertIn("No PHI", boundary)
        self.assertIn("No company production data", boundary)
        self.assertIn("No product release decision", boundary)
        self.assertIn("No GMP approval decision", boundary)
        self.assertIn("No source-system override", boundary)
        self.assertIn("No Quality Unit replacement", boundary)
        self.assertIn("No regulated action execution", boundary)
        self.assertIn("No binding operational consequence", boundary)

    def test_markdown_preserves_display_terms(self):
        text = self.markdown

        self.assertIn("LOCKED THREAD D2 DISPLAY FIXTURE ONLY", text)
        self.assertIn("Thread D2 — RAMAT Vision Advanced Assurance Preview", text)
        self.assertIn("PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED", text)
        self.assertIn("AI OUTPUT HASHED", text)
        self.assertIn("HASH VERIFIED", text)
        self.assertIn("AGENT ACTION NOT ADMISSIBLE", text)
        self.assertIn("RAMAT VISION DISPLAY READY", text)
        self.assertIn("PLATFORM B1 DECISION DISPLAYED", text)
        self.assertIn("Platform B1 evaluates", text)
        self.assertIn("Thread D2 displays", text)
        self.assertIn("RAMAT Vision displays only", text)
        self.assertIn("No real Halo hardware integration", text)
        self.assertIn("No product release decision", text)
        self.assertIn("No Quality Unit replacement", text)


if __name__ == "__main__":
    unittest.main()
