import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"
FIXTURE_DIR = ROOT / "regulated_operations_digital_twin" / "mock_fixtures"


class RegulatedOperationsDigitalTwinMockFixtureTests(unittest.TestCase):
    def _load_fixture(self, filename):
        path = FIXTURE_DIR / filename
        with path.open("r", encoding="utf-8-sig") as handle:
            return json.load(handle)

    def test_all_fixture_json_files_parse(self):
        fixtures = [
            "compound_pharmacy_preparation_package_review.json",
            "irlt_equipment_ci_quality_handoff_review.json",
            "dscsa_late_epcis_vrs_no_response_exception.json",
        ]

        for fixture in fixtures:
            data = self._load_fixture(fixture)
            self.assertEqual(data["fixture_status"], "LOCKED_MOCK_FIXTURE_ONLY")
            self.assertIn("expected_platform_b1_outputs", data)
            self.assertIn("twin_state", data)

    def test_first_tier_track_ids_are_present(self):
        compound = self._load_fixture("compound_pharmacy_preparation_package_review.json")
        irlt = self._load_fixture("irlt_equipment_ci_quality_handoff_review.json")
        dscsa = self._load_fixture("dscsa_late_epcis_vrs_no_response_exception.json")

        self.assertEqual(compound["track_id"], "compound_pharmacy")
        self.assertEqual(irlt["track_id"], "irlt_radiopharma_operations")
        self.assertEqual(dscsa["track_id"], "dscsa_evidence_integrity_exception_assurance")

    def test_compound_pharmacy_fixture_outputs(self):
        fixture = self._load_fixture("compound_pharmacy_preparation_package_review.json")
        outputs = " ".join(fixture["expected_platform_b1_outputs"])

        self.assertIn("COMPOUNDING EVIDENCE SEALED", outputs)
        self.assertIn("HASH VERIFIED", outputs)
        self.assertIn("BUD EVIDENCE REVIEW REQUIRED", outputs)
        self.assertIn("AI CONTENT REVIEW REQUIRED", outputs)
        self.assertIn("COMPOUNDING WORKFLOW APPEARS COMPLETE BUT BLOCKED", outputs)

    def test_irlt_fixture_outputs(self):
        fixture = self._load_fixture("irlt_equipment_ci_quality_handoff_review.json")
        outputs = " ".join(fixture["expected_platform_b1_outputs"])

        self.assertIn("IRLT EVIDENCE SEALED", outputs)
        self.assertIn("CI READINESS GAP", outputs)
        self.assertIn("SUPPORT GROUP MISSING", outputs)
        self.assertIn("QUALITY DEPENDENCY BLOCKED", outputs)
        self.assertIn("RAMAT VISION DISPLAY READY", outputs)
        self.assertIn("IRLT WORKFLOW APPEARS COMPLETE BUT BLOCKED", outputs)

    def test_dscsa_fixture_outputs(self):
        fixture = self._load_fixture("dscsa_late_epcis_vrs_no_response_exception.json")
        outputs = " ".join(fixture["expected_platform_b1_outputs"])

        self.assertIn("DSCSA EXCEPTION DETECTED", outputs)
        self.assertIn("EPCIS FILE MISMATCH", outputs)
        self.assertIn("VRS RESPONSE MISSING", outputs)
        self.assertIn("TRADING PARTNER EVIDENCE STALE", outputs)
        self.assertIn("QUARANTINE REQUIRED", outputs)
        self.assertIn("EXCEPTION NOT DEFENSIBLE", outputs)

    def test_each_fixture_preserves_required_twin_state_families(self):
        fixtures = [
            "compound_pharmacy_preparation_package_review.json",
            "irlt_equipment_ci_quality_handoff_review.json",
            "dscsa_late_epcis_vrs_no_response_exception.json",
        ]

        for fixture_name in fixtures:
            fixture = self._load_fixture(fixture_name)
            twin_state = fixture["twin_state"]

            self.assertIn("identity_role_persona", twin_state)
            self.assertIn("workflow_dependency_chain", twin_state)
            self.assertIn("evidence_integrity", twin_state)
            self.assertIn("ai_agent_output", twin_state)
            self.assertIn("ramat_vision_display", twin_state)

    def test_boundaries_preserve_no_production_rules(self):
        fixtures = [
            "compound_pharmacy_preparation_package_review.json",
            "irlt_equipment_ci_quality_handoff_review.json",
            "dscsa_late_epcis_vrs_no_response_exception.json",
        ]

        for fixture_name in fixtures:
            fixture = self._load_fixture(fixture_name)
            boundary = " ".join(fixture["boundary"])

            self.assertIn("Mock fixture only", boundary)
            self.assertIn("No PHI", boundary)
            self.assertIn("No product release decision", boundary)
            self.assertIn("No source-system override", boundary)
            self.assertIn("Platform B1 evaluates", boundary)
            self.assertIn("Thread D2 displays", boundary)
            self.assertIn("RAMAT Vision displays only", boundary)


if __name__ == "__main__":
    unittest.main()
