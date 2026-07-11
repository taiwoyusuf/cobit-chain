import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"
DSCSA_DIR = ROOT / "dscsa"


class DscsaEvidenceIntegrityAddendumTests(unittest.TestCase):
    def test_dscsa_addendum_json_parses(self):
        path = DSCSA_DIR / "dscsa_evidence_integrity_exception_assurance_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        self.assertEqual(
            addendum["addendum_name"],
            "DSCSA Evidence Integrity and Exception Assurance Addendum",
        )
        self.assertEqual(addendum["addendum_status"], "LOCKED_TOP_TIER_EXTENSION_ADDENDUM")
        self.assertEqual(addendum["priority"], "FIRST_TIER")

    def test_dscsa_evidence_integrity_preserves_hashing_and_rehashing(self):
        path = DSCSA_DIR / "dscsa_evidence_integrity_exception_assurance_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        model = addendum["evidence_integrity_model"]

        self.assertTrue(model["hashing_required"])
        self.assertTrue(model["rehashing_required"])

        combined = " ".join(
            model["sealed_evidence_objects"]
            + model["rehash_triggers"]
            + model["example_outputs"]
        )

        self.assertIn("EPCIS file hash", combined)
        self.assertIn("AI output hash", combined)
        self.assertIn("HASH VERIFIED", combined)
        self.assertIn("REHASH REQUIRED", combined)
        self.assertIn("CHAIN OF CUSTODY GAP", combined)

    def test_exception_and_trading_partner_models_are_present(self):
        path = DSCSA_DIR / "dscsa_evidence_integrity_exception_assurance_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        exception_model = addendum["exception_assurance_model"]
        partner_model = addendum["trading_partner_trust_model"]

        exception_combined = " ".join(
            exception_model["exception_types"]
            + exception_model["exception_passport_fields"]
            + exception_model["example_outputs"]
        )

        partner_combined = " ".join(
            partner_model["checks"]
            + partner_model["example_outputs"]
        )

        self.assertIn("VRS no response", exception_combined)
        self.assertIn("QUARANTINE REQUIRED", exception_combined)
        self.assertIn("EXCEPTION NOT DEFENSIBLE", exception_combined)
        self.assertIn("TRADING PARTNER VERIFIED", partner_combined)
        self.assertIn("AUTHORIZED STATUS NOT VERIFIED", partner_combined)

    def test_epcis_and_vrs_terms_are_present(self):
        path = DSCSA_DIR / "dscsa_evidence_integrity_exception_assurance_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        combined = json.dumps(addendum)

        self.assertIn("EPCIS", combined)
        self.assertIn("VRS", combined)
        self.assertIn("serialized", combined)
        self.assertIn("aggregation", combined)
        self.assertIn("PHYSICAL DIGITAL SERIAL MISMATCH", combined)

    def test_ai_governance_boundary_is_preserved(self):
        path = DSCSA_DIR / "dscsa_evidence_integrity_exception_assurance_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        ai_model = addendum["governed_ai_model"]
        allowed = " ".join(ai_model["allowed_ai_actions"])
        prohibited = " ".join(ai_model["prohibited_ai_actions"])
        controls = " ".join(ai_model["required_controls"])
        outputs = " ".join(ai_model["example_outputs"])

        self.assertIn("classify exception type", allowed)
        self.assertIn("AI may not release product", prohibited)
        self.assertIn("AI may not override quarantine", prohibited)
        self.assertIn("AI agent identity", controls)
        self.assertIn("AI output hash", controls)
        self.assertIn("AI OUTPUT HASHED", outputs)
        self.assertIn("AGENT ACTION NOT ADMISSIBLE", outputs)

    def test_first_mock_scenario_defined_not_built(self):
        path = DSCSA_DIR / "dscsa_evidence_integrity_exception_assurance_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        scenario = addendum["first_mock_scenario_direction"]

        self.assertEqual(scenario["scenario_id"], "dscsa_late_epcis_vrs_no_response_exception")
        self.assertEqual(scenario["status"], "DEFINED_NOT_BUILT")

        outputs = " ".join(scenario["expected_outputs"])

        self.assertIn("DSCSA EXCEPTION DETECTED", outputs)
        self.assertIn("EPCIS FILE MISMATCH", outputs)
        self.assertIn("VRS RESPONSE MISSING", outputs)
        self.assertIn("HUMAN REVIEW REQUIRED", outputs)
        self.assertIn("QUARANTINE REQUIRED", outputs)

    def test_global_boundaries_preserved(self):
        path = DSCSA_DIR / "dscsa_evidence_integrity_exception_assurance_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        boundary = " ".join(addendum["global_boundary"])

        self.assertIn("Do not modify Platform B v1", boundary)
        self.assertIn("Do not reopen Thread D v1", boundary)
        self.assertIn("Do not build real EPCIS integration now", boundary)
        self.assertIn("Do not build real VRS integration now", boundary)
        self.assertIn("Do not use real DSCSA production data", boundary)
        self.assertIn("No product release decision", boundary)
        self.assertIn("No quarantine override", boundary)
        self.assertIn("No PHI", boundary)
        self.assertIn("No company production data", boundary)
        self.assertIn("Platform B1 evaluates", boundary)
        self.assertIn("Thread D2 displays", boundary)


if __name__ == "__main__":
    unittest.main()
