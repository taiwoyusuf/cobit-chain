import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"
COMPOUND_DIR = ROOT / "compound_pharmacy"


class CompoundPharmacyCommercializationAddendumTests(unittest.TestCase):
    def test_compound_pharmacy_addendum_json_parses(self):
        path = COMPOUND_DIR / "compound_pharmacy_commercialization_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        self.assertEqual(addendum["addendum_name"], "Compound Pharmacy Commercialization Addendum")
        self.assertEqual(addendum["addendum_status"], "LOCKED_FIRST_TIER_COMMERCIALIZATION_ADDENDUM")
        self.assertEqual(addendum["priority"], "FIRST_TIER")
        self.assertEqual(addendum["track_id"], "compound_pharmacy")

    def test_commercial_package_is_defined_not_built(self):
        path = COMPOUND_DIR / "compound_pharmacy_commercialization_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        package = addendum["commercial_package"]

        self.assertEqual(package["package_name"], "Compound Pharmacy Assurance Package")
        self.assertEqual(package["package_status"], "DEFINED_NOT_BUILT")
        self.assertIn("compounding pharmacy owner", package["target_buyers"])
        self.assertIn("inspection readiness anxiety", package["buyer_pain_points"])

    def test_assurance_components_are_present(self):
        path = COMPOUND_DIR / "compound_pharmacy_commercialization_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        component_ids = [component["component_id"] for component in addendum["assurance_components"]]

        required = {
            "formula_evidence_assurance",
            "ingredient_lot_traceability_assurance",
            "preparation_record_integrity_assurance",
            "bud_evidence_assurance",
            "quality_review_readiness_assurance",
            "ai_gmp_content_review_assurance",
        }

        self.assertTrue(required.issubset(set(component_ids)))

    def test_evidence_integrity_preserves_hashing_and_rehashing(self):
        path = COMPOUND_DIR / "compound_pharmacy_commercialization_addendum.json"

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

        self.assertIn("AI output hash", combined)
        self.assertIn("final evidence package hash", combined)
        self.assertIn("COMPOUNDING EVIDENCE SEALED", combined)
        self.assertIn("HASH VERIFIED", combined)
        self.assertIn("REHASH REQUIRED", combined)

    def test_workflow_dependency_outputs_are_present(self):
        path = COMPOUND_DIR / "compound_pharmacy_commercialization_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        model = addendum["workflow_dependency_model"]
        combined = " ".join(model["dependency_checks"] + model["example_outputs"])

        self.assertIn("approved formula present", combined)
        self.assertIn("ingredient lots verified", combined)
        self.assertIn("BUD evidence present", combined)
        self.assertIn("COMPOUNDING WORKFLOW APPEARS COMPLETE BUT BLOCKED", combined)
        self.assertIn("COMPOUNDING PACKAGE DEFENSIBLE", combined)

    def test_ai_governance_boundary_is_preserved(self):
        path = COMPOUND_DIR / "compound_pharmacy_commercialization_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        ai_model = addendum["governed_ai_model"]
        allowed = " ".join(ai_model["allowed_ai_actions"])
        prohibited = " ".join(ai_model["prohibited_ai_actions"])
        controls = " ".join(ai_model["required_controls"])
        outputs = " ".join(ai_model["example_outputs"])

        self.assertIn("summarize preparation evidence", allowed)
        self.assertIn("AI may not release compounded preparation", prohibited)
        self.assertIn("AI may not replace pharmacist review", prohibited)
        self.assertIn("AI output hash", controls)
        self.assertIn("AI CONTENT REVIEW REQUIRED", outputs)
        self.assertIn("AGENT ACTION NOT ADMISSIBLE", outputs)

    def test_first_commercial_demo_defined_not_built(self):
        path = COMPOUND_DIR / "compound_pharmacy_commercialization_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        scenario = addendum["first_commercial_demo_direction"]

        self.assertEqual(scenario["scenario_id"], "compound_pharmacy_preparation_package_review")
        self.assertEqual(scenario["status"], "DEFINED_NOT_BUILT")

        outputs = " ".join(scenario["expected_outputs"])

        self.assertIn("COMPOUNDING EVIDENCE SEALED", outputs)
        self.assertIn("BUD EVIDENCE REVIEW REQUIRED", outputs)
        self.assertIn("AI CONTENT REVIEW REQUIRED", outputs)
        self.assertIn("HUMAN REVIEW REQUIRED", outputs)
        self.assertIn("QUALITY REVIEW REQUIRED", outputs)

    def test_global_boundaries_preserved(self):
        path = COMPOUND_DIR / "compound_pharmacy_commercialization_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        boundary = " ".join(addendum["global_boundary"])

        self.assertIn("Do not modify Platform B v1", boundary)
        self.assertIn("Do not reopen Thread D v1", boundary)
        self.assertIn("Do not build new commercial module now", boundary)
        self.assertIn("Do not connect to real pharmacy systems now", boundary)
        self.assertIn("No PHI", boundary)
        self.assertIn("No company production data", boundary)
        self.assertIn("No preparation release decision", boundary)
        self.assertIn("No pharmacist replacement", boundary)
        self.assertIn("No source-system override", boundary)
        self.assertIn("Platform B1 evaluates", boundary)
        self.assertIn("Thread D2 displays", boundary)


if __name__ == "__main__":
    unittest.main()
