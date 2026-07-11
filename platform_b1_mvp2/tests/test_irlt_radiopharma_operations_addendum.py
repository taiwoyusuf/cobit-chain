import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"
IRLT_DIR = ROOT / "irlt_radiopharma"


class IrltRadiopharmaOperationsAddendumTests(unittest.TestCase):
    def test_irlt_addendum_json_parses(self):
        path = IRLT_DIR / "irlt_radiopharma_operations_first_tier_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        self.assertEqual(addendum["addendum_name"], "IRLT / Radiopharma Operations First-Tier Addendum")
        self.assertEqual(addendum["addendum_status"], "LOCKED_FIRST_TIER_OPERATIONS_ADDENDUM")
        self.assertEqual(addendum["priority"], "FIRST_TIER")
        self.assertEqual(addendum["track_id"], "irlt_radiopharma_operations")

    def test_operational_package_is_defined_not_built(self):
        path = IRLT_DIR / "irlt_radiopharma_operations_first_tier_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        package = addendum["operational_package"]

        self.assertEqual(package["package_name"], "IRLT / Radiopharma Operations Assurance Package")
        self.assertEqual(package["package_status"], "DEFINED_NOT_BUILT")
        self.assertIn("radiopharma operations leader", package["target_users"])
        self.assertIn("equipment readiness uncertainty", package["operational_pain_points"])

    def test_assurance_components_are_present(self):
        path = IRLT_DIR / "irlt_radiopharma_operations_first_tier_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        component_ids = [component["component_id"] for component in addendum["assurance_components"]]

        required = {
            "equipment_ci_readiness_assurance",
            "servicenow_operational_assurance",
            "controlled_handoff_assurance",
            "quality_dependency_assurance",
            "radiopharma_execution_context_assurance",
            "ramat_vision_field_display_assurance",
            "ai_recommendation_boundary_assurance",
        }

        self.assertTrue(required.issubset(set(component_ids)))

    def test_evidence_integrity_preserves_hashing_and_rehashing(self):
        path = IRLT_DIR / "irlt_radiopharma_operations_first_tier_addendum.json"

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

        self.assertIn("CI identifier", combined)
        self.assertIn("AI output hash", combined)
        self.assertIn("RAMAT Vision display event", combined)
        self.assertIn("IRLT EVIDENCE SEALED", combined)
        self.assertIn("HASH VERIFIED", combined)
        self.assertIn("REHASH REQUIRED", combined)

    def test_workflow_dependency_outputs_are_present(self):
        path = IRLT_DIR / "irlt_radiopharma_operations_first_tier_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        model = addendum["workflow_dependency_model"]
        combined = " ".join(model["dependency_checks"] + model["example_outputs"])

        self.assertIn("equipment identity verified", combined)
        self.assertIn("ServiceNow change state checked", combined)
        self.assertIn("quality dependency state checked", combined)
        self.assertIn("IRLT WORKFLOW APPEARS COMPLETE BUT BLOCKED", combined)
        self.assertIn("IRLT PACKAGE DEFENSIBLE", combined)

    def test_ramat_vision_boundary_is_preserved(self):
        path = IRLT_DIR / "irlt_radiopharma_operations_first_tier_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        model = addendum["ramat_vision_display_model"]
        allowed = " ".join(model["display_allowed"])
        prohibited = " ".join(model["display_prohibited"])
        outputs = " ".join(model["example_outputs"])

        self.assertIn("readiness state", allowed)
        self.assertIn("RAMAT Vision may not approve GMP work", prohibited)
        self.assertIn("RAMAT Vision may not release product", prohibited)
        self.assertIn("RAMAT VISION DISPLAY READY", outputs)
        self.assertIn("ROLE VERIFIED", outputs)
        self.assertIn("PLATFORM B1 DECISION DISPLAYED", outputs)

    def test_ai_governance_boundary_is_preserved(self):
        path = IRLT_DIR / "irlt_radiopharma_operations_first_tier_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        ai_model = addendum["governed_ai_model"]
        allowed = " ".join(ai_model["allowed_ai_actions"])
        prohibited = " ".join(ai_model["prohibited_ai_actions"])
        controls = " ".join(ai_model["required_controls"])
        outputs = " ".join(ai_model["example_outputs"])

        self.assertIn("summarize operational readiness evidence", allowed)
        self.assertIn("AI may not release product", prohibited)
        self.assertIn("AI may not approve GMP work", prohibited)
        self.assertIn("AI output hash", controls)
        self.assertIn("AI RECOMMENDATION REVIEW REQUIRED", outputs)
        self.assertIn("AGENT ACTION NOT ADMISSIBLE", outputs)

    def test_first_demo_defined_not_built(self):
        path = IRLT_DIR / "irlt_radiopharma_operations_first_tier_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        scenario = addendum["first_demo_direction"]

        self.assertEqual(scenario["scenario_id"], "irlt_equipment_ci_quality_handoff_review")
        self.assertEqual(scenario["status"], "DEFINED_NOT_BUILT")

        outputs = " ".join(scenario["expected_outputs"])

        self.assertIn("IRLT EVIDENCE SEALED", outputs)
        self.assertIn("CI READINESS GAP", outputs)
        self.assertIn("QUALITY DEPENDENCY BLOCKED", outputs)
        self.assertIn("RAMAT VISION DISPLAY READY", outputs)
        self.assertIn("IRLT WORKFLOW APPEARS COMPLETE BUT BLOCKED", outputs)

    def test_global_boundaries_preserved(self):
        path = IRLT_DIR / "irlt_radiopharma_operations_first_tier_addendum.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            addendum = json.load(handle)

        boundary = " ".join(addendum["global_boundary"])

        self.assertIn("Do not modify Platform B v1", boundary)
        self.assertIn("Do not reopen Thread D v1", boundary)
        self.assertIn("Do not build new commercial module now", boundary)
        self.assertIn("No PHI", boundary)
        self.assertIn("No company production data", boundary)
        self.assertIn("No product release decision", boundary)
        self.assertIn("No GMP approval decision", boundary)
        self.assertIn("No Quality Unit replacement", boundary)
        self.assertIn("No source-system override", boundary)
        self.assertIn("No real radiopharma production data", boundary)
        self.assertIn("Platform B1 evaluates", boundary)
        self.assertIn("Thread D2 displays", boundary)
        self.assertIn("RAMAT Vision displays only", boundary)


if __name__ == "__main__":
    unittest.main()
