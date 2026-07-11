import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"
TWIN_DIR = ROOT / "regulated_operations_digital_twin"


class RegulatedOperationsDigitalTwinObjectModelTests(unittest.TestCase):
    def test_digital_twin_object_model_json_parses(self):
        path = TWIN_DIR / "regulated_operations_digital_twin_object_model.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            model = json.load(handle)

        self.assertEqual(model["model_name"], "Regulated Operations Digital Twin Object Model")
        self.assertEqual(model["model_status"], "LOCKED_OBJECT_MODEL_ONLY")

    def test_required_object_families_exist(self):
        path = TWIN_DIR / "regulated_operations_digital_twin_object_model.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            model = json.load(handle)

        family_ids = [family["object_family_id"] for family in model["object_families"]]

        required = {
            "identity_role_persona",
            "equipment_ci_asset",
            "workflow_dependency_chain",
            "evidence_integrity",
            "quality_state",
            "material_product_supply_chain",
            "execution_context",
            "ai_agent_output",
            "ramat_vision_display",
        }

        self.assertTrue(required.issubset(set(family_ids)))

    def test_track_alignment_preserves_first_tier_tracks(self):
        path = TWIN_DIR / "regulated_operations_digital_twin_object_model.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            model = json.load(handle)

        track_ids = [track["track_id"] for track in model["track_alignment"]]

        self.assertIn("compound_pharmacy", track_ids)
        self.assertIn("irlt_radiopharma_operations", track_ids)
        self.assertIn("dscsa_evidence_integrity_exception_assurance", track_ids)

    def test_relationship_types_cover_core_assurance_links(self):
        path = TWIN_DIR / "regulated_operations_digital_twin_object_model.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            model = json.load(handle)

        relationship_ids = [relationship["relationship_id"] for relationship in model["relationship_types"]]

        required = {
            "equipment_has_ci",
            "workflow_step_depends_on_evidence",
            "evidence_has_hash_record",
            "ai_output_requires_human_review",
            "dscsa_event_has_epcis_evidence",
            "serialized_product_has_vrs_response",
            "compound_preparation_has_formula",
            "irlt_context_has_handoff_record",
            "platform_decision_displayed_by_ramat_vision",
        }

        self.assertTrue(required.issubset(set(relationship_ids)))

    def test_ai_and_ramat_boundaries_are_present(self):
        path = TWIN_DIR / "regulated_operations_digital_twin_object_model.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            model = json.load(handle)

        combined = json.dumps(model)

        self.assertIn("AI OUTPUT HASHED", combined)
        self.assertIn("AI RECOMMENDATION REVIEW REQUIRED", combined)
        self.assertIn("AGENT ACTION NOT ADMISSIBLE", combined)
        self.assertIn("RAMAT VISION DISPLAY READY", combined)
        self.assertIn("PLATFORM B1 DECISION DISPLAYED", combined)
        self.assertIn("RAMAT Vision displays only", combined)

    def test_dscsa_compound_and_irlt_outputs_are_present(self):
        path = TWIN_DIR / "regulated_operations_digital_twin_object_model.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            model = json.load(handle)

        combined = json.dumps(model)

        self.assertIn("COMPOUNDING WORKFLOW APPEARS COMPLETE BUT BLOCKED", combined)
        self.assertIn("BUD EVIDENCE REVIEW REQUIRED", combined)
        self.assertIn("IRLT WORKFLOW APPEARS COMPLETE BUT BLOCKED", combined)
        self.assertIn("CI READINESS GAP", combined)
        self.assertIn("DSCSA EXCEPTION DETECTED", combined)
        self.assertIn("EPCIS FILE MISMATCH", combined)
        self.assertIn("VRS RESPONSE MISSING", combined)

    def test_boundary_preserves_no_production_and_no_deployment_rules(self):
        path = TWIN_DIR / "regulated_operations_digital_twin_object_model.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            model = json.load(handle)

        boundary = " ".join(model["boundary"])

        self.assertIn("Do not deploy Azure Digital Twins now", boundary)
        self.assertIn("Do not deploy Azure resources now", boundary)
        self.assertIn("Do not modify Platform B v1", boundary)
        self.assertIn("Do not reopen Thread D v1", boundary)
        self.assertIn("No PHI", boundary)
        self.assertIn("No company production data", boundary)
        self.assertIn("No product release decision", boundary)
        self.assertIn("No GMP approval decision", boundary)
        self.assertIn("No source-system override", boundary)
        self.assertIn("No Quality Unit replacement", boundary)
        self.assertIn("Platform B1 evaluates", boundary)
        self.assertIn("Thread D2 displays", boundary)
        self.assertIn("Official records remain in source systems", boundary)


if __name__ == "__main__":
    unittest.main()
