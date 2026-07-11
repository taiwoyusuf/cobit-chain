import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"
CATALOGUE_DIR = ROOT / "extension_catalogue"


class ManufacturingSupplyChainExtensionCatalogueTests(unittest.TestCase):
    def test_catalogue_json_parses(self):
        path = CATALOGUE_DIR / "manufacturing_supply_chain_extension_catalogue.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            catalogue = json.load(handle)

        self.assertEqual(
            catalogue["catalogue_name"],
            "Platform B1 MVP2 Manufacturing and Supply Chain Extension Catalogue",
        )
        self.assertEqual(catalogue["catalogue_status"], "LOCKED_CATALOGUE_ONLY")

    def test_first_tier_tracks_are_preserved(self):
        path = CATALOGUE_DIR / "manufacturing_supply_chain_extension_catalogue.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            catalogue = json.load(handle)

        track_ids = [track["track_id"] for track in catalogue["first_tier_tracks"]]

        self.assertIn("compound_pharmacy", track_ids)
        self.assertIn("irlt_radiopharma_operations", track_ids)
        self.assertIn("dscsa_evidence_integrity_exception_assurance", track_ids)

        for track in catalogue["first_tier_tracks"]:
            self.assertEqual(track["priority"], "FIRST_TIER")

    def test_required_extension_categories_exist(self):
        path = CATALOGUE_DIR / "manufacturing_supply_chain_extension_catalogue.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            catalogue = json.load(handle)

        category_ids = [category["category_id"] for category in catalogue["extension_categories"]]

        self.assertIn("manufacturing_execution", category_ids)
        self.assertIn("materials_and_supply_chain", category_ids)
        self.assertIn("equipment_automation_facility", category_ids)
        self.assertIn("quality_and_process_assurance", category_ids)
        self.assertIn("lifecycle_external_manufacturing", category_ids)

    def test_dscsa_is_top_tier_extension(self):
        path = CATALOGUE_DIR / "manufacturing_supply_chain_extension_catalogue.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            catalogue = json.load(handle)

        extensions = []
        for category in catalogue["extension_categories"]:
            extensions.extend(category["extensions"])

        dscsa = next(
            extension for extension in extensions
            if extension["extension_id"] == "dscsa_evidence_integrity_exception_assurance"
        )

        combined = " ".join(dscsa["example_outputs"])

        self.assertEqual(dscsa["priority"], "FIRST_TIER")
        self.assertIn("DSCSA EVIDENCE SEALED", combined)
        self.assertIn("EPCIS FILE MISMATCH", combined)
        self.assertIn("VRS RESPONSE MISSING", combined)
        self.assertIn("QUARANTINE REQUIRED", combined)
        self.assertIn("EXCEPTION NOT DEFENSIBLE", combined)

    def test_core_manufacturing_extensions_exist(self):
        path = CATALOGUE_DIR / "manufacturing_supply_chain_extension_catalogue.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            catalogue = json.load(handle)

        extension_ids = []
        for category in catalogue["extension_categories"]:
            extension_ids.extend(extension["extension_id"] for extension in category["extensions"])

        required = {
            "mes_execution_dependency_assurance",
            "batch_release_dependency_assurance",
            "material_genealogy_erp_weigh_dispense_assurance",
            "equipment_readiness_calibration_pm_assurance",
            "automation_plc_scada_historian_truth_assurance",
            "cleaning_line_clearance_changeover_assurance",
            "recipe_master_data_mbr_bom_assurance",
            "manufacturing_deviation_impact_assurance",
            "cmo_external_manufacturing_assurance",
        }

        self.assertTrue(required.issubset(set(extension_ids)))

    def test_ai_governance_and_foundation_are_preserved(self):
        path = CATALOGUE_DIR / "manufacturing_supply_chain_extension_catalogue.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            catalogue = json.load(handle)

        principle = catalogue["cross_cutting_ai_governance"]["principle"]
        controls = " ".join(catalogue["cross_cutting_ai_governance"]["required_controls"])
        foundation = " ".join(catalogue["shared_foundation"])

        self.assertIn("AI may assist", principle)
        self.assertIn("AI may not independently approve", principle)
        self.assertIn("AI agent identity", controls)
        self.assertIn("hash of AI output", controls)
        self.assertIn("rehash status", controls)
        self.assertIn("Hashing", foundation)
        self.assertIn("Rehashing", foundation)
        self.assertIn("Evidence integrity", foundation)
        self.assertIn("Regulated operations digital twin", foundation)

    def test_global_boundaries_preserved(self):
        path = CATALOGUE_DIR / "manufacturing_supply_chain_extension_catalogue.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            catalogue = json.load(handle)

        boundary = " ".join(catalogue["global_boundary"])

        self.assertIn("Do not modify Platform B v1", boundary)
        self.assertIn("Do not reopen Thread D v1", boundary)
        self.assertIn("No PHI", boundary)
        self.assertIn("No company production data", boundary)
        self.assertIn("Platform B1 evaluates", boundary)
        self.assertIn("Thread D2 displays", boundary)


if __name__ == "__main__":
    unittest.main()
