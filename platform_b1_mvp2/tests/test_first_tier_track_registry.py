import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"
TRACK_DIR = ROOT / "first_tier_tracks"


class FirstTierTrackRegistryTests(unittest.TestCase):
    def test_first_tier_registry_json_parses(self):
        path = TRACK_DIR / "first_tier_track_registry.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            registry = json.load(handle)

        self.assertEqual(registry["registry_name"], "Platform B1 MVP2 First-Tier Track Registry")
        self.assertEqual(registry["registry_status"], "LOCKED_FIRST_TIER_TRACKS")

    def test_first_tier_tracks_are_present(self):
        path = TRACK_DIR / "first_tier_track_registry.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            registry = json.load(handle)

        track_ids = [track["track_id"] for track in registry["tracks"]]

        self.assertEqual(len(track_ids), 3)
        self.assertIn("compound_pharmacy", track_ids)
        self.assertIn("irlt_radiopharma_operations", track_ids)
        self.assertIn("dscsa_evidence_integrity_exception_assurance", track_ids)

        for track in registry["tracks"]:
            self.assertEqual(track["priority"], "FIRST_TIER")

    def test_each_track_preserves_hashing_and_ai_governance(self):
        path = TRACK_DIR / "first_tier_track_registry.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            registry = json.load(handle)

        for track in registry["tracks"]:
            focus = " ".join(track["assurance_focus"]).lower()
            governed_ai = " ".join(track["governed_ai_use_cases"]).lower()
            prohibited_ai = " ".join(track["prohibited_ai_actions"]).lower()

            self.assertIn("hashing", focus)
            self.assertIn("rehashing", focus)
            self.assertIn("ai", governed_ai)
            self.assertIn("ai", prohibited_ai)

    def test_dscsa_track_contains_required_supply_chain_terms(self):
        path = TRACK_DIR / "first_tier_track_registry.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            registry = json.load(handle)

        dscsa = next(
            track for track in registry["tracks"]
            if track["track_id"] == "dscsa_evidence_integrity_exception_assurance"
        )

        combined = " ".join(dscsa["assurance_focus"] + dscsa["example_outputs"])

        self.assertIn("EPCIS", combined)
        self.assertIn("VRS", combined)
        self.assertIn("serialized product identity", combined)
        self.assertIn("DSCSA EXCEPTION DETECTED", combined)
        self.assertIn("QUARANTINE REQUIRED", combined)

    def test_irlt_and_compound_pharmacy_are_first_tier(self):
        path = TRACK_DIR / "first_tier_track_registry.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            registry = json.load(handle)

        tracks = {track["track_id"]: track for track in registry["tracks"]}

        self.assertEqual(tracks["compound_pharmacy"]["priority"], "FIRST_TIER")
        self.assertEqual(tracks["irlt_radiopharma_operations"]["priority"], "FIRST_TIER")

        self.assertIn("first commercial target groups", tracks["compound_pharmacy"]["commercial_position"])
        self.assertIn("first-tier", tracks["irlt_radiopharma_operations"]["commercial_position"])

    def test_global_boundaries_preserved(self):
        path = TRACK_DIR / "first_tier_track_registry.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            registry = json.load(handle)

        boundary = " ".join(registry["global_boundary"])

        self.assertIn("Do not modify Platform B v1", boundary)
        self.assertIn("Do not reopen Thread D v1", boundary)
        self.assertIn("No PHI", boundary)
        self.assertIn("No company production data", boundary)
        self.assertIn("Platform B1 evaluates", boundary)
        self.assertIn("Thread D2 displays", boundary)


if __name__ == "__main__":
    unittest.main()
