import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"


class PriorityScopeLockTests(unittest.TestCase):
    def test_priority_scope_lock_json_parses(self):
        path = ROOT / "priority_scope_lock.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            scope_lock = json.load(handle)

        self.assertEqual(scope_lock["scope_lock_name"], "Platform B1 MVP2 Priority Scope Lock")
        self.assertEqual(scope_lock["scope_lock_status"], "LOCKED_MVP2_PRIORITY_DIRECTION")

    def test_first_tier_tracks_are_locked(self):
        path = ROOT / "priority_scope_lock.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            scope_lock = json.load(handle)

        track_ids = [track["track_id"] for track in scope_lock["first_tier_tracks"]]

        self.assertIn("compound_pharmacy", track_ids)
        self.assertIn("irlt_radiopharma_operations", track_ids)
        self.assertIn("dscsa_evidence_integrity_exception_assurance", track_ids)

        for track in scope_lock["first_tier_tracks"]:
            self.assertEqual(track["priority"], "FIRST_TIER")

    def test_foundation_preserves_cobitchain_identity(self):
        path = ROOT / "priority_scope_lock.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            scope_lock = json.load(handle)

        foundation = " ".join(scope_lock["core_foundation"])

        self.assertIn("Hashing", foundation)
        self.assertIn("Rehashing", foundation)
        self.assertIn("Evidence integrity", foundation)
        self.assertIn("Chain-of-custody truth", foundation)
        self.assertIn("Governed AI", foundation)
        self.assertIn("RAMAT Vision", foundation)

    def test_current_validated_chain_preserved(self):
        path = ROOT / "priority_scope_lock.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            scope_lock = json.load(handle)

        chain = scope_lock["mvp2_current_validated_chain"]

        self.assertEqual(chain["feature_id"], "workflow_dependency_assurance_lens")
        self.assertEqual(chain["status"], "VALIDATED_LOCAL_MVP2_CHAIN")
        self.assertEqual(chain["primary_output"], "WORKFLOW APPEARS COMPLETE BUT BLOCKED")
        self.assertEqual(chain["reason"], "LIS HOLD DETECTED")
        self.assertEqual(chain["required_action"], "SECONDARY REVIEW REQUIRED")

    def test_build_rules_preserve_boundaries(self):
        path = ROOT / "priority_scope_lock.json"

        with path.open("r", encoding="utf-8-sig") as handle:
            scope_lock = json.load(handle)

        build_rules = " ".join(scope_lock["build_rules"])

        self.assertIn("Do not modify Platform B v1", build_rules)
        self.assertIn("Do not reopen Thread D v1", build_rules)
        self.assertIn("Do not activate MVP3", build_rules)
        self.assertIn("mock-data-first", build_rules)
        self.assertIn("No PHI", build_rules)
        self.assertIn("No company production data", build_rules)


if __name__ == "__main__":
    unittest.main()
