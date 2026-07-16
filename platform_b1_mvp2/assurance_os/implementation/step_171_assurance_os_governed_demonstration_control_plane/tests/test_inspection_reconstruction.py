import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.inspection_reconstruction import build_reconstruction


class ReconstructionTests(unittest.TestCase):
    def test_reconstruction_is_display_only(self):
        manifest = {
            "session_id": "S",
            "canonical_baseline_commit": "C",
        }

        result = build_reconstruction(
            manifest,
            [{"evidence_type": "X"}],
            ["E1"],
        )

        self.assertTrue(result["display_only"])
