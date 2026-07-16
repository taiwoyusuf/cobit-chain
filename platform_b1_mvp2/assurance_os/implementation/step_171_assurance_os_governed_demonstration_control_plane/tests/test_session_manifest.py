import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.session_manifest import build_session_manifest


class SessionManifestTests(unittest.TestCase):
    def test_manifest_is_deterministic(self):
        track = {"code": "IRLT"}

        scenario = {
            "scenario_id": "IRLT_01_governed_success"
        }

        references = [
            {
                "canonical_commit": "c",
                "evidence_class": "SEAL",
                "read_only": True,
                "relative_path": "x",
                "sha256": "0" * 64,
            }
        ]

        first = build_session_manifest(
            track,
            scenario,
            "c",
            references,
        )

        second = build_session_manifest(
            track,
            scenario,
            "c",
            references,
        )

        self.assertEqual(first, second)
