import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.source_state import evaluate_source_states


class SourceStateTests(unittest.TestCase):
    def test_disagreement_fails(self):
        result = evaluate_source_states([
            {
                "source_id": "S",
                "authoritative": True,
                "agreement": False,
                "available": True,
            }
        ])

        self.assertFalse(result["passed"])
