import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.canonical import canonical_json_text


class DeterminismTests(unittest.TestCase):
    def test_key_order_is_canonical(self):
        self.assertEqual(
            canonical_json_text({"b": 2, "a": 1}),
            canonical_json_text({"a": 1, "b": 2}),
        )
