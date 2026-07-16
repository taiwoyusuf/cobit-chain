import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.no_bind import derive_no_bind


class NoBindTests(unittest.TestCase):
    def test_failure_creates_hold(self):
        result = derive_no_bind(
            {"passed": False},
            False,
            "SYNTHETIC_HUMAN",
        )

        self.assertEqual(
            result["state"],
            "ACTION_HELD",
        )
