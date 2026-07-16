import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.no_bind import derive_no_bind


class HumanHandoffTests(unittest.TestCase):
    def test_software_never_binds(self):
        result = derive_no_bind(
            {"passed": True},
            True,
            "SYNTHETIC_HUMAN",
        )

        self.assertFalse(
            result["software_can_bind"]
        )
