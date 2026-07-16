import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.identity_accountability import evaluate_identity


class IdentityTests(unittest.TestCase):
    def test_accountable_human_is_required(self):
        result = evaluate_identity({
            "identity_id": "I",
            "role_valid": True,
            "mapping_valid": True,
            "accountable_human_identified": False,
            "accountable_human_id": "",
        })

        self.assertFalse(result["passed"])
