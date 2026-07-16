import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.authority_revalidation import evaluate_authority


class AuthorityTests(unittest.TestCase):
    def test_expired_authority_is_no_bind(self):
        result = evaluate_authority({
            "present": True,
            "valid": True,
            "current": True,
            "delegated": True,
            "available": True,
            "not_expired": False,
            "timing_valid": True,
            "silent": False,
            "revoked": False,
        })

        self.assertTrue(result["no_bind"])
