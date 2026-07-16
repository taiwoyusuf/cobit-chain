import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.evidence_integrity import evaluate_evidence


class EvidenceIntegrityTests(unittest.TestCase):
    def test_hash_failure_fails_closed(self):
        result = evaluate_evidence({
            "provenance": "SYNTHETIC",
            "hash_matches": False,
            "seal_valid": True,
            "sufficient": True,
        })

        self.assertFalse(result["passed"])
