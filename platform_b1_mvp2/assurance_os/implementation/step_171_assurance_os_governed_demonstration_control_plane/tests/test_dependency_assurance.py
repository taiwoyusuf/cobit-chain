import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.dependency_assurance import evaluate_dependencies


class DependencyTests(unittest.TestCase):
    def test_incomplete_dependency_fails(self):
        result = evaluate_dependencies([
            {
                "dependency_id": "D",
                "complete": False,
                "mapping_valid": True,
                "current": True,
            }
        ])

        self.assertFalse(result["passed"])
