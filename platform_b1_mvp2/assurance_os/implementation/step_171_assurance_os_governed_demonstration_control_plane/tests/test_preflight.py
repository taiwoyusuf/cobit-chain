import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.preflight import perform_preflight


class PreflightTests(unittest.TestCase):
    def test_success_fixture_passes(self):
        fixture = json.loads(
            (
                ROOT
                / "data"
                / "scenarios"
                / "irlt_01_governed_success.json"
            ).read_text(encoding="utf-8")
        )

        self.assertTrue(
            perform_preflight(fixture)["passed"]
        )
