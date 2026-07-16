import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SecurityBoundaryTests(unittest.TestCase):
    def test_runtime_boundaries_are_disabled(self):
        data = json.loads(
            (
                ROOT
                / "config"
                / "runtime_config.json"
            ).read_text(encoding="utf-8")
        )

        self.assertFalse(data["network_enabled"])
        self.assertFalse(
            data["production_connections_enabled"]
        )
        self.assertFalse(data["deployment_enabled"])
        self.assertFalse(data["hardware_enabled"])
