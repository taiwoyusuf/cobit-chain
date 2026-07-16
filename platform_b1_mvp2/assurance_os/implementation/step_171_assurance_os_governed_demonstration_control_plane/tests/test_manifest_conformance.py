import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ManifestConformanceTests(unittest.TestCase):
    def test_component_manifest_declares_static_count(self):
        data = json.loads(
            (
                ROOT
                / "manifests"
                / "component_manifest.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(data["static_file_count"], 89)
