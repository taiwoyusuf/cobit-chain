import unittest
from pathlib import Path

from src.source_adapters import (
    load_fixture,
    load_scenario_catalog,
)


class SourceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(
            __file__
        ).resolve().parents[1]

    def test_catalog_and_fixture_are_synthetic(self):
        catalog = load_scenario_catalog(
            self.root
        )

        fixture = load_fixture(
            self.root,
            "irlt",
        )

        self.assertEqual(
            len(catalog["tracks"]),
            4,
        )

        self.assertEqual(
            fixture["evidence"]["provenance"],
            "SYNTHETIC",
        )


if __name__ == "__main__":
    unittest.main()
