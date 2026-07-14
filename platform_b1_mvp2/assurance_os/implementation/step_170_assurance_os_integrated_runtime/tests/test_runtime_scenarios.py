import unittest
from pathlib import Path

from src.runtime import evaluate_scenario
from src.source_adapters import (
    load_fixture,
    load_scenario_catalog,
)


class RuntimeScenarioTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(
            __file__
        ).resolve().parents[1]

        self.catalog = (
            load_scenario_catalog(
                self.root
            )
        )

    def test_all_catalog_decisions_match(self):
        for track in self.catalog["tracks"]:
            fixture = load_fixture(
                self.root,
                track["id"],
            )

            for scenario in track["scenarios"]:
                result = evaluate_scenario(
                    track,
                    scenario,
                    fixture,
                    self.catalog[
                        "deterministic_timestamp"
                    ],
                )

                self.assertEqual(
                    result[
                        "action_admissibility"
                    ]["decision"],
                    scenario[
                        "expected_decision"
                    ],
                )


if __name__ == "__main__":
    unittest.main()
