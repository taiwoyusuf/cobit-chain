from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(ROOT / "src"),
)

from orchestrator_api import (
    api_self_test,
    read_json,
    run_demo,
)


class Step164Tests(unittest.TestCase):
    def test_orchestrator_and_read_only_api(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project = Path(temp_dir) / "step164"

            shutil.copytree(
                ROOT / "config",
                project / "config",
            )

            summary = run_demo(project)
            api_result = api_self_test(project)

            self.assertEqual(
                "PASS",
                summary["overall_status"],
            )

            self.assertEqual(
                3,
                summary["first_tier_track_count"],
            )

            self.assertEqual(
                12,
                summary["scenario_count"],
            )

            self.assertEqual(
                3,
                summary["passport_count"],
            )

            self.assertEqual(
                {
                    "IRLT",
                    "COMPOUNDING",
                    "DSCSA",
                },
                set(summary["first_tier_tracks"]),
            )

            for scenario in summary["scenarios"]:
                self.assertFalse(
                    scenario["execution_performed"]
                )

                display = read_json(
                    project /
                    "runs" /
                    scenario["scenario_name"] /
                    "display_contract.json"
                )

                self.assertEqual(
                    "DISPLAY / WITNESS ONLY",
                    display["display_authority"],
                )

                self.assertFalse(
                    display["can_release"]
                )

                self.assertFalse(
                    display["can_execute"]
                )

            tamper_rows = [
                item
                for item in summary["scenarios"]
                if item["scenario_name"].endswith(
                    "02_evidence_tamper_failure"
                )
            ]

            domain_rows = [
                item
                for item in summary["scenarios"]
                if item["scenario_name"].endswith(
                    "03_domain_failure"
                )
            ]

            self.assertEqual(3, len(tamper_rows))
            self.assertEqual(3, len(domain_rows))

            for item in tamper_rows:
                self.assertEqual(
                    "REHASH_MISMATCH",
                    item["integrity_state"],
                )

                self.assertEqual(
                    "ACTIVE",
                    item["no_bind_state"],
                )

                self.assertEqual(
                    "HELD",
                    item["action_admissibility_state"],
                )

            for item in domain_rows:
                self.assertFalse(
                    item["dependencies_satisfied"]
                )

                self.assertEqual(
                    "ACTIVE",
                    item["no_bind_state"],
                )

                self.assertEqual(
                    "HELD",
                    item["action_admissibility_state"],
                )

            self.assertEqual(
                "PASS",
                api_result["status"],
            )

            self.assertTrue(
                api_result["checks"][
                    "all_expected_gets_return_200"
                ]
            )

            self.assertTrue(
                api_result["checks"][
                    "all_write_methods_rejected"
                ]
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)