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

from triad_kernel import read_json, run_demo


class TriadKernelTests(unittest.TestCase):
    def test_all_three_first_tier_tracks(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project = Path(temp_dir) / "triad"

            for name in (
                "config",
                "manifests",
            ):
                source = ROOT / name

                if source.exists():
                    shutil.copytree(
                        source,
                        project / name,
                    )

            summary = run_demo(project)

            self.assertEqual(
                "PASS",
                summary["overall_status"],
            )

            self.assertEqual(
                3,
                summary["first_tier_track_count"],
            )

            self.assertEqual(
                9,
                summary["scenario_count"],
            )

            self.assertEqual(
                {
                    "IRLT",
                    "COMPOUNDING",
                    "DSCSA",
                },
                set(
                    summary["first_tier_tracks"]
                ),
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

            tamper_scenarios = [
                item
                for item in summary["scenarios"]
                if item["scenario_name"].endswith(
                    "02_tamper_failure"
                )
            ]

            self.assertEqual(
                3,
                len(tamper_scenarios),
            )

            for scenario in tamper_scenarios:
                self.assertEqual(
                    "REHASH_MISMATCH",
                    scenario["integrity_state"],
                )

                self.assertEqual(
                    "ACTIVE",
                    scenario["no_bind_state"],
                )

                self.assertEqual(
                    "HELD",
                    scenario[
                        "action_admissibility_state"
                    ],
                )

                self.assertIn(
                    "EVIDENCE INSUFFICIENT",
                    scenario["display_states"],
                )

                self.assertIn(
                    "NO-BIND STATE ACTIVE",
                    scenario["display_states"],
                )

                self.assertIn(
                    "ACTION HELD",
                    scenario["display_states"],
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)