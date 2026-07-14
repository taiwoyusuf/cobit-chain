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

from assurance_slice import read_json, run_demo


class AssuranceSliceTests(unittest.TestCase):
    def test_success_tamper_hold_and_recovery(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project = (
                Path(temp_dir) /
                "slice"
            )

            for name in (
                "config",
                "data",
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
                summary["scenario_count"],
            )

            (
                baseline,
                tamper,
                recovery,
            ) = summary["scenarios"]

            self.assertEqual(
                "ADMISSIBLE",
                baseline[
                    "action_admissibility_state"
                ],
            )

            self.assertEqual(
                "REHASH_VERIFIED",
                baseline["integrity_state"],
            )

            self.assertEqual(
                "HELD",
                tamper[
                    "action_admissibility_state"
                ],
            )

            self.assertEqual(
                "ACTIVE",
                tamper["no_bind_state"],
            )

            self.assertEqual(
                "REHASH_MISMATCH",
                tamper["integrity_state"],
            )

            self.assertIn(
                "EVIDENCE INSUFFICIENT",
                tamper["display_states"],
            )

            self.assertIn(
                "NO-BIND STATE ACTIVE",
                tamper["display_states"],
            )

            self.assertIn(
                "ACTION HELD",
                tamper["display_states"],
            )

            self.assertEqual(
                "ADMISSIBLE",
                recovery[
                    "action_admissibility_state"
                ],
            )

            self.assertEqual(
                "REHASH_VERIFIED",
                recovery["integrity_state"],
            )

            display = read_json(
                project /
                "runs" /
                "02_tamper_failure" /
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


if __name__ == "__main__":
    unittest.main(verbosity=2)