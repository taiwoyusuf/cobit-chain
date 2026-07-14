from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(ROOT / "src"),
)

from demonstration_console import (
    read_json,
    verify,
)


class Step166ConsoleTests(unittest.TestCase):
    def test_generated_console_bundle(self) -> None:
        summary = verify(ROOT)

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
            1,
            summary["console_count"],
        )

        self.assertFalse(
            summary["checks"][
                "platform_b_v1_modified"
            ]
        )

        self.assertFalse(
            summary["checks"][
                "thread_d_v1_modified"
            ]
        )

        self.assertFalse(
            summary["checks"][
                "production_write_back_performed"
            ]
        )

        bundle = read_json(
            ROOT /
            "bundle" /
            "inspection_passport_bundle.json"
        )

        self.assertFalse(
            bundle["execution_performed"]
        )

        self.assertFalse(
            bundle[
                "production_write_back_performed"
            ]
        )

        self.assertFalse(
            bundle["phi_used"]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)