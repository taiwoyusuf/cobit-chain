import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DisplayOnlyTests(unittest.TestCase):
    def test_display_authority_is_non_binding(self):
        path = (
            ROOT.parents[1]
            / "inventory"
            / "step_171_assurance_os_governed_demonstration_control_plane_scope_review"
            / "authority_and_binding_boundary.json"
        )

        data = json.loads(
            path.read_text(encoding="utf-8")
        )

        self.assertEqual(
            data["ramat_vision"],
            "DISPLAY_ONLY",
        )

        self.assertFalse(
            data["software_can_bind"]
        )
