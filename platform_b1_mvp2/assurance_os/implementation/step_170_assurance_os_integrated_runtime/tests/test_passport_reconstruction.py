import unittest

from src.passport_builder import build_passport
from src.reconstruction import (
    build_reconstruction,
)


class PassportReconstructionTests(
    unittest.TestCase
):
    def test_decision_is_reconstructable(self):
        evidence = {
            "state": "VERIFIED",
            "valid": True,
        }

        dependencies = {
            "state": "DEPENDENCIES_VERIFIED",
            "valid": True,
        }

        authority = {
            "authority_state": (
                "AUTHORITY_VERIFIED"
            ),
            "authority_valid": True,
            "no_bind_state": "INACTIVE",
        }

        decision = {
            "decision": "ADMISSIBLE",
            "no_bind_state": "INACTIVE",
            "action_held": False,
            "escalation_required": False,
            "documented_pause_created": False,
            "reasons": [],
            "fail_closed": False,
        }

        passport = build_passport(
            "irlt",
            "IRLT_01",
            {"object_id": "O1"},
            {"state": "VERIFIED"},
            evidence,
            dependencies,
            authority,
            decision,
            "2026-07-13T00:00:00Z",
        )

        reconstruction = (
            build_reconstruction(
                "irlt",
                "IRLT_01",
                evidence,
                dependencies,
                authority,
                decision,
                "2026-07-13T00:00:00Z",
            )
        )

        self.assertEqual(
            passport[
                "action_admissibility"
            ]["decision"],
            "ADMISSIBLE",
        )

        self.assertTrue(
            reconstruction[
                "history_preserved"
            ]
        )


if __name__ == "__main__":
    unittest.main()
