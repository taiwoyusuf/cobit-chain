import unittest

from src.display_contracts import (
    build_display_contract,
)


class DisplayContractTests(unittest.TestCase):
    def test_contract_cannot_bind(self):
        contract = build_display_contract(
            "irlt",
            "IRLT_01",
            {
                "authority_state": (
                    "AUTHORITY_VERIFIED"
                ),
            },
            {
                "decision": "ADMISSIBLE",
                "no_bind_state": "INACTIVE",
                "action_held": False,
                "escalation_required": False,
                "documented_pause_created": False,
            },
        )

        self.assertTrue(
            contract["display_only"]
        )

        self.assertFalse(
            contract["can_approve"]
        )

        self.assertFalse(
            contract["can_bind"]
        )


if __name__ == "__main__":
    unittest.main()
