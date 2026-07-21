"""
Static local deterministic unit-test definition for test_compoundsafe_preparation.

Planning assumption only. Synthetic data only.
No scenario, acceptance, tamper, recovery, or determinism execution occurs in Step 174C.
"""

import unittest


PLANNING_ASSUMPTION = True
SYNTHETIC_ONLY = True
NETWORK_ALLOWED = False
PRODUCTION_DATA_ALLOWED = False
HARDWARE_ALLOWED = False

EXPECTED_OUTCOMES = (
    "ALLOW",
    "HOLD",
    "NO-BIND",
    "DENY",
    "FAIL-CLOSED",
)

EXPECTED_PRECEDENCE = (
    "DENY",
    "FAIL-CLOSED",
    "NO-BIND",
    "HOLD",
    "ALLOW",
)

RAMAT_PROHIBITED = (
    "approve",
    "release",
    "override",
    "write_back",
    "reconcile_source_states",
    "resolve_holds",
    "bind_regulated_action",
    "replace_official_record",
    "replace_accountable_human",
)


def build_synthetic_sample():
    return {
        "planning_assumption": True,
        "synthetic_only": True,
        "decision_outcomes": EXPECTED_OUTCOMES,
        "decision_precedence": EXPECTED_PRECEDENCE,
        "official_records_remain_external": True,
        "accountable_human_preserved": True,
        "no_bind_when_authority_insufficient": True,
        "source_disagreement_represented": True,
        "silent_reconciliation_permitted": False,
        "ramat_binding_authority": False,
    }


class TestCompoundsafePreparation(unittest.TestCase):
    def test_synthetic_and_planning_boundary(self):
        sample = build_synthetic_sample()
        self.assertTrue(sample["planning_assumption"])
        self.assertTrue(sample["synthetic_only"])
        self.assertFalse(NETWORK_ALLOWED)
        self.assertFalse(PRODUCTION_DATA_ALLOWED)
        self.assertFalse(HARDWARE_ALLOWED)

    def test_decision_outcome_and_precedence_contract(self):
        sample = build_synthetic_sample()
        self.assertEqual(
            tuple(sample["decision_outcomes"]),
            EXPECTED_OUTCOMES,
        )
        self.assertEqual(
            tuple(sample["decision_precedence"]),
            EXPECTED_PRECEDENCE,
        )

    def test_authority_source_nobind_and_ramat_contract(self):
        sample = build_synthetic_sample()
        self.assertTrue(
            sample["official_records_remain_external"]
        )
        self.assertTrue(
            sample["accountable_human_preserved"]
        )
        self.assertTrue(
            sample["no_bind_when_authority_insufficient"]
        )
        self.assertTrue(
            sample["source_disagreement_represented"]
        )
        self.assertFalse(
            sample["silent_reconciliation_permitted"]
        )
        self.assertFalse(
            sample["ramat_binding_authority"]
        )
        self.assertIn(
            "bind_regulated_action",
            RAMAT_PROHIBITED,
        )


if __name__ == "__main__":
    unittest.main()
