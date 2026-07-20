"""
Local source-only unit-test definition for power cold chain.

The test source is not executed during Step 173C.
"""

from __future__ import annotations

import unittest


TEST_ID = "power_cold_chain"
ALLOWED_OUTCOMES = (
    "ALLOW",
    "HOLD",
    "NO-BIND",
    "DENY",
    "FAIL-CLOSED",
)
PRECEDENCE = (
    "DENY",
    "FAIL-CLOSED",
    "NO-BIND",
    "HOLD",
    "ALLOW",
)


class StaticContractTest(unittest.TestCase):
    """Pure local contract assertions with no network or hardware dependency."""

    def test_outcome_contract(self) -> None:
        self.assertEqual(len(ALLOWED_OUTCOMES), 5)

    def test_precedence_contract(self) -> None:
        self.assertEqual(PRECEDENCE[0], "DENY")
        self.assertEqual(PRECEDENCE[-1], "ALLOW")

    def test_source_identity(self) -> None:
        self.assertTrue(TEST_ID)


TEST_METADATA = {
    "test_id": TEST_ID,
    "source_only": True,
    "executed_in_step_173c": False,
}
