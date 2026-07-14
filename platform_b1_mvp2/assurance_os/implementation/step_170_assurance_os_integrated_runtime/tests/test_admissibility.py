import unittest

from src.admissibility import (
    determine_admissibility,
)


class AdmissibilityTests(unittest.TestCase):
    def test_dependency_failure_withholds_action(self):
        result = determine_admissibility(
            {"valid": True},
            {"valid": False},
            {"authority_valid": True},
        )

        self.assertEqual(
            result["decision"],
            "NOT_ADMISSIBLE",
        )

        self.assertEqual(
            result["no_bind_state"],
            "ACTIVE",
        )

        self.assertTrue(
            result["action_held"]
        )


if __name__ == "__main__":
    unittest.main()
