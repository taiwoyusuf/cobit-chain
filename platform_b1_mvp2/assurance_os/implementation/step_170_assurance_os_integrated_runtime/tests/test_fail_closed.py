import unittest

from src.admissibility import (
    determine_admissibility,
)
from src.authority_no_bind import (
    evaluate_authority,
)
from src.dependency_lens import (
    evaluate_dependencies,
)


class FailClosedTests(unittest.TestCase):
    def test_unknown_inputs_fail_closed(self):
        authority = evaluate_authority({})
        dependencies = (
            evaluate_dependencies([])
        )

        decision = determine_admissibility(
            {"valid": False},
            dependencies,
            authority,
        )

        self.assertEqual(
            decision["decision"],
            "NOT_ADMISSIBLE",
        )

        self.assertEqual(
            decision["no_bind_state"],
            "ACTIVE",
        )


if __name__ == "__main__":
    unittest.main()
