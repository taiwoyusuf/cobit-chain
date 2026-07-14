import unittest

from src.authority_no_bind import (
    evaluate_authority,
)


class AuthorityNoBindTests(unittest.TestCase):
    def test_absent_authority_activates_no_bind(self):
        result = evaluate_authority({})

        self.assertEqual(
            result["no_bind_state"],
            "ACTIVE",
        )

        self.assertTrue(
            result["action_held"]
        )


if __name__ == "__main__":
    unittest.main()
