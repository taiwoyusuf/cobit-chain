import unittest

from src.dependency_lens import (
    evaluate_dependencies,
)


class DependencyLensTests(unittest.TestCase):
    def test_mismatch_fails_closed(self):
        result = evaluate_dependencies([
            {
                "name": "lis",
                "required": True,
                "present": True,
                "current": True,
                "agrees": False,
            }
        ])

        self.assertFalse(result["valid"])
        self.assertEqual(
            result["state"],
            "DEPENDENCY_FAILURE",
        )


if __name__ == "__main__":
    unittest.main()
