import unittest

from src.canonicalization import (
    canonical_json,
    sha256_json,
)


class CanonicalizationTests(unittest.TestCase):
    def test_key_order_is_deterministic(self):
        left = {"b": 2, "a": 1}
        right = {"a": 1, "b": 2}

        self.assertEqual(
            canonical_json(left),
            canonical_json(right),
        )

        self.assertEqual(
            sha256_json(left),
            sha256_json(right),
        )


if __name__ == "__main__":
    unittest.main()
