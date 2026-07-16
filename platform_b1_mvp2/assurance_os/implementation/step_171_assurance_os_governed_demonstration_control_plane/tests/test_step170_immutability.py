import unittest


CANONICAL_COMMIT = "ea22f14a84f7beeea3f446123059fc65660c38e6"


class Step170ImmutabilityTests(unittest.TestCase):
    def test_commit_is_pinned(self):
        self.assertEqual(len(CANONICAL_COMMIT), 40)
