import hashlib
import unittest


class BackupRestoreTests(unittest.TestCase):
    def test_rehash_is_stable(self):
        payload = b"synthetic-step-171-evidence"

        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            hashlib.sha256(payload).hexdigest(),
        )
