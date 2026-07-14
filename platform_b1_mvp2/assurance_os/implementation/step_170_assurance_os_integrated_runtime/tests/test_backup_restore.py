import tempfile
import unittest
from pathlib import Path

from src.backup_restore import (
    create_backup,
    verify_restore,
)


class BackupRestoreTests(unittest.TestCase):
    def test_restore_rehashes_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            backup = root / "backup.json"
            verification = (
                root /
                "verification.json"
            )

            create_backup(
                {"value": "synthetic"},
                backup,
            )

            result = verify_restore(
                backup,
                verification,
            )

            self.assertTrue(
                result["restore_verified"]
            )


if __name__ == "__main__":
    unittest.main()
