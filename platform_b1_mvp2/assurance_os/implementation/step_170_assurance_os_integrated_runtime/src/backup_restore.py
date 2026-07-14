import json
from pathlib import Path

from .canonicalization import (
    sha256_json,
    write_json,
)


def create_backup(
    source_payload,
    backup_path,
):
    backup = {
        "schema_version": "1.0",
        "payload": source_payload,
        "payload_sha256": (
            sha256_json(source_payload)
        ),
    }

    write_json(backup_path, backup)
    return backup


def verify_restore(
    backup_path,
    verification_path,
):
    backup = json.loads(
        Path(backup_path).read_text(
            encoding="utf-8"
        )
    )

    actual = sha256_json(
        backup["payload"]
    )

    valid = (
        actual ==
        backup.get("payload_sha256")
    )

    result = {
        "schema_version": "1.0",
        "restore_verified": valid,
        "expected_sha256": (
            backup.get("payload_sha256")
        ),
        "actual_sha256": actual,
        "fail_closed": not valid,
    }

    write_json(
        verification_path,
        result,
    )

    return result
