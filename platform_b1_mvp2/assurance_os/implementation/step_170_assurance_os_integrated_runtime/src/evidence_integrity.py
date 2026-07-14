from .canonicalization import sha256_json


def create_seal(payload, object_id, timestamp):
    return {
        "schema_version": "1.0",
        "object_id": object_id,
        "algorithm": "SHA-256",
        "canonicalization": "JSON_SORTED_KEYS_COMPACT_UTF8",
        "payload_sha256": sha256_json(payload),
        "sealed_at": timestamp,
        "state": "SEALED",
    }


def verify_payload(payload, seal):
    actual = sha256_json(payload)
    expected = seal.get("payload_sha256")
    valid = bool(expected) and actual == expected

    return {
        "state": (
            "VERIFIED"
            if valid
            else "INTEGRITY_FAILURE"
        ),
        "valid": valid,
        "expected_sha256": expected,
        "actual_sha256": actual,
        "fail_closed": not valid,
    }
