"""Deterministic canonical serialization utilities."""

import hashlib
import json
from typing import Any


def canonical_json_text(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonical_json_bytes(value: Any) -> bytes:
    return canonical_json_text(value).encode("utf-8")


def deterministic_id(namespace: str, value: Any) -> str:
    digest = hashlib.sha256(
        namespace.encode("utf-8") + b":" + canonical_json_bytes(value)
    ).hexdigest()
    return f"{namespace}-{digest[:24]}"
