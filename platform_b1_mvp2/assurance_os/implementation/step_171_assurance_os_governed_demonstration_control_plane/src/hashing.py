"""SHA-256 hashing and seal verification."""

import hashlib
from typing import Any, Mapping

from .canonical import canonical_json_bytes


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest().upper()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def make_seal(value: Any) -> dict:
    return {
        "algorithm": "SHA-256",
        "digest": sha256_json(value),
        "valid": True,
    }


def verify_seal(value: Any, seal: Mapping[str, object]) -> bool:
    return (
        seal.get("algorithm") == "SHA-256"
        and seal.get("valid") is True
        and seal.get("digest") == sha256_json(value)
    )
