"""Synthetic deterministic Step 172C runtime component.

Platform B1 evaluates assurance state. Source systems remain authoritative.
Only an accountable human may bind regulated action.
RAMAT Vision and Thread D2 are display-only.
"""

import hashlib
from pathlib import Path
from typing import Dict


CONTROLLED_SELF_REFERENCE = "CONTROLLED_SELF_REFERENCE"


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest().upper()


def file_record(path: Path) -> Dict[str, object]:
    payload = path.read_bytes()

    return {
        "byte_length": len(payload),
        "sha256": sha256_bytes(payload),
    }
