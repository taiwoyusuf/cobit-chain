"""Synthetic deterministic Step 172C runtime component.

Platform B1 evaluates assurance state. Source systems remain authoritative.
Only an accountable human may bind regulated action.
RAMAT Vision and Thread D2 are display-only.
"""

import json
from typing import Any


def normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): normalize(value[key])
            for key in sorted(value)
        }

    if isinstance(value, list):
        return [
            normalize(item)
            for item in value
        ]

    if isinstance(value, tuple):
        return [
            normalize(item)
            for item in value
        ]

    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
