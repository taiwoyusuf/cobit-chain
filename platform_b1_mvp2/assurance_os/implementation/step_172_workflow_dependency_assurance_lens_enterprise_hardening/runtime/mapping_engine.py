"""Synthetic deterministic Step 172C runtime component.

Platform B1 evaluates assurance state. Source systems remain authoritative.
Only an accountable human may bind regulated action.
RAMAT Vision and Thread D2 are display-only.
"""

from typing import Any, Dict, List


def validate_mappings(
    mappings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    required = [
        item
        for item in mappings
        if item.get("required", True)
    ]

    present = bool(required) and all(
        item.get("present", False)
        for item in required
    )

    valid = present and all(
        item.get("valid", False)
        and item.get("source_identifier")
        and item.get("target_identifier")
        for item in required
    )

    return {
        "mapping_present": present,
        "mapping_valid": valid,
    }
