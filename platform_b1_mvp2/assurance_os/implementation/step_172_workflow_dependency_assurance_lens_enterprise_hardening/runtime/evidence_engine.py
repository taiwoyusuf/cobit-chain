"""Synthetic deterministic Step 172C runtime component.

Platform B1 evaluates assurance state. Source systems remain authoritative.
Only an accountable human may bind regulated action.
RAMAT Vision and Thread D2 are display-only.
"""

from typing import Any, Dict, List


def evaluate_evidence(
    evidence_records: List[Dict[str, Any]],
) -> Dict[str, Any]:
    required = [
        item
        for item in evidence_records
        if item.get("required", True)
    ]

    present = bool(required) and all(
        item.get("present", False)
        for item in required
    )

    integrity_valid = present and all(
        item.get("integrity_valid", False)
        for item in required
    )

    current = present and all(
        item.get("current", False)
        for item in required
    )

    return {
        "evidence_present": present,
        "evidence_integrity_valid": integrity_valid,
        "evidence_current": current,
    }
