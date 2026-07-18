"""Synthetic deterministic Step 172C runtime component.

Platform B1 evaluates assurance state. Source systems remain authoritative.
Only an accountable human may bind regulated action.
RAMAT Vision and Thread D2 are display-only.
"""

from typing import Any, Dict, List


def evaluate_dependencies(
    dependencies: List[Dict[str, Any]],
) -> Dict[str, Any]:
    missing = [
        item.get("dependency_id", "")
        for item in dependencies
        if item.get("mandatory", True)
        and not item.get("present", False)
    ]

    stale = [
        item.get("dependency_id", "")
        for item in dependencies
        if item.get("present", False)
        and not item.get("current", False)
    ]

    identity_invalid = [
        item.get("dependency_id", "")
        for item in dependencies
        if item.get("present", False)
        and not item.get("identity_valid", False)
    ]

    return {
        "dependency_present": not missing,
        "dependency_identity_valid": not identity_invalid,
        "dependency_current": not stale,
        "missing": sorted(missing),
        "stale": sorted(stale),
        "identity_invalid": sorted(identity_invalid),
    }
