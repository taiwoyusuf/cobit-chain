"""Synthetic deterministic Step 172C runtime component.

Platform B1 evaluates assurance state. Source systems remain authoritative.
Only an accountable human may bind regulated action.
RAMAT Vision and Thread D2 are display-only.
"""

from typing import Any, Dict, List


def compare_source_states(
    snapshots: List[Dict[str, Any]],
) -> Dict[str, Any]:
    available = bool(snapshots) and all(
        item.get("availability_state") == "AVAILABLE"
        for item in snapshots
    )

    current = available and all(
        item.get("current", False)
        for item in snapshots
    )

    state_values = {
        (
            item.get("state_code"),
            item.get("regulated_object_id"),
        )
        for item in snapshots
        if item.get("availability_state") == "AVAILABLE"
    }

    agreed = (
        available
        and current
        and len(state_values) == 1
    )

    return {
        "source_state_available": available,
        "source_state_current": current,
        "source_state_agreement": agreed,
        "snapshots_preserved": True,
        "silent_reconciliation": False,
        "human_review_required": available and not agreed,
    }
