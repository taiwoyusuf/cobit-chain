"""Synthetic deterministic Step 172C runtime component.

Platform B1 evaluates assurance state. Source systems remain authoritative.
Only an accountable human may bind regulated action.
RAMAT Vision and Thread D2 are display-only.
"""

from typing import Any, Dict, List


NO_BIND_FIELDS = (
    "authority_present",
    "authority_valid",
    "authority_current",
    "authority_delegated",
    "approver_available",
    "human_accountability_identified",
)


def evaluate_no_bind(
    authority_result: Dict[str, Any],
    escalation_required: bool = False,
) -> Dict[str, Any]:
    failures: List[str] = [
        field
        for field in NO_BIND_FIELDS
        if not authority_result.get(field, False)
    ]

    if (
        escalation_required
        and not authority_result.get(
            "escalation_available",
            False,
        )
    ):
        failures.append(
            "escalation_available"
        )

    return {
        "no_bind_state": bool(failures),
        "failures": sorted(set(failures)),
        "silence_is_consent": False,
    }
