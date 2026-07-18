"""Synthetic deterministic Step 172C runtime component.

Platform B1 evaluates assurance state. Source systems remain authoritative.
Only an accountable human may bind regulated action.
RAMAT Vision and Thread D2 are display-only.
"""

from typing import Any, Dict, List


def build_reconstruction(
    evaluation_id: str,
    events: List[Dict[str, Any]],
    evidence_references: List[str],
    decision: Dict[str, Any],
) -> Dict[str, Any]:
    ordered_events = sorted(
        events,
        key=lambda item: (
            str(item.get("sequence", "")),
            str(item.get("event_id", "")),
        ),
    )

    return {
        "evaluation_id": evaluation_id,
        "ordered_events": ordered_events,
        "evidence_references": sorted(
            evidence_references
        ),
        "decision": decision,
        "read_only": True,
        "source_states_preserved": True,
        "human_binding_authority_required": True,
    }
