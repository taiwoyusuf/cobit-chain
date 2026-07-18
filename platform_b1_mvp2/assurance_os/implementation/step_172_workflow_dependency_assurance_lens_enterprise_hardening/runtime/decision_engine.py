"""Synthetic deterministic Step 172C runtime component.

Platform B1 evaluates assurance state. Source systems remain authoritative.
Only an accountable human may bind regulated action.
RAMAT Vision and Thread D2 are display-only.
"""

from typing import Any, Dict, List


PRECEDENCE = (
    "DENY",
    "FAIL-CLOSED",
    "NO-BIND",
    "HOLD",
    "ALLOW",
)


def determine_outcome(
    dimensions: Dict[str, Any],
) -> Dict[str, Any]:
    reasons: List[str] = []

    deny_conditions = [
        not dimensions.get(
            "dependency_identity_valid",
            False,
        ),
        not dimensions.get(
            "evidence_integrity_valid",
            False,
        ),
        bool(
            dimensions.get(
                "prohibited_action",
                False,
            )
        ),
    ]

    fail_closed_conditions = [
        not dimensions.get(
            "dependency_present",
            False,
        ),
        not dimensions.get(
            "source_state_available",
            False,
        ),
        not dimensions.get(
            "mapping_present",
            False,
        ),
        not dimensions.get(
            "mapping_valid",
            False,
        ),
        not dimensions.get(
            "workflow_sequence_valid",
            False,
        ),
    ]

    no_bind = bool(
        dimensions.get(
            "no_bind_state",
            False,
        )
    )

    hold_conditions = [
        not dimensions.get(
            "dependency_current",
            False,
        ),
        not dimensions.get(
            "source_state_current",
            False,
        ),
        not dimensions.get(
            "source_state_agreement",
            False,
        ),
        not dimensions.get(
            "evidence_present",
            False,
        ),
        not dimensions.get(
            "evidence_current",
            False,
        ),
        not dimensions.get(
            "timing_valid",
            False,
        ),
    ]

    if any(deny_conditions):
        outcome = "DENY"
        reasons.append(
            "A deny-precedence integrity or prohibited-action condition exists."
        )
    elif any(fail_closed_conditions):
        outcome = "FAIL-CLOSED"
        reasons.append(
            "A critical dependency, source, mapping, or sequence condition failed."
        )
    elif no_bind:
        outcome = "NO-BIND"
        reasons.append(
            "Sufficient accountable human authority is unavailable."
        )
    elif any(hold_conditions):
        outcome = "HOLD"
        reasons.append(
            "A recoverable dependency, source, evidence, or timing condition requires review."
        )
    elif not dimensions.get(
        "release_or_execution_condition_satisfied",
        False,
    ):
        outcome = "HOLD"
        reasons.append(
            "The release or execution condition is not satisfied."
        )
    else:
        outcome = "ALLOW"
        reasons.append(
            "All mandatory assurance dimensions agree."
        )

    return {
        "outcome": outcome,
        "precedence": PRECEDENCE,
        "reasons": reasons,
        "human_binding_authority_required": True,
    }
