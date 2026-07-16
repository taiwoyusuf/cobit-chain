"""No-Bind governance and accountable-human handoff states."""

from typing import Mapping


def derive_no_bind(
    preflight: Mapping[str, object],
    revalidation_passed: bool,
    accountable_human_id: str,
) -> dict:
    passed = (
        preflight.get("passed") is True
        and revalidation_passed
    )

    if passed:
        return {
            "no_bind": False,
            "state": "READY_FOR_SIMULATED_HUMAN_HANDOFF",
            "documented_pause": False,
            "escalation_required": False,
            "accountable_human_id": accountable_human_id,
            "software_can_bind": False,
        }

    return {
        "no_bind": True,
        "state": "ACTION_HELD",
        "documented_pause": True,
        "escalation_required": True,
        "accountable_human_id": accountable_human_id,
        "software_can_bind": False,
    }
