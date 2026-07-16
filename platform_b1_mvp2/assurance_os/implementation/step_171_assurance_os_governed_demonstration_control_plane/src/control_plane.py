"""Governed orchestration and execution-time revalidation."""

from typing import Mapping, Sequence

from .no_bind import derive_no_bind
from .preflight import perform_preflight
from .session_manifest import build_session_manifest
from .step170_reference import validate_reference_set


ADMISSIBLE_PLATFORM_STATES = {
    "ADMISSIBLE",
    "ADMISSIBLE_AFTER_CORRECTION",
}


def evaluate_session(
    track: Mapping[str, object],
    scenario: Mapping[str, object],
    fixture: Mapping[str, object],
    canonical_commit: str,
    step170_references: Sequence[Mapping[str, object]],
) -> dict:
    references = validate_reference_set(
        step170_references,
        canonical_commit,
    )

    manifest = build_session_manifest(
        track,
        scenario,
        canonical_commit,
        step170_references,
    )

    preflight = perform_preflight(fixture)

    platform_state = str(
        fixture.get(
            "platform_b1_action_admissibility",
            "NOT_ADMISSIBLE",
        )
    )

    timing_valid = (
        fixture.get("execution_timing_valid") is True
    )

    revalidation_passed = (
        references["passed"]
        and preflight["passed"]
        and timing_valid
        and platform_state in ADMISSIBLE_PLATFORM_STATES
    )

    handoff = derive_no_bind(
        preflight,
        revalidation_passed,
        str(fixture["identity"]["accountable_human_id"]),
    )

    disposition = (
        "ADMISSIBLE_FOR_SIMULATED_HUMAN_HANDOFF"
        if revalidation_passed
        else "ACTION_HELD"
    )

    return {
        "session_manifest": manifest,
        "preflight": preflight,
        "step170_references": references,
        "platform_b1_state": platform_state,
        "platform_b1_consumed_read_only": True,
        "execution_revalidation": {
            "passed": revalidation_passed,
            "timing_valid": timing_valid,
            "fail_closed": not revalidation_passed,
        },
        "no_bind_handoff": handoff,
        "disposition": disposition,
        "software_can_approve": False,
        "software_can_bind": False,
        "software_can_release": False,
        "software_can_override": False,
        "software_can_write_back": False,
        "source_systems_authoritative": True,
        "display_only": True,
    }
