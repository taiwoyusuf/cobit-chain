"""Authorized scenario registry validation."""

from typing import Mapping, Sequence


AUTHORIZED_SCENARIO_TYPES = (
    "GOVERNED_SUCCESS",
    "EVIDENCE_PROVENANCE_FAILURE",
    "DEPENDENCY_SOURCE_DISAGREEMENT",
    "AUTHORITY_OR_NO_BIND_HOLD",
    "CORRECTION_RECOVERY_REVALIDATION_SUCCESS",
)


def validate_scenarios(scenarios: Sequence[Mapping[str, object]]) -> dict:
    identifiers = [
        str(item.get("scenario_id"))
        for item in scenarios
    ]

    types = {
        str(item.get("scenario_type"))
        for item in scenarios
    }

    passed = (
        len(scenarios) == 20
        and len(set(identifiers)) == 20
        and types == set(AUTHORIZED_SCENARIO_TYPES)
    )

    return {
        "passed": passed,
        "scenario_count": len(scenarios),
    }


def select_scenario(
    scenarios: Sequence[Mapping[str, object]],
    scenario_id: str,
) -> dict:
    for scenario in scenarios:
        if scenario.get("scenario_id") == scenario_id:
            return dict(scenario)

    raise ValueError("Unauthorized scenario")
