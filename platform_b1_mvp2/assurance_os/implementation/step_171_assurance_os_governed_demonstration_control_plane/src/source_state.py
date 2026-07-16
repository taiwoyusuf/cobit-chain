"""Authoritative source-state agreement verification."""

from typing import Mapping, Sequence


def evaluate_source_states(
    source_states: Sequence[Mapping[str, object]],
) -> dict:
    results = []

    for state in source_states:
        authoritative = state.get("authoritative") is True
        agreement = state.get("agreement") is True
        available = state.get("available") is True
        passed = authoritative and agreement and available

        results.append({
            "source_id": state.get("source_id"),
            "passed": passed,
            "authoritative": authoritative,
            "agreement": agreement,
            "available": available,
        })

    overall = bool(results) and all(item["passed"] for item in results)

    return {
        "passed": overall,
        "results": results,
        "source_systems_authoritative": True,
        "result": "PASS" if overall else "FAIL_CLOSED",
    }
