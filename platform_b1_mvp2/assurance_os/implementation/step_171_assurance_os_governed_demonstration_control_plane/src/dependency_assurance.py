"""Workflow dependency assurance."""

from typing import Mapping, Sequence


def evaluate_dependencies(
    dependencies: Sequence[Mapping[str, object]],
) -> dict:
    results = []

    for dependency in dependencies:
        complete = dependency.get("complete") is True
        mapped = dependency.get("mapping_valid") is True
        current = dependency.get("current") is True
        passed = complete and mapped and current

        results.append({
            "dependency_id": dependency.get("dependency_id"),
            "passed": passed,
            "complete": complete,
            "mapping_valid": mapped,
            "current": current,
        })

    overall = bool(results) and all(item["passed"] for item in results)

    return {
        "passed": overall,
        "results": results,
        "result": "PASS" if overall else "FAIL_CLOSED",
    }
