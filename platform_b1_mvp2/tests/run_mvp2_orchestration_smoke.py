"""
Platform B1 / MVP2 local orchestration smoke runner.

Purpose:
Prove the first local MVP2 chain:

mock data -> evaluator registry -> evaluator -> Thread D2 display fixture

Boundary:
- Local smoke runner only.
- No Azure deployment.
- No Platform B v1 change.
- No Thread D v1 change.
- No real ServiceNow, LIS, middleware, eQMS, PHI, GMP production data, or company production data.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict


REPO_ROOT = Path(__file__).resolve().parents[2]
PLATFORM_B1_ROOT = REPO_ROOT / "platform_b1_mvp2"
EVALUATOR_DIR = PLATFORM_B1_ROOT / "evaluators"

sys.path.insert(0, str(EVALUATOR_DIR))

from evaluator_registry import get_workflow_dependency_evaluator  # noqa: E402
from workflow_dependency_evaluator import evaluate_workflow_dependency  # noqa: E402


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def run_orchestration_smoke() -> Dict[str, Any]:
    registry_entry = get_workflow_dependency_evaluator()

    mock_path = REPO_ROOT / registry_entry["mock_record"]
    d2_fixture_path = REPO_ROOT / registry_entry["d2_display_fixture"]
    schema_path = REPO_ROOT / registry_entry["schema"]

    if not mock_path.exists():
        raise FileNotFoundError(f"Mock record not found: {mock_path}")

    if not d2_fixture_path.exists():
        raise FileNotFoundError(f"D2 display fixture not found: {d2_fixture_path}")

    if not schema_path.exists():
        raise FileNotFoundError(f"Schema not found: {schema_path}")

    mock_record = _load_json(mock_path)
    d2_fixture = _load_json(d2_fixture_path)

    evaluator_result = evaluate_workflow_dependency(mock_record)

    required_outputs = [
        "WORKFLOW APPEARS COMPLETE BUT BLOCKED",
        "LIS HOLD DETECTED",
        "MIDDLEWARE VERIFIED ONLY",
        "MANDATORY FIELD MISSING",
        "SECONDARY REVIEW REQUIRED",
        "RESULT RELEASE NOT ADMISSIBLE",
    ]

    missing_outputs = [
        output for output in required_outputs
        if output not in evaluator_result.get("outputs", [])
    ]

    if missing_outputs:
        raise AssertionError(f"Missing evaluator outputs: {missing_outputs}")

    checks = {
        "feature_name_matches_registry": evaluator_result.get("feature_name") == registry_entry["feature_name"],
        "status_matches_d2_headline": evaluator_result.get("status") == d2_fixture["headline"],
        "reason_matches_d2_reason": evaluator_result.get("reason") == d2_fixture["reason"],
        "required_action_matches_d2": evaluator_result.get("required_action") == d2_fixture["required_action"],
        "evidence_state_matches_d2": evaluator_result.get("evidence_state") == d2_fixture["evidence_state"],
        "severity_matches_d2": evaluator_result.get("severity") == d2_fixture["severity"],
        "registry_points_to_evaluator": "workflow_dependency_evaluator.py" in registry_entry["evaluator_module"],
        "registry_points_to_d2_fixture": "workflow_dependency_d2_display_fixture.json" in registry_entry["d2_display_fixture"],
        "official_records_guardrail_present": "Official records remain in source systems" in registry_entry["guardrail"],
        "glasses_no_release_guardrail_present": "Glasses do not release results" in registry_entry["guardrail"],
    }

    failed_checks = [name for name, passed in checks.items() if not passed]

    if failed_checks:
        raise AssertionError(f"Failed orchestration checks: {failed_checks}")

    return {
        "smoke_status": "PASS",
        "chain": "mock data -> evaluator registry -> evaluator -> Thread D2 display fixture",
        "feature_name": registry_entry["feature_name"],
        "feature_id": registry_entry["feature_id"],
        "primary_case": registry_entry["primary_case"],
        "mock_record": registry_entry["mock_record"],
        "schema": registry_entry["schema"],
        "evaluator_module": registry_entry["evaluator_module"],
        "d2_display_fixture": registry_entry["d2_display_fixture"],
        "headline": evaluator_result.get("status"),
        "reason": evaluator_result.get("reason"),
        "required_action": evaluator_result.get("required_action"),
        "evidence_state": evaluator_result.get("evidence_state"),
        "severity": evaluator_result.get("severity"),
        "outputs": evaluator_result.get("outputs", []),
        "validated_checks": checks,
        "boundary": [
            "Local smoke runner only.",
            "No Azure deployment.",
            "No Platform B v1 change.",
            "No Thread D v1 change.",
            "Official records remain in source systems.",
            "Thread D2 displays Platform B1 output.",
            "Glasses do not release results."
        ]
    }


def main() -> int:
    result = run_orchestration_smoke()
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
