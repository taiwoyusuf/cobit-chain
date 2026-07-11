from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Tuple


RESULT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_RESULT_SUMMARY_FIXTURE = (
    RESULT_DIR / "platform_b1_local_validation_result_summary_fixture.json"
)

VALIDATOR_NAME = "Platform B1 Local Validation Result Summary Fixture Validator"
VALIDATOR_STATUS = "LOCKED_RESULT_SUMMARY_FIXTURE_VALIDATOR_ONLY"

REQUIRED_TOP_LEVEL_FIELDS = {
    "fixture_name",
    "fixture_status",
    "workstream",
    "source_bundle",
    "source_bundle_status",
    "result_type",
    "summary_state",
    "validated_commands",
    "assurance_signals",
    "display_summary",
    "boundary",
}

EXPECTED_FIXTURE_NAME = "Platform B1 Local Validation Bundle Result Summary Fixture"
EXPECTED_FIXTURE_STATUS = "LOCKED_RESULT_SUMMARY_FIXTURE_ONLY"
EXPECTED_WORKSTREAM = "Platform B1 / MVP2"
EXPECTED_SOURCE_BUNDLE = "Platform B1 / MVP2 Local Validation Bundle"
EXPECTED_SOURCE_BUNDLE_STATUS = "LOCKED_LOCAL_VALIDATION_BUNDLE_ONLY"
EXPECTED_RESULT_TYPE = "LOCAL_VALIDATION_RESULT_SUMMARY"

EXPECTED_SUMMARY_STATE = {
    "overall_status": "PASSED",
    "validation_count": 4,
    "failed_validation_count": 0,
    "result_admissibility": "LOCAL_VALIDATION_SUMMARY_ONLY",
    "azure_deployment_status": "NOT_DEPLOYED",
    "platform_b_v1_impact": "NONE",
    "thread_d_v1_impact": "NONE",
    "mvp3_activation": "NONE",
}

REQUIRED_VALIDATED_COMMAND_IDS = {
    "digital_twin_object_model_unit_test",
    "digital_twin_mock_fixtures_unit_test",
    "digital_twin_mock_fixture_validator_cli",
    "digital_twin_mock_fixture_validator_unit_test",
}

REQUIRED_ASSURANCE_SIGNALS = {
    "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED",
    "DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED",
    "AI OUTPUT HASHED",
    "HASH VERIFIED",
    "AGENT ACTION NOT ADMISSIBLE",
    "RAMAT VISION DISPLAY READY",
    "PLATFORM B1 DECISION DISPLAYED",
}

EXPECTED_DISPLAY_SUMMARY = {
    "thread_d2_display_status": "PREVIEW_READY",
    "ramat_vision_display_status": "DISPLAY_READY",
}

REQUIRED_DISPLAY_TEXT = {
    "Platform B1 local validation bundle passed",
    "local validation summary only",
    "not a GMP approval",
    "product release decision",
    "source-system override",
    "Quality Unit replacement",
}

REQUIRED_BOUNDARY_PHRASES = {
    "Result summary fixture only.",
    "Local validation evidence only.",
    "No Azure deployment.",
    "No Azure Digital Twins deployment.",
    "No Platform B v1 change.",
    "No Thread D v1 change.",
    "No MVP3 activation.",
    "No real production system connection.",
    "No real ServiceNow production data.",
    "No real LIS, MES, ERP, eQMS, QMS, VRS, EPCIS, pharmacy, or radiopharma production data.",
    "No PHI.",
    "No company production data.",
    "No product release decision.",
    "No GMP approval decision.",
    "No source-system override.",
    "No Quality Unit replacement.",
    "Platform B1 evaluates.",
    "Thread D2 displays.",
    "RAMAT Vision displays only.",
    "Official records remain in source systems.",
    "Humans remain accountable.",
}


def load_result_summary_fixture(path: Path = DEFAULT_RESULT_SUMMARY_FIXTURE) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def _as_text_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def validate_result_summary_fixture(fixture: Dict[str, Any]) -> List[str]:
    errors: List[str] = []

    missing_top_level = sorted(REQUIRED_TOP_LEVEL_FIELDS.difference(fixture.keys()))
    if missing_top_level:
        errors.append(f"missing top-level fields: {', '.join(missing_top_level)}")

    identity_expectations = {
        "fixture_name": EXPECTED_FIXTURE_NAME,
        "fixture_status": EXPECTED_FIXTURE_STATUS,
        "workstream": EXPECTED_WORKSTREAM,
        "source_bundle": EXPECTED_SOURCE_BUNDLE,
        "source_bundle_status": EXPECTED_SOURCE_BUNDLE_STATUS,
        "result_type": EXPECTED_RESULT_TYPE,
    }

    for key, expected_value in identity_expectations.items():
        if fixture.get(key) != expected_value:
            errors.append(f"{key} must be {expected_value}")

    summary_state = fixture.get("summary_state", {})
    if not isinstance(summary_state, dict):
        errors.append("summary_state must be an object")
        summary_state = {}

    for key, expected_value in EXPECTED_SUMMARY_STATE.items():
        if summary_state.get(key) != expected_value:
            errors.append(f"summary_state.{key} must be {expected_value}")

    validated_commands = fixture.get("validated_commands", [])
    if not isinstance(validated_commands, list):
        errors.append("validated_commands must be a list")
        validated_commands = []

    command_ids = {
        str(command.get("id"))
        for command in validated_commands
        if isinstance(command, dict)
    }

    missing_commands = sorted(REQUIRED_VALIDATED_COMMAND_IDS.difference(command_ids))
    if missing_commands:
        errors.append(f"missing validated commands: {', '.join(missing_commands)}")

    if len(command_ids) != len(REQUIRED_VALIDATED_COMMAND_IDS):
        errors.append(
            f"validated command count must be {len(REQUIRED_VALIDATED_COMMAND_IDS)}"
        )

    for command in validated_commands:
        if not isinstance(command, dict):
            errors.append("each validated command must be an object")
            continue
        if command.get("expected_status") != "PASSED":
            errors.append(
                f"validated command {command.get('id')} expected_status must be PASSED"
            )

    assurance_signals = set(_as_text_list(fixture.get("assurance_signals")))
    missing_signals = sorted(REQUIRED_ASSURANCE_SIGNALS.difference(assurance_signals))
    if missing_signals:
        errors.append(f"missing assurance signals: {', '.join(missing_signals)}")

    display_summary = fixture.get("display_summary", {})
    if not isinstance(display_summary, dict):
        errors.append("display_summary must be an object")
        display_summary = {}

    for key, expected_value in EXPECTED_DISPLAY_SUMMARY.items():
        if display_summary.get(key) != expected_value:
            errors.append(f"display_summary.{key} must be {expected_value}")

    display_text = " ".join(
        _as_text(display_summary.get(key))
        for key in ("headline", "operator_message", "quality_message", "audit_message")
    )

    missing_display_terms = sorted(
        term for term in REQUIRED_DISPLAY_TEXT if term not in display_text
    )
    if missing_display_terms:
        errors.append(
            f"missing display summary terms: {', '.join(missing_display_terms)}"
        )

    boundary = set(_as_text_list(fixture.get("boundary")))
    missing_boundaries = sorted(REQUIRED_BOUNDARY_PHRASES.difference(boundary))
    if missing_boundaries:
        errors.append(f"missing boundary phrases: {', '.join(missing_boundaries)}")

    return errors


def validate_result_summary_file(
    path: Path = DEFAULT_RESULT_SUMMARY_FIXTURE,
) -> Tuple[bool, List[str]]:
    try:
        fixture = load_result_summary_fixture(path)
    except json.JSONDecodeError as exc:
        return False, [f"invalid JSON: {exc}"]
    except OSError as exc:
        return False, [f"cannot read file: {exc}"]

    errors = validate_result_summary_fixture(fixture)
    return not errors, errors


def validate_default_result_summary() -> Dict[str, Any]:
    passed, errors = validate_result_summary_file(DEFAULT_RESULT_SUMMARY_FIXTURE)

    return {
        "validator_name": VALIDATOR_NAME,
        "validator_status": VALIDATOR_STATUS,
        "fixture": DEFAULT_RESULT_SUMMARY_FIXTURE.name,
        "passed": passed,
        "errors": errors,
        "required_assurance_signals": sorted(REQUIRED_ASSURANCE_SIGNALS),
        "required_validated_commands": sorted(REQUIRED_VALIDATED_COMMAND_IDS),
    }


def clone_fixture(fixture: Dict[str, Any]) -> Dict[str, Any]:
    return deepcopy(fixture)


def main() -> int:
    report = validate_default_result_summary()

    print(json.dumps(report, indent=2))

    if report["passed"]:
        print("LOCAL VALIDATION RESULT SUMMARY FIXTURE VALIDATION PASSED")
        return 0

    print("LOCAL VALIDATION RESULT SUMMARY FIXTURE VALIDATION FAILED")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
