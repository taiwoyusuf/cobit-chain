from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[4]
ROOT = REPO_ROOT / "platform_b1_mvp2"

MANIFEST_JSON = (
    ROOT
    / "validation"
    / "status_manifest"
    / "platform_b1_thread_d2_local_validation_status_manifest.json"
)

MANIFEST_MD = (
    ROOT
    / "validation"
    / "status_manifest"
    / "PLATFORM_B1_THREAD_D2_LOCAL_VALIDATION_STATUS_MANIFEST.md"
)

VALIDATOR_NAME = "Platform B1 Thread D2 Local Validation Status Manifest Validator"
VALIDATOR_STATUS = "LOCKED_LOCAL_VALIDATION_STATUS_MANIFEST_VALIDATOR_ONLY"
PASS_SIGNAL = "PLATFORM B1 THREAD D2 LOCAL VALIDATION STATUS MANIFEST VALIDATION PASSED"

REQUIRED_TOP_LEVEL_FIELDS = [
    "manifest_name",
    "manifest_status",
    "manifest_type",
    "workstreams",
    "source_bundle",
    "source_bundle_status",
    "overall_status",
    "validation_count",
    "failed_validation_count",
    "azure_deployment_status",
    "azure_digital_twins_status",
    "platform_b_v1_impact",
    "thread_d_v1_impact",
    "mvp3_activation",
    "thread_d2_status",
    "validated_commands",
    "required_assurance_signals",
    "doctrine",
    "boundary",
    "next_allowed_work",
]

REQUIRED_VALIDATED_COMMANDS = [
    "digital_twin_object_model_unit_test",
    "digital_twin_mock_fixtures_unit_test",
    "digital_twin_mock_fixture_validator_cli",
    "digital_twin_mock_fixture_validator_unit_test",
    "result_summary_fixture_validator_cli",
    "result_summary_fixture_validator_unit_test",
    "thread_d2_ramat_vision_display_fixture_validator_cli",
    "thread_d2_ramat_vision_display_fixture_validator_unit_test",
]

REQUIRED_ASSURANCE_SIGNALS = [
    "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED",
    "DIGITAL TWIN OBJECT MODEL VALIDATED",
    "DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED",
    "LOCAL VALIDATION RESULT SUMMARY FIXTURE VALIDATION PASSED",
    "THREAD D2 RAMAT VISION DISPLAY FIXTURE VALIDATION PASSED",
    "AI OUTPUT HASHED",
    "HASH VERIFIED",
    "AGENT ACTION NOT ADMISSIBLE",
    "RAMAT VISION DISPLAY READY",
    "PLATFORM B1 DECISION DISPLAYED",
]

REQUIRED_THREAD_D2_STATUS = {
    "display_fixture_status": "LOCKED_THREAD_D2_DISPLAY_FIXTURE_ONLY",
    "display_validator_status": "LOCKED_THREAD_D2_DISPLAY_FIXTURE_VALIDATOR_ONLY",
    "ramat_vision_display_status": "DISPLAY_READY",
    "platform_b1_decision_status": "DISPLAYED_ONLY",
    "operator_action_status": "NOT_AUTHORIZED_BY_DISPLAY",
    "quality_unit_status": "NOT_REPLACED",
    "source_system_status": "NOT_OVERRIDDEN",
}

REQUIRED_DOCTRINE_PHRASES = [
    "Platform B1 evaluates.",
    "Thread D2 displays.",
    "RAMAT Vision displays only.",
    "Any device may witness.",
    "Official records remain in source systems.",
    "Humans remain accountable.",
]

REQUIRED_BOUNDARY_PHRASES = [
    "Local validation status manifest only.",
    "Local validation evidence only.",
    "No Azure deployment.",
    "No Azure Digital Twins deployment.",
    "No Platform B v1 change.",
    "No Thread D v1 change.",
    "No MVP3 activation.",
    "No real production system connection.",
    "No real glasses hardware integration.",
    "No real Halo hardware integration.",
    "No PHI.",
    "No company production data.",
    "No product release decision.",
    "No GMP approval decision.",
    "No source-system override.",
    "No Quality Unit replacement.",
    "No regulated action execution.",
    "No binding operational consequence.",
]

REQUIRED_MARKDOWN_PHRASES = [
    "LOCKED LOCAL VALIDATION STATUS MANIFEST ONLY",
    "LOCAL_VALIDATION_STATUS_SNAPSHOT",
    "Validation count: 8",
    "Failed validation count: 0",
    "THREAD D2 RAMAT VISION DISPLAY FIXTURE VALIDATION PASSED",
    "RAMAT VISION DISPLAY READY",
    "PLATFORM B1 DECISION DISPLAYED",
    "No Azure deployment",
    "No Azure Digital Twins deployment",
    "No Platform B v1 change",
    "No Thread D v1 change",
    "No real Halo hardware integration",
    "No Quality Unit replacement",
]


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _missing_from_list(values: List[str], required: List[str]) -> List[str]:
    present = " ".join(values)
    return [item for item in required if item not in present]


def validate_status_manifest() -> Dict[str, Any]:
    errors: List[str] = []

    if not MANIFEST_JSON.exists():
        errors.append(f"Missing status manifest JSON: {MANIFEST_JSON}")
        return _report(errors)

    if not MANIFEST_MD.exists():
        errors.append(f"Missing status manifest markdown: {MANIFEST_MD}")
        return _report(errors)

    try:
        manifest = _load_json(MANIFEST_JSON)
    except json.JSONDecodeError as exc:
        errors.append(f"Invalid status manifest JSON: {exc}")
        return _report(errors)

    markdown = MANIFEST_MD.read_text(encoding="utf-8-sig")

    for field in REQUIRED_TOP_LEVEL_FIELDS:
        if field not in manifest:
            errors.append(f"Missing top-level field: {field}")

    if errors:
        return _report(errors)

    if manifest["manifest_name"] != "Platform B1 / Thread D2 Local Validation Status Manifest":
        errors.append("Unexpected manifest_name.")

    if manifest["manifest_status"] != "LOCKED_LOCAL_VALIDATION_STATUS_MANIFEST_ONLY":
        errors.append("manifest_status must be LOCKED_LOCAL_VALIDATION_STATUS_MANIFEST_ONLY.")

    if manifest["manifest_type"] != "LOCAL_VALIDATION_STATUS_SNAPSHOT":
        errors.append("manifest_type must be LOCAL_VALIDATION_STATUS_SNAPSHOT.")

    workstreams = " ".join(manifest.get("workstreams", []))
    if "Platform B1 / MVP2" not in workstreams:
        errors.append("Missing Platform B1 / MVP2 workstream.")
    if "Thread D2 — RAMAT Vision Advanced Assurance Preview" not in workstreams:
        errors.append("Missing Thread D2 RAMAT Vision workstream.")

    if manifest["source_bundle"] != "Platform B1 / MVP2 Local Validation Bundle":
        errors.append("source_bundle must be Platform B1 / MVP2 Local Validation Bundle.")

    if manifest["source_bundle_status"] != "LOCKED_LOCAL_VALIDATION_BUNDLE_ONLY":
        errors.append("source_bundle_status must be LOCKED_LOCAL_VALIDATION_BUNDLE_ONLY.")

    if manifest["overall_status"] != "PASSED":
        errors.append("overall_status must be PASSED.")

    if manifest["validation_count"] != 8:
        errors.append("validation_count must be 8.")

    if manifest["failed_validation_count"] != 0:
        errors.append("failed_validation_count must be 0.")

    expected_status_fields = {
        "azure_deployment_status": "NOT_DEPLOYED",
        "azure_digital_twins_status": "NOT_DEPLOYED",
        "platform_b_v1_impact": "NONE",
        "thread_d_v1_impact": "NONE",
        "mvp3_activation": "NONE",
    }

    for key, expected in expected_status_fields.items():
        if manifest.get(key) != expected:
            errors.append(f"{key} must be {expected}.")

    thread_d2_status = manifest.get("thread_d2_status", {})
    for key, expected in REQUIRED_THREAD_D2_STATUS.items():
        if thread_d2_status.get(key) != expected:
            errors.append(f"thread_d2_status.{key} must be {expected}.")

    commands = manifest.get("validated_commands", [])
    if len(commands) != 8:
        errors.append("validated_commands must contain exactly 8 commands.")

    for command in REQUIRED_VALIDATED_COMMANDS:
        if command not in commands:
            errors.append(f"Missing validated command: {command}")

    missing_signals = _missing_from_list(
        manifest.get("required_assurance_signals", []),
        REQUIRED_ASSURANCE_SIGNALS,
    )
    for signal in missing_signals:
        errors.append(f"Missing required assurance signal: {signal}")

    missing_doctrine = _missing_from_list(
        manifest.get("doctrine", []),
        REQUIRED_DOCTRINE_PHRASES,
    )
    for phrase in missing_doctrine:
        errors.append(f"Missing doctrine phrase: {phrase}")

    missing_boundary = _missing_from_list(
        manifest.get("boundary", []),
        REQUIRED_BOUNDARY_PHRASES,
    )
    for phrase in missing_boundary:
        errors.append(f"Missing boundary phrase: {phrase}")

    for phrase in REQUIRED_MARKDOWN_PHRASES:
        if phrase not in markdown:
            errors.append(f"Missing markdown phrase: {phrase}")

    return _report(errors)


def _report(errors: List[str]) -> Dict[str, Any]:
    return {
        "validator_name": VALIDATOR_NAME,
        "validator_status": VALIDATOR_STATUS,
        "manifest": MANIFEST_JSON.name,
        "passed": len(errors) == 0,
        "errors": errors,
        "required_validated_commands": REQUIRED_VALIDATED_COMMANDS,
        "required_assurance_signals": REQUIRED_ASSURANCE_SIGNALS,
        "required_thread_d2_status": REQUIRED_THREAD_D2_STATUS,
        "boundary_mode": [
            "Local validation status manifest validator only.",
            "Local validation evidence only.",
            "No Azure deployment.",
            "No Azure Digital Twins deployment.",
            "No Platform B v1 change.",
            "No Thread D v1 change.",
            "No MVP3 activation.",
            "No real glasses hardware integration.",
            "No real Halo hardware integration.",
            "No product release decision.",
            "No GMP approval decision.",
            "No Quality Unit replacement.",
        ],
    }


def main() -> int:
    report = validate_status_manifest()
    print(json.dumps(report, indent=2))

    if report["passed"]:
        print(PASS_SIGNAL)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
