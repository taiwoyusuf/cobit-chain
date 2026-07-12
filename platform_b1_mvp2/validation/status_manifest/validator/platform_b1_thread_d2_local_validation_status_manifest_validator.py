import json
import sys
from pathlib import Path


VALIDATOR_NAME = "Platform B1 Thread D2 Local Validation Status Manifest Validator"
VALIDATOR_STATUS = "LOCKED_LOCAL_VALIDATION_STATUS_MANIFEST_VALIDATOR_ONLY"
PASS_SIGNAL = "PLATFORM B1 THREAD D2 LOCAL VALIDATION STATUS MANIFEST VALIDATION PASSED"

ROOT = Path(__file__).resolve().parents[3]
MANIFEST_JSON = ROOT / "validation" / "status_manifest" / "platform_b1_thread_d2_local_validation_status_manifest.json"

VALIDATION_COUNT_EXPECTED = 11
FAILED_VALIDATION_COUNT_EXPECTED = 0

REQUIRED_VALIDATED_COMMANDS = [
    "digital_twin_object_model_unit_test",
    "digital_twin_mock_fixtures_unit_test",
    "digital_twin_mock_fixture_validator_cli",
    "digital_twin_mock_fixture_validator_unit_test",
    "result_summary_fixture_validator_cli",
    "result_summary_fixture_validator_unit_test",
    "thread_d2_ramat_vision_display_fixture_validator_cli",
    "status_manifest_validator_cli",
    "thread_d2_ramat_vision_display_fixture_validator_unit_test",
    "agentic_ambient_ai_vendor_assurance_passport_validator_cli",
    "local_validation_evidence_ledger_validator_cli",
]

REQUIRED_ASSURANCE_SIGNALS = [
    "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED",
    "DIGITAL TWIN OBJECT MODEL VALIDATED",
    "DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED",
    "LOCAL VALIDATION RESULT SUMMARY FIXTURE VALIDATION PASSED",
    "THREAD D2 RAMAT VISION DISPLAY FIXTURE VALIDATION PASSED",
    "PLATFORM B1 THREAD D2 LOCAL VALIDATION STATUS MANIFEST VALIDATION PASSED",
    "AI OUTPUT HASHED",
    "HASH VERIFIED",
    "AGENT ACTION NOT ADMISSIBLE",
    "RAMAT VISION DISPLAY READY",
    "PLATFORM B1 DECISION DISPLAYED",
    "AGENTIC AMBIENT AI VENDOR ASSURANCE PASSPORT VALIDATION PASSED",
    "PLATFORM B1 LOCAL VALIDATION EVIDENCE LEDGER VALIDATION PASSED",
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

REQUIRED_BOUNDARY = [
    "No evidence ledger update yet.",
    "No Azure deployment.",
    "No Azure Digital Twins deployment.",
    "No Platform B v1 change.",
    "No Thread D v1 change.",
    "No MVP3 activation.",
    "No PHI.",
    "No company production data.",
    "No regulated action execution.",
    "No binding operational consequence.",
]


def _load_manifest():
    return json.loads(MANIFEST_JSON.read_text(encoding="utf-8-sig"))


def _string_list_from_manifest(manifest, keys):
    values = []
    for key in keys:
        raw = manifest.get(key, [])
        if not isinstance(raw, list):
            continue
        for item in raw:
            if isinstance(item, str) and item not in values:
                values.append(item)
            elif isinstance(item, dict) and "id" in item and item["id"] not in values:
                values.append(item["id"])
    return values


def validate_status_manifest():
    errors = []

    if not MANIFEST_JSON.exists():
        return {
            "validator_name": VALIDATOR_NAME,
            "validator_status": VALIDATOR_STATUS,
            "manifest": MANIFEST_JSON.name,
            "passed": False,
            "errors": [f"Manifest not found: {MANIFEST_JSON}"],
            "validation_count_expected": VALIDATION_COUNT_EXPECTED,
            "failed_validation_count_expected": FAILED_VALIDATION_COUNT_EXPECTED,
            "required_validated_commands": REQUIRED_VALIDATED_COMMANDS,
            "required_assurance_signals": REQUIRED_ASSURANCE_SIGNALS,
            "required_thread_d2_status": REQUIRED_THREAD_D2_STATUS,
            "boundary_mode": REQUIRED_BOUNDARY,
        }

    try:
        manifest = _load_manifest()
    except json.JSONDecodeError as exc:
        return {
            "validator_name": VALIDATOR_NAME,
            "validator_status": VALIDATOR_STATUS,
            "manifest": MANIFEST_JSON.name,
            "passed": False,
            "errors": [f"Manifest JSON is invalid: {exc}"],
            "validation_count_expected": VALIDATION_COUNT_EXPECTED,
            "failed_validation_count_expected": FAILED_VALIDATION_COUNT_EXPECTED,
            "required_validated_commands": REQUIRED_VALIDATED_COMMANDS,
            "required_assurance_signals": REQUIRED_ASSURANCE_SIGNALS,
            "required_thread_d2_status": REQUIRED_THREAD_D2_STATUS,
            "boundary_mode": REQUIRED_BOUNDARY,
        }

    if manifest.get("validation_count") != VALIDATION_COUNT_EXPECTED:
        errors.append("validation_count must be 11.")

    if manifest.get("failed_validation_count") != FAILED_VALIDATION_COUNT_EXPECTED:
        errors.append("failed_validation_count must be 0.")

    if manifest.get("overall_status") != "PASSED":
        errors.append("overall_status must be PASSED.")

    validated_commands = _string_list_from_manifest(manifest, ["validated_commands", "commands_locked"])
    if len(validated_commands) != VALIDATION_COUNT_EXPECTED:
        errors.append("validated_commands must contain exactly 11 commands.")

    for command_id in REQUIRED_VALIDATED_COMMANDS:
        if command_id not in validated_commands:
            errors.append(f"missing validated command: {command_id}")

    assurance_signals = _string_list_from_manifest(manifest, ["assurance_signals", "assurance_outputs", "outputs"])
    for signal in REQUIRED_ASSURANCE_SIGNALS:
        if signal not in assurance_signals:
            errors.append(f"missing assurance signal: {signal}")

    thread_d2_status = manifest.get("thread_d2_status", {})
    for key, expected_value in REQUIRED_THREAD_D2_STATUS.items():
        if thread_d2_status.get(key) != expected_value:
            errors.append(f"thread_d2_status.{key} must be {expected_value}.")

    boundary_values = _string_list_from_manifest(manifest, ["boundary_mode", "boundary"])
    boundary_text = " ".join(boundary_values)
    for boundary in REQUIRED_BOUNDARY:
        if boundary not in boundary_text:
            errors.append(f"missing boundary: {boundary}")

    return {
        "validator_name": VALIDATOR_NAME,
        "validator_status": VALIDATOR_STATUS,
        "manifest": MANIFEST_JSON.name,
        "passed": len(errors) == 0,
        "errors": errors,
        "validation_count_expected": VALIDATION_COUNT_EXPECTED,
        "failed_validation_count_expected": FAILED_VALIDATION_COUNT_EXPECTED,
        "required_validated_commands": REQUIRED_VALIDATED_COMMANDS,
        "required_assurance_signals": REQUIRED_ASSURANCE_SIGNALS,
        "required_thread_d2_status": REQUIRED_THREAD_D2_STATUS,
        "boundary_mode": REQUIRED_BOUNDARY,
    }


def main():
    result = validate_status_manifest()
    print(json.dumps(result, indent=2))

    if result["passed"]:
        print(PASS_SIGNAL)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())

