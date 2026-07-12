import json
import sys
from pathlib import Path


VALIDATOR_NAME = "Platform B1 Thread D2 Local Validation Status Manifest Validator"
VALIDATOR_STATUS = "LOCKED_LOCAL_VALIDATION_STATUS_MANIFEST_VALIDATOR_ONLY"
PASS_SIGNAL = "PLATFORM B1 THREAD D2 LOCAL VALIDATION STATUS MANIFEST VALIDATION PASSED"

ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = ROOT / "validation" / "status_manifest" / "platform_b1_thread_d2_local_validation_status_manifest.json"

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

BOUNDARY_MODE = [
    "Local validation status manifest validator only.",
    "Local validation evidence only.",
    "No Azure deployment.",
    "No Azure Digital Twins deployment.",
    "No Platform B v1 change.",
    "No Thread D v1 change.",
    "No MVP3 activation.",
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


def _walk_values(obj, key_name):
    values = []

    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == key_name:
                values.append(value)
            values.extend(_walk_values(value, key_name))

    elif isinstance(obj, list):
        for item in obj:
            values.extend(_walk_values(item, key_name))

    return values


def validate_status_manifest():
    errors = []

    if not MANIFEST_PATH.exists():
        return {
            "validator_name": VALIDATOR_NAME,
            "validator_status": VALIDATOR_STATUS,
            "manifest": MANIFEST_PATH.name,
            "passed": False,
            "errors": [f"Manifest not found: {MANIFEST_PATH}"],
            "validation_count_expected": 10,
            "failed_validation_count_expected": 0,
            "required_validated_commands": REQUIRED_VALIDATED_COMMANDS,
            "required_assurance_signals": REQUIRED_ASSURANCE_SIGNALS,
            "required_thread_d2_status": REQUIRED_THREAD_D2_STATUS,
            "boundary_mode": BOUNDARY_MODE,
        }

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8-sig"))
    manifest_text = json.dumps(manifest, sort_keys=True)

    validation_counts = _walk_values(manifest, "validation_count")
    failed_counts = _walk_values(manifest, "failed_validation_count")

    if 10 not in validation_counts:
        errors.append("validation_count must include 10.")

    if any(value != 10 for value in validation_counts if isinstance(value, int)):
        errors.append("all integer validation_count values must be 10.")

    if 0 not in failed_counts:
        errors.append("failed_validation_count must include 0.")

    if any(value != 0 for value in failed_counts if isinstance(value, int)):
        errors.append("all integer failed_validation_count values must be 0.")

    for command_id in REQUIRED_VALIDATED_COMMANDS:
        if command_id not in manifest_text:
            errors.append(f"missing validated command: {command_id}")

    for signal in REQUIRED_ASSURANCE_SIGNALS:
        if signal not in manifest_text:
            errors.append(f"missing assurance signal: {signal}")

    for status_value in REQUIRED_THREAD_D2_STATUS.values():
        if status_value not in manifest_text:
            errors.append(f"missing Thread D2 status value: {status_value}")

    for boundary in BOUNDARY_MODE:
        if boundary not in manifest_text:
            errors.append(f"missing boundary term: {boundary}")

    return {
        "validator_name": VALIDATOR_NAME,
        "validator_status": VALIDATOR_STATUS,
        "manifest": MANIFEST_PATH.name,
        "passed": len(errors) == 0,
        "errors": errors,
        "validation_count_expected": 10,
        "failed_validation_count_expected": 0,
        "required_validated_commands": REQUIRED_VALIDATED_COMMANDS,
        "required_assurance_signals": REQUIRED_ASSURANCE_SIGNALS,
        "required_thread_d2_status": REQUIRED_THREAD_D2_STATUS,
        "boundary_mode": BOUNDARY_MODE,
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
