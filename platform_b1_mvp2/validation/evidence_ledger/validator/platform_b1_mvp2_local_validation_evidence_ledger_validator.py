import json
import sys
from pathlib import Path


VALIDATOR_NAME = "Platform B1 / MVP2 Local Validation Evidence Ledger Validator"
VALIDATOR_STATUS = "LOCKED_LOCAL_VALIDATION_EVIDENCE_LEDGER_VALIDATOR_ONLY"
PASS_SIGNAL = "PLATFORM B1 LOCAL VALIDATION EVIDENCE LEDGER VALIDATION PASSED"

ROOT = Path(__file__).resolve().parents[3]
LEDGER_JSON = ROOT / "validation" / "evidence_ledger" / "platform_b1_mvp2_local_validation_evidence_ledger.json"
LEDGER_MD = ROOT / "validation" / "evidence_ledger" / "PLATFORM_B1_MVP2_LOCAL_VALIDATION_EVIDENCE_LEDGER.md"

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
    "PLATFORM B1 THREAD D2 LOCAL VALIDATION STATUS MANIFEST VALIDATION PASSED",
    "THREAD D2 RAMAT VISION DISPLAY FIXTURE VALIDATION PASSED",
    "AGENTIC AMBIENT AI VENDOR ASSURANCE PASSPORT VALIDATION PASSED",
    "PLATFORM B1 LOCAL VALIDATION EVIDENCE LEDGER VALIDATION PASSED",
    "AI OUTPUT HASHED",
    "HASH VERIFIED",
    "AGENT ACTION NOT ADMISSIBLE",
    "RAMAT VISION DISPLAY READY",
    "PLATFORM B1 DECISION DISPLAYED",
]

REQUIRED_DOCTRINE = [
    "Platform B1 evaluates.",
    "Thread D2 displays.",
    "RAMAT Vision displays only.",
    "Any device may witness.",
    "Only Platform B1 evaluates in the preview workstream.",
    "Official records remain in source systems.",
    "Humans remain accountable.",
    "Silence is not consent.",
    "AI output is not binding without evidence, authority, review, and accountability.",
]

REQUIRED_BOUNDARY = [
    "Local validation evidence ledger only.",
    "No architecture change.",
    "No Platform B v1 change.",
    "No Thread D v1 change.",
    "No MVP3 activation.",
    "No Azure deployment.",
    "No Azure Digital Twins deployment.",
    "No real production system connection.",
    "No PHI.",
    "No company production data.",
    "No regulated action execution.",
    "No binding operational consequence.",
]

REQUIRED_EVIDENCE_OBJECTS = [
    "platform_b1_local_validation_bundle.py",
    "platform_b1_thread_d2_local_validation_status_manifest.json",
    "platform_b1_mvp2_local_validation_evidence_ledger.json",
    "platform_b1_mvp2_local_validation_evidence_ledger_validator.py",
]


def _load_ledger():
    return json.loads(LEDGER_JSON.read_text(encoding="utf-8-sig"))


def _string_list_from_ledger(ledger, keys):
    values = []
    for key in keys:
        raw = ledger.get(key, [])
        if not isinstance(raw, list):
            continue
        for item in raw:
            if isinstance(item, str) and item not in values:
                values.append(item)
            elif isinstance(item, dict) and "id" in item and item["id"] not in values:
                values.append(item["id"])
    return values


def validate_evidence_ledger():
    errors = []

    if not LEDGER_JSON.exists():
        return {
            "validator_name": VALIDATOR_NAME,
            "validator_status": VALIDATOR_STATUS,
            "ledger": LEDGER_JSON.name,
            "passed": False,
            "errors": [f"Evidence ledger not found: {LEDGER_JSON}"],
            "validation_count_expected": VALIDATION_COUNT_EXPECTED,
            "failed_validation_count_expected": FAILED_VALIDATION_COUNT_EXPECTED,
            "required_validated_commands": REQUIRED_VALIDATED_COMMANDS,
            "required_assurance_signals": REQUIRED_ASSURANCE_SIGNALS,
            "boundary_mode": REQUIRED_BOUNDARY,
        }

    if not LEDGER_MD.exists():
        errors.append(f"Evidence ledger markdown not found: {LEDGER_MD}")

    try:
        ledger = _load_ledger()
    except json.JSONDecodeError as exc:
        return {
            "validator_name": VALIDATOR_NAME,
            "validator_status": VALIDATOR_STATUS,
            "ledger": LEDGER_JSON.name,
            "passed": False,
            "errors": [f"Evidence ledger JSON is invalid: {exc}"],
            "validation_count_expected": VALIDATION_COUNT_EXPECTED,
            "failed_validation_count_expected": FAILED_VALIDATION_COUNT_EXPECTED,
            "required_validated_commands": REQUIRED_VALIDATED_COMMANDS,
            "required_assurance_signals": REQUIRED_ASSURANCE_SIGNALS,
            "boundary_mode": REQUIRED_BOUNDARY,
        }

    md_text = LEDGER_MD.read_text(encoding="utf-8-sig") if LEDGER_MD.exists() else ""

    if ledger.get("ledger_status") != "LOCKED_LOCAL_VALIDATION_EVIDENCE_LEDGER_ONLY":
        errors.append("ledger_status must be LOCKED_LOCAL_VALIDATION_EVIDENCE_LEDGER_ONLY.")

    if ledger.get("validation_count") != VALIDATION_COUNT_EXPECTED:
        errors.append("validation_count must be 11.")

    if ledger.get("failed_validation_count") != FAILED_VALIDATION_COUNT_EXPECTED:
        errors.append("failed_validation_count must be 0.")

    if ledger.get("overall_status") != "PASSED":
        errors.append("overall_status must be PASSED.")

    if ledger.get("pass_signal") != "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED":
        errors.append("pass_signal must be PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED.")

    validated_commands = _string_list_from_ledger(ledger, ["validated_commands", "commands_locked"])
    if len(validated_commands) != VALIDATION_COUNT_EXPECTED:
        errors.append("validated_commands must contain exactly 11 commands.")

    for command_id in REQUIRED_VALIDATED_COMMANDS:
        if command_id not in validated_commands:
            errors.append(f"missing validated command: {command_id}")
        if command_id not in md_text:
            errors.append(f"missing markdown validated command: {command_id}")

    assurance_signals = _string_list_from_ledger(ledger, ["assurance_signals", "assurance_outputs", "outputs"])
    for signal in REQUIRED_ASSURANCE_SIGNALS:
        if signal not in assurance_signals:
            errors.append(f"missing assurance signal: {signal}")
        if signal not in md_text:
            errors.append(f"missing markdown assurance signal: {signal}")

    doctrine_values = _string_list_from_ledger(ledger, ["doctrine", "core_doctrine"])
    doctrine_text = " ".join(doctrine_values)
    for doctrine in REQUIRED_DOCTRINE:
        if doctrine not in doctrine_text:
            errors.append(f"missing doctrine: {doctrine}")
        if doctrine not in md_text:
            errors.append(f"missing markdown doctrine: {doctrine}")

    boundary_values = _string_list_from_ledger(ledger, ["boundary", "boundary_mode"])
    boundary_text = " ".join(boundary_values)
    for boundary in REQUIRED_BOUNDARY:
        if boundary not in boundary_text:
            errors.append(f"missing boundary: {boundary}")
        if boundary not in md_text:
            errors.append(f"missing markdown boundary: {boundary}")

    evidence_objects = _string_list_from_ledger(ledger, ["evidence_objects"])
    for evidence_object in REQUIRED_EVIDENCE_OBJECTS:
        if evidence_object not in evidence_objects:
            errors.append(f"missing evidence object: {evidence_object}")
        if evidence_object not in md_text:
            errors.append(f"missing markdown evidence object: {evidence_object}")

    return {
        "validator_name": VALIDATOR_NAME,
        "validator_status": VALIDATOR_STATUS,
        "ledger": LEDGER_JSON.name,
        "passed": len(errors) == 0,
        "errors": errors,
        "validation_count_expected": VALIDATION_COUNT_EXPECTED,
        "failed_validation_count_expected": FAILED_VALIDATION_COUNT_EXPECTED,
        "required_validated_commands": REQUIRED_VALIDATED_COMMANDS,
        "required_assurance_signals": REQUIRED_ASSURANCE_SIGNALS,
        "required_doctrine": REQUIRED_DOCTRINE,
        "required_evidence_objects": REQUIRED_EVIDENCE_OBJECTS,
        "boundary_mode": REQUIRED_BOUNDARY,
    }


def main():
    result = validate_evidence_ledger()
    print(json.dumps(result, indent=2))

    if result["passed"]:
        print(PASS_SIGNAL)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())

