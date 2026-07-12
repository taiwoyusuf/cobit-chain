import json
import sys
from pathlib import Path


VALIDATOR_NAME = "Platform B1 / MVP2 Local Validation Evidence Ledger Validator"
VALIDATOR_STATUS = "LOCKED_LOCAL_VALIDATION_EVIDENCE_LEDGER_VALIDATOR_ONLY"
PASS_SIGNAL = "PLATFORM B1 LOCAL VALIDATION EVIDENCE LEDGER VALIDATION PASSED"

ROOT = Path(__file__).resolve().parents[3]
LEDGER_JSON = ROOT / "validation" / "evidence_ledger" / "platform_b1_mvp2_local_validation_evidence_ledger.json"
LEDGER_MD = ROOT / "validation" / "evidence_ledger" / "PLATFORM_B1_MVP2_LOCAL_VALIDATION_EVIDENCE_LEDGER.md"

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
    "PLATFORM B1 THREAD D2 LOCAL VALIDATION STATUS MANIFEST VALIDATION PASSED",
    "THREAD D2 RAMAT VISION DISPLAY FIXTURE VALIDATION PASSED",
    "AGENTIC AMBIENT AI VENDOR ASSURANCE PASSPORT VALIDATION PASSED",
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
    "Official records remain in source systems.",
    "Humans remain accountable.",
    "Silence is not consent.",
    "AI output is not binding without evidence, authority, review, and accountability.",
]

REQUIRED_BOUNDARY = [
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
    "PLATFORM_B1_LOCAL_VALIDATION_BUNDLE.md",
    "platform_b1_thread_d2_local_validation_status_manifest.json",
    "platform_b1_thread_d2_local_validation_status_manifest_validator.py",
    "platform_b1_agentic_ambient_ai_vendor_assurance_passport.json",
    "platform_b1_agentic_ambient_ai_vendor_assurance_passport_validator.py",
]


def validate_evidence_ledger():
    errors = []

    if not LEDGER_JSON.exists():
        errors.append(f"Evidence ledger JSON not found: {LEDGER_JSON}")
        ledger = {}
        ledger_text = ""
    else:
        ledger_text = LEDGER_JSON.read_text(encoding="utf-8-sig")
        try:
            ledger = json.loads(ledger_text)
        except json.JSONDecodeError as exc:
            ledger = {}
            errors.append(f"Evidence ledger JSON is invalid: {exc}")

    if not LEDGER_MD.exists():
        errors.append(f"Evidence ledger markdown not found: {LEDGER_MD}")
        markdown_text = ""
    else:
        markdown_text = LEDGER_MD.read_text(encoding="utf-8-sig")

    if ledger.get("ledger_name") != "Platform B1 / MVP2 Local Validation Evidence Ledger":
        errors.append("ledger_name is not correct.")

    if ledger.get("ledger_status") != "LOCKED_LOCAL_VALIDATION_EVIDENCE_LEDGER_ONLY":
        errors.append("ledger_status is not locked correctly.")

    if ledger.get("ledger_version") != "1.0":
        errors.append("ledger_version must be 1.0.")

    if ledger.get("validation_count") != 10:
        errors.append("validation_count must be 10.")

    if ledger.get("failed_validation_count") != 0:
        errors.append("failed_validation_count must be 0.")

    if ledger.get("overall_status") != "PASSED":
        errors.append("overall_status must be PASSED.")

    if ledger.get("pass_signal") != "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED":
        errors.append("pass_signal must be PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED.")

    validated_commands = ledger.get("validated_commands", [])
    if len(validated_commands) != 10:
        errors.append("validated_commands must contain exactly 10 commands.")

    for command_id in REQUIRED_VALIDATED_COMMANDS:
        if command_id not in validated_commands:
            errors.append(f"missing validated command: {command_id}")
        if command_id not in markdown_text:
            errors.append(f"missing markdown command reference: {command_id}")

    assurance_signals = ledger.get("assurance_signals", [])
    for signal in REQUIRED_ASSURANCE_SIGNALS:
        if signal not in assurance_signals:
            errors.append(f"missing assurance signal: {signal}")
        if signal not in markdown_text:
            errors.append(f"missing markdown assurance signal: {signal}")

    doctrine_text = " ".join(ledger.get("doctrine", []))
    for doctrine in REQUIRED_DOCTRINE:
        if doctrine not in doctrine_text:
            errors.append(f"missing doctrine: {doctrine}")
        if doctrine not in markdown_text:
            errors.append(f"missing markdown doctrine: {doctrine}")

    boundary_text = " ".join(ledger.get("boundary", []))
    for boundary in REQUIRED_BOUNDARY:
        if boundary not in boundary_text:
            errors.append(f"missing boundary: {boundary}")
        if boundary not in markdown_text:
            errors.append(f"missing markdown boundary: {boundary}")

    evidence_objects = ledger.get("evidence_objects_referenced", [])
    for evidence_object in REQUIRED_EVIDENCE_OBJECTS:
        if evidence_object not in evidence_objects:
            errors.append(f"missing evidence object reference: {evidence_object}")
        if evidence_object not in markdown_text:
            errors.append(f"missing markdown evidence object reference: {evidence_object}")

    return {
        "validator_name": VALIDATOR_NAME,
        "validator_status": VALIDATOR_STATUS,
        "ledger": LEDGER_JSON.name,
        "passed": len(errors) == 0,
        "errors": errors,
        "validation_count_expected": 10,
        "failed_validation_count_expected": 0,
        "required_validated_commands": REQUIRED_VALIDATED_COMMANDS,
        "required_assurance_signals": REQUIRED_ASSURANCE_SIGNALS,
        "required_doctrine": REQUIRED_DOCTRINE,
        "required_boundary": REQUIRED_BOUNDARY,
        "required_evidence_objects": REQUIRED_EVIDENCE_OBJECTS,
        "boundary_mode": [
            "Local validation evidence ledger validator only.",
            "No bundle integration yet.",
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
        ],
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
