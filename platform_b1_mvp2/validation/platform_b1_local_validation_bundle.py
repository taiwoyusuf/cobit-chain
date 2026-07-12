import json
import subprocess
import sys
from pathlib import Path


BUNDLE_NAME = "Platform B1 / MVP2 Local Validation Bundle"
BUNDLE_STATUS = "LOCKED_LOCAL_VALIDATION_BUNDLE_ONLY"
PASS_SIGNAL = "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED"

ROOT = Path(__file__).resolve().parents[1]


def _commands_locked():
    return [
        {
            "id": "digital_twin_object_model_unit_test",
            "description": "Validate Regulated Operations Digital Twin object model.",
            "command": [
                sys.executable,
                "-m",
                "unittest",
                "platform_b1_mvp2.tests.test_regulated_operations_digital_twin_object_model",
            ],
            "expected_signal": "OK",
        },
        {
            "id": "digital_twin_mock_fixtures_unit_test",
            "description": "Validate Digital Twin mock fixtures.",
            "command": [
                sys.executable,
                "-m",
                "unittest",
                "platform_b1_mvp2.tests.test_regulated_operations_digital_twin_mock_fixtures",
            ],
            "expected_signal": "OK",
        },
        {
            "id": "digital_twin_mock_fixture_validator_cli",
            "description": "Run Digital Twin mock fixture validator CLI.",
            "command": [
                sys.executable,
                str(ROOT / "regulated_operations_digital_twin" / "validator" / "digital_twin_mock_fixture_validator.py"),
            ],
            "expected_signal": "DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED",
        },
        {
            "id": "digital_twin_mock_fixture_validator_unit_test",
            "description": "Validate Digital Twin mock fixture validator unit tests.",
            "command": [
                sys.executable,
                "-m",
                "unittest",
                "platform_b1_mvp2.tests.test_regulated_operations_digital_twin_mock_fixture_validator",
            ],
            "expected_signal": "OK",
        },
        {
            "id": "result_summary_fixture_validator_cli",
            "description": "Run Platform B1 local validation result summary fixture validator CLI.",
            "command": [
                sys.executable,
                str(ROOT / "validation" / "result_fixtures" / "validator" / "result_summary_fixture_validator.py"),
            ],
            "expected_signal": "LOCAL VALIDATION RESULT SUMMARY FIXTURE VALIDATION PASSED",
        },
        {
            "id": "result_summary_fixture_validator_unit_test",
            "description": "Validate Platform B1 local validation result summary fixture validator unit tests.",
            "command": [
                sys.executable,
                "-m",
                "unittest",
                "platform_b1_mvp2.tests.test_platform_b1_local_validation_result_summary_fixture_validator",
            ],
            "expected_signal": "OK",
        },
        {
            "id": "thread_d2_ramat_vision_display_fixture_validator_cli",
            "description": "Run Thread D2 RAMAT Vision display fixture validator CLI.",
            "command": [
                sys.executable,
                str(ROOT / "thread_d2_ramat_vision_preview" / "validator" / "thread_d2_ramat_vision_display_fixture_validator.py"),
            ],
            "expected_signal": "THREAD D2 RAMAT VISION DISPLAY FIXTURE VALIDATION PASSED",
        },
        {
            "id": "status_manifest_validator_cli",
            "description": "Run Platform B1 Thread D2 local validation status manifest validator CLI.",
            "command": [
                sys.executable,
                str(ROOT / "validation" / "status_manifest" / "validator" / "platform_b1_thread_d2_local_validation_status_manifest_validator.py"),
            ],
            "expected_signal": "PLATFORM B1 THREAD D2 LOCAL VALIDATION STATUS MANIFEST VALIDATION PASSED",
        },
        {
            "id": "thread_d2_ramat_vision_display_fixture_validator_unit_test",
            "description": "Validate Thread D2 RAMAT Vision display fixture validator unit tests.",
            "command": [
                sys.executable,
                "-m",
                "unittest",
                "platform_b1_mvp2.tests.test_thread_d2_ramat_vision_display_fixture_validator",
            ],
            "expected_signal": "OK",
        },
        {
            "id": "agentic_ambient_ai_vendor_assurance_passport_validator_cli",
            "description": "Run Platform B1 Agentic & Ambient AI Vendor Assurance Passport validator CLI.",
            "command": [
                sys.executable,
                str(ROOT / "research_watch" / "validator" / "platform_b1_agentic_ambient_ai_vendor_assurance_passport_validator.py"),
            ],
            "expected_signal": "AGENTIC AMBIENT AI VENDOR ASSURANCE PASSPORT VALIDATION PASSED",
        },
        {
            "id": "local_validation_evidence_ledger_validator_cli",
            "description": "Run Platform B1 / MVP2 local validation evidence ledger validator CLI.",
            "command": [
                sys.executable,
                str(ROOT / "validation" / "evidence_ledger" / "validator" / "platform_b1_mvp2_local_validation_evidence_ledger_validator.py"),
            ],
            "expected_signal": "PLATFORM B1 LOCAL VALIDATION EVIDENCE LEDGER VALIDATION PASSED",
        },
    ]


def _run_command(command_spec):
    completed = subprocess.run(
        command_spec["command"],
        capture_output=True,
        text=True,
    )

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    expected_signal = command_spec["expected_signal"]
    expected_signal_found = expected_signal in stdout or expected_signal in stderr

    return {
        "id": command_spec["id"],
        "description": command_spec["description"],
        "command": [str(part) for part in command_spec["command"]],
        "expected_signal": expected_signal,
        "expected_signal_found": expected_signal_found,
        "returncode": completed.returncode,
        "passed": completed.returncode == 0 and expected_signal_found,
        "stdout": stdout,
        "stderr": stderr,
    }


def run_validation_bundle():
    commands = _commands_locked()
    results = [_run_command(command_spec) for command_spec in commands]
    failed_validation_count = len([result for result in results if not result["passed"]])

    return {
        "bundle_name": BUNDLE_NAME,
        "bundle_status": BUNDLE_STATUS,
        "passed": failed_validation_count == 0,
        "pass_signal": PASS_SIGNAL,
        "validation_count": len(results),
        "failed_validation_count": failed_validation_count,
        "results": results,
        "commands_locked": [
            {
                "id": command_spec["id"],
                "description": command_spec["description"],
                "command": [str(part) for part in command_spec["command"]],
                "expected_signal": command_spec["expected_signal"],
            }
            for command_spec in commands
        ],
        "assurance_outputs": [
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
        ],
        "boundary": [
            "Local validation bundle only.",
            "Local validation evidence only.",
            "No status manifest update yet.",
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
            "No real glasses hardware integration.",
            "No real Halo hardware integration.",
            "No product release decision.",
            "No GMP approval decision.",
            "No source-system override.",
            "No Quality Unit replacement.",
            "No regulated action execution.",
            "No binding operational consequence.",
            "Platform B1 evaluates.",
            "Thread D2 displays.",
            "RAMAT Vision displays only.",
            "Official records remain in source systems.",
            "Humans remain accountable.",
        ],
    }


def main() -> int:
    result = run_validation_bundle()
    print(json.dumps(result, indent=2))

    if result["passed"]:
        print(PASS_SIGNAL)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

