from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"

BUNDLE_NAME = "Platform B1 / MVP2 Local Validation Bundle"
BUNDLE_STATUS = "LOCKED_LOCAL_VALIDATION_BUNDLE_ONLY"

PASS_SIGNAL = "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED"
FAIL_SIGNAL = "PLATFORM B1 LOCAL VALIDATION BUNDLE FAILED"

BOUNDARY = [
    "Local validation bundle only.",
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
]

ASSURANCE_OUTPUTS = [
    PASS_SIGNAL,
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


@dataclass(frozen=True)
class ValidationCommand:
    id: str
    description: str
    command: List[str]
    expected_signal: str


COMMANDS = [
    ValidationCommand(
        id="digital_twin_object_model_unit_test",
        description="Validate Regulated Operations Digital Twin object model.",
        command=[
            sys.executable,
            "-m",
            "unittest",
            "platform_b1_mvp2.tests.test_regulated_operations_digital_twin_object_model",
        ],
        expected_signal="OK",
    ),
    ValidationCommand(
        id="digital_twin_mock_fixtures_unit_test",
        description="Validate Digital Twin mock fixtures.",
        command=[
            sys.executable,
            "-m",
            "unittest",
            "platform_b1_mvp2.tests.test_regulated_operations_digital_twin_mock_fixtures",
        ],
        expected_signal="OK",
    ),
    ValidationCommand(
        id="digital_twin_mock_fixture_validator_cli",
        description="Run Digital Twin mock fixture validator CLI.",
        command=[
            sys.executable,
            str(
                ROOT
                / "regulated_operations_digital_twin"
                / "validator"
                / "digital_twin_mock_fixture_validator.py"
            ),
        ],
        expected_signal="DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED",
    ),
    ValidationCommand(
        id="digital_twin_mock_fixture_validator_unit_test",
        description="Validate Digital Twin mock fixture validator unit tests.",
        command=[
            sys.executable,
            "-m",
            "unittest",
            "platform_b1_mvp2.tests.test_regulated_operations_digital_twin_mock_fixture_validator",
        ],
        expected_signal="OK",
    ),
    ValidationCommand(
        id="result_summary_fixture_validator_cli",
        description="Run Platform B1 local validation result summary fixture validator CLI.",
        command=[
            sys.executable,
            str(
                ROOT
                / "validation"
                / "result_fixtures"
                / "validator"
                / "result_summary_fixture_validator.py"
            ),
        ],
        expected_signal="LOCAL VALIDATION RESULT SUMMARY FIXTURE VALIDATION PASSED",
    ),
    ValidationCommand(
        id="result_summary_fixture_validator_unit_test",
        description="Validate Platform B1 local validation result summary fixture validator unit tests.",
        command=[
            sys.executable,
            "-m",
            "unittest",
            "platform_b1_mvp2.tests.test_platform_b1_local_validation_result_summary_fixture_validator",
        ],
        expected_signal="OK",
    ),
    ValidationCommand(
        id="thread_d2_ramat_vision_display_fixture_validator_cli",
        description="Run Thread D2 RAMAT Vision display fixture validator CLI.",
        command=[
            sys.executable,
            str(
                ROOT
                / "thread_d2_ramat_vision_preview"
                / "validator"
                / "thread_d2_ramat_vision_display_fixture_validator.py"
            ),
        ],
        expected_signal="THREAD D2 RAMAT VISION DISPLAY FIXTURE VALIDATION PASSED",
    ),
    ValidationCommand(
        id="thread_d2_ramat_vision_display_fixture_validator_unit_test",
        description="Validate Thread D2 RAMAT Vision display fixture validator unit tests.",
        command=[
            sys.executable,
            "-m",
            "unittest",
            "platform_b1_mvp2.tests.test_thread_d2_ramat_vision_display_fixture_validator",
        ],
        expected_signal="OK",
    ),
]


def run_validation_command(validation_command: ValidationCommand) -> Dict[str, Any]:
    completed = subprocess.run(
        validation_command.command,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    combined_output = "\n".join(
        part for part in [completed.stdout, completed.stderr] if part
    )

    expected_signal_found = validation_command.expected_signal in combined_output
    passed = completed.returncode == 0 and expected_signal_found

    return {
        "id": validation_command.id,
        "description": validation_command.description,
        "command": validation_command.command,
        "expected_signal": validation_command.expected_signal,
        "expected_signal_found": expected_signal_found,
        "returncode": completed.returncode,
        "passed": passed,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def run_bundle() -> Dict[str, Any]:
    results = [run_validation_command(command) for command in COMMANDS]
    failed = [result for result in results if not result["passed"]]
    passed = len(failed) == 0

    return {
        "bundle_name": BUNDLE_NAME,
        "bundle_status": BUNDLE_STATUS,
        "passed": passed,
        "pass_signal": PASS_SIGNAL if passed else FAIL_SIGNAL,
        "validation_count": len(results),
        "failed_validation_count": len(failed),
        "results": results,
        "commands_locked": [asdict(command) for command in COMMANDS],
        "assurance_outputs": ASSURANCE_OUTPUTS,
        "boundary": BOUNDARY,
    }


def main() -> int:
    report = run_bundle()
    print(json.dumps(report, indent=2))

    if report["passed"]:
        print(PASS_SIGNAL)
        return 0

    print(FAIL_SIGNAL)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
