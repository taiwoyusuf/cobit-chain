from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


REPO_ROOT = Path(__file__).resolve().parents[2]
PLATFORM_B1_ROOT = REPO_ROOT / "platform_b1_mvp2"

BUNDLE_NAME = "Platform B1 / MVP2 Local Validation Bundle"
BUNDLE_STATUS = "LOCKED_LOCAL_VALIDATION_BUNDLE_ONLY"

VALIDATION_COMMANDS = [
    {
        "id": "digital_twin_object_model_unit_test",
        "description": "Validate Regulated Operations Digital Twin object model.",
        "command": [
            sys.executable,
            "-m",
            "unittest",
            "platform_b1_mvp2.tests.test_regulated_operations_digital_twin_object_model",
        ],
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
    },
    {
        "id": "digital_twin_mock_fixture_validator_cli",
        "description": "Run Digital Twin mock fixture validator CLI.",
        "command": [
            sys.executable,
            str(
                PLATFORM_B1_ROOT
                / "regulated_operations_digital_twin"
                / "validator"
                / "digital_twin_mock_fixture_validator.py"
            ),
        ],
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
    },
]


BOUNDARY = [
    "Local validation bundle only.",
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
]


@dataclass(frozen=True)
class ValidationResult:
    id: str
    description: str
    passed: bool
    returncode: int
    stdout: str
    stderr: str


def run_command(command_spec: Dict[str, object]) -> ValidationResult:
    completed = subprocess.run(
        command_spec["command"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    return ValidationResult(
        id=str(command_spec["id"]),
        description=str(command_spec["description"]),
        passed=completed.returncode == 0,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def run_validation_bundle() -> Dict[str, object]:
    results: List[ValidationResult] = [
        run_command(command_spec) for command_spec in VALIDATION_COMMANDS
    ]

    return {
        "bundle_name": BUNDLE_NAME,
        "bundle_status": BUNDLE_STATUS,
        "validation_count": len(results),
        "passed": all(result.passed for result in results),
        "results": [
            {
                "id": result.id,
                "description": result.description,
                "passed": result.passed,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
            for result in results
        ],
        "boundary": BOUNDARY,
    }


def main() -> int:
    report = run_validation_bundle()

    print(json.dumps(report, indent=2))

    if report["passed"]:
        print("PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED")
        return 0

    print("PLATFORM B1 LOCAL VALIDATION BUNDLE FAILED")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
