from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Tuple


TWIN_DIR = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE_DIR = TWIN_DIR / "mock_fixtures"

REQUIRED_FIXTURE_STATUS = "LOCKED_MOCK_FIXTURE_ONLY"

REQUIRED_TOP_LEVEL_FIELDS = {
    "fixture_name",
    "fixture_status",
    "track_id",
    "scenario_id",
    "source",
    "purpose",
    "twin_state",
    "expected_platform_b1_outputs",
    "boundary",
}

COMMON_REQUIRED_TWIN_FAMILIES = {
    "identity_role_persona",
    "workflow_dependency_chain",
    "evidence_integrity",
    "ai_agent_output",
    "ramat_vision_display",
}

COMMON_REQUIRED_BOUNDARY_PHRASES = {
    "Mock fixture only.",
    "No PHI.",
    "No product release decision.",
    "No source-system override.",
    "Platform B1 evaluates.",
    "Thread D2 displays.",
    "RAMAT Vision displays only.",
}

TRACK_RULES: Dict[str, Dict[str, Any]] = {
    "compound_pharmacy": {
        "expected_file": "compound_pharmacy_preparation_package_review.json",
        "expected_scenario": "compound_pharmacy_preparation_package_review",
        "required_twin_families": {
            "material_product_supply_chain",
            "execution_context",
        },
        "required_outputs": {
            "COMPOUNDING EVIDENCE SEALED",
            "HASH VERIFIED",
            "BUD EVIDENCE REVIEW REQUIRED",
            "AI CONTENT REVIEW REQUIRED",
            "HUMAN REVIEW REQUIRED",
            "QUALITY REVIEW REQUIRED",
            "COMPOUNDING WORKFLOW APPEARS COMPLETE BUT BLOCKED",
            "COMPOUNDING PACKAGE NOT YET DEFENSIBLE",
        },
        "track_boundary_phrases": {
            "No real pharmacy production data.",
            "No real patient data.",
            "No pharmacist replacement.",
        },
    },
    "irlt_radiopharma_operations": {
        "expected_file": "irlt_equipment_ci_quality_handoff_review.json",
        "expected_scenario": "irlt_equipment_ci_quality_handoff_review",
        "required_twin_families": {
            "equipment_ci_asset",
            "quality_state",
            "execution_context",
        },
        "required_outputs": {
            "IRLT EVIDENCE SEALED",
            "HASH VERIFIED",
            "CI READINESS GAP",
            "SUPPORT GROUP MISSING",
            "INCIDENT IMPACT REVIEW REQUIRED",
            "QUALITY DEPENDENCY BLOCKED",
            "AI RECOMMENDATION REVIEW REQUIRED",
            "RAMAT VISION DISPLAY READY",
            "HUMAN REVIEW REQUIRED",
            "IRLT WORKFLOW APPEARS COMPLETE BUT BLOCKED",
        },
        "track_boundary_phrases": {
            "No real ServiceNow production data.",
            "No real radiopharma production data.",
            "No GMP approval decision.",
            "No Quality Unit replacement.",
        },
    },
    "dscsa_evidence_integrity_exception_assurance": {
        "expected_file": "dscsa_late_epcis_vrs_no_response_exception.json",
        "expected_scenario": "dscsa_late_epcis_vrs_no_response_exception",
        "required_twin_families": {
            "material_product_supply_chain",
            "quality_state",
        },
        "required_outputs": {
            "DSCSA EXCEPTION DETECTED",
            "EPCIS FILE MISMATCH",
            "VRS RESPONSE MISSING",
            "TRADING PARTNER EVIDENCE STALE",
            "AI EXCEPTION CLASSIFICATION GENERATED",
            "HUMAN REVIEW REQUIRED",
            "QUARANTINE REQUIRED",
            "EXCEPTION NOT DEFENSIBLE",
        },
        "track_boundary_phrases": {
            "No real EPCIS integration.",
            "No real VRS integration.",
            "No real DSCSA production data.",
            "No quarantine override.",
        },
    },
}


def load_fixture(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def _as_text_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def validate_fixture(fixture: Dict[str, Any], filename: str = "") -> List[str]:
    errors: List[str] = []

    missing_top_level = sorted(REQUIRED_TOP_LEVEL_FIELDS.difference(fixture.keys()))
    if missing_top_level:
        errors.append(f"{filename}: missing top-level fields: {', '.join(missing_top_level)}")

    if fixture.get("fixture_status") != REQUIRED_FIXTURE_STATUS:
        errors.append(
            f"{filename}: fixture_status must be {REQUIRED_FIXTURE_STATUS}"
        )

    track_id = fixture.get("track_id")
    if track_id not in TRACK_RULES:
        errors.append(f"{filename}: unsupported track_id: {track_id}")
        return errors

    rules = TRACK_RULES[track_id]

    if filename and filename != rules["expected_file"]:
        errors.append(
            f"{filename}: expected filename for track {track_id} is {rules['expected_file']}"
        )

    if fixture.get("scenario_id") != rules["expected_scenario"]:
        errors.append(
            f"{filename}: scenario_id must be {rules['expected_scenario']}"
        )

    twin_state = fixture.get("twin_state", {})
    if not isinstance(twin_state, dict):
        errors.append(f"{filename}: twin_state must be an object")
        twin_state = {}

    required_families = COMMON_REQUIRED_TWIN_FAMILIES.union(
        rules["required_twin_families"]
    )
    missing_families = sorted(required_families.difference(twin_state.keys()))
    if missing_families:
        errors.append(
            f"{filename}: missing twin_state families: {', '.join(missing_families)}"
        )

    expected_outputs = set(_as_text_list(fixture.get("expected_platform_b1_outputs")))
    missing_outputs = sorted(rules["required_outputs"].difference(expected_outputs))
    if missing_outputs:
        errors.append(
            f"{filename}: missing expected Platform B1 outputs: {', '.join(missing_outputs)}"
        )

    boundary = set(_as_text_list(fixture.get("boundary")))
    required_boundaries = COMMON_REQUIRED_BOUNDARY_PHRASES.union(
        rules["track_boundary_phrases"]
    )
    missing_boundaries = sorted(required_boundaries.difference(boundary))
    if missing_boundaries:
        errors.append(
            f"{filename}: missing boundary phrases: {', '.join(missing_boundaries)}"
        )

    ai_state = twin_state.get("ai_agent_output", {})
    if isinstance(ai_state, dict):
        if ai_state.get("approval_boundary") != "recommendation_only":
            errors.append(
                f"{filename}: ai_agent_output.approval_boundary must be recommendation_only"
            )
        ai_outputs = set(_as_text_list(ai_state.get("outputs")))
        if "AI OUTPUT HASHED" not in ai_outputs:
            errors.append(
                f"{filename}: AI outputs must include AI OUTPUT HASHED"
            )
        if "AGENT ACTION NOT ADMISSIBLE" not in ai_outputs:
            errors.append(
                f"{filename}: AI outputs must include AGENT ACTION NOT ADMISSIBLE"
            )
    else:
        errors.append(f"{filename}: ai_agent_output must be an object")

    display_state = twin_state.get("ramat_vision_display", {})
    if isinstance(display_state, dict):
        if display_state.get("approval_authority") is not False:
            errors.append(
                f"{filename}: ramat_vision_display.approval_authority must be false"
            )
        display_outputs = set(_as_text_list(display_state.get("outputs")))
        if "RAMAT VISION DISPLAY READY" not in display_outputs:
            errors.append(
                f"{filename}: RAMAT Vision outputs must include RAMAT VISION DISPLAY READY"
            )
    else:
        errors.append(f"{filename}: ramat_vision_display must be an object")

    evidence_state = twin_state.get("evidence_integrity", {})
    if isinstance(evidence_state, dict):
        evidence_outputs = set(_as_text_list(evidence_state.get("outputs")))
        if "HASH VERIFIED" not in evidence_outputs:
            errors.append(
                f"{filename}: evidence_integrity.outputs must include HASH VERIFIED"
            )
    else:
        errors.append(f"{filename}: evidence_integrity must be an object")

    return errors


def validate_fixture_file(path: Path) -> Tuple[bool, List[str]]:
    try:
        fixture = load_fixture(path)
    except json.JSONDecodeError as exc:
        return False, [f"{path.name}: invalid JSON: {exc}"]
    except OSError as exc:
        return False, [f"{path.name}: cannot read file: {exc}"]

    errors = validate_fixture(fixture, filename=path.name)
    return not errors, errors


def validate_all_fixtures(fixture_dir: Path = DEFAULT_FIXTURE_DIR) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []

    expected_files = [rules["expected_file"] for rules in TRACK_RULES.values()]

    for filename in expected_files:
        path = fixture_dir / filename
        if not path.exists():
            results.append(
                {
                    "fixture": filename,
                    "passed": False,
                    "errors": [f"{filename}: expected fixture file is missing"],
                }
            )
            continue

        passed, errors = validate_fixture_file(path)
        results.append(
            {
                "fixture": filename,
                "passed": passed,
                "errors": errors,
            }
        )

    return {
        "validator_name": "Digital Twin Mock Fixture Validator",
        "validator_status": "LOCKED_LOCAL_VALIDATOR_ONLY",
        "fixture_count": len(results),
        "passed": all(result["passed"] for result in results),
        "results": results,
    }


def clone_fixture(fixture: Dict[str, Any]) -> Dict[str, Any]:
    return deepcopy(fixture)


def main() -> int:
    report = validate_all_fixtures()

    print(json.dumps(report, indent=2))

    if report["passed"]:
        print("DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED")
        return 0

    print("DIGITAL TWIN MOCK FIXTURE VALIDATION FAILED")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

