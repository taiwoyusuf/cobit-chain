from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[3]
ROOT = REPO_ROOT / "platform_b1_mvp2"

DISPLAY_FIXTURE_JSON = (
    ROOT
    / "thread_d2_ramat_vision_preview"
    / "platform_b1_local_validation_result_summary_display_fixture.json"
)

DISPLAY_FIXTURE_MD = (
    ROOT
    / "thread_d2_ramat_vision_preview"
    / "PLATFORM_B1_LOCAL_VALIDATION_RESULT_SUMMARY_DISPLAY_FIXTURE.md"
)

VALIDATOR_NAME = "Thread D2 RAMAT Vision Display Fixture Validator"
VALIDATOR_STATUS = "LOCKED_THREAD_D2_DISPLAY_FIXTURE_VALIDATOR_ONLY"
PASS_SIGNAL = "THREAD D2 RAMAT VISION DISPLAY FIXTURE VALIDATION PASSED"

REQUIRED_TOP_LEVEL_FIELDS = [
    "display_fixture_name",
    "fixture_status",
    "workstream",
    "source_workstream",
    "source_bundle",
    "source_bundle_status",
    "source_result_summary_fixture",
    "source_result_type",
    "display_type",
    "display_state",
    "source_validation_summary",
    "ramat_vision_cards",
    "required_assurance_signals",
    "display_doctrine",
    "boundary",
]

REQUIRED_ASSURANCE_SIGNALS = [
    "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED",
    "DIGITAL TWIN OBJECT MODEL VALIDATED",
    "DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED",
    "LOCAL VALIDATION RESULT SUMMARY FIXTURE VALIDATION PASSED",
    "AI OUTPUT HASHED",
    "HASH VERIFIED",
    "AGENT ACTION NOT ADMISSIBLE",
    "RAMAT VISION DISPLAY READY",
    "PLATFORM B1 DECISION DISPLAYED",
]

REQUIRED_CARD_TITLES = [
    "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED",
    "EVIDENCE INTEGRITY SIGNALS PRESENT",
    "AGENT ACTION NOT ADMISSIBLE",
    "RAMAT VISION DISPLAYS ONLY",
]

REQUIRED_DISPLAY_STATE = {
    "thread_d2_display_status": "PREVIEW_READY",
    "ramat_vision_display_status": "DISPLAY_READY",
    "platform_b1_decision_status": "DISPLAYED_ONLY",
    "operator_action_status": "NOT_AUTHORIZED_BY_DISPLAY",
    "quality_unit_status": "NOT_REPLACED",
    "source_system_status": "NOT_OVERRIDDEN",
}

REQUIRED_SOURCE_VALIDATION_SUMMARY = {
    "overall_status": "PASSED",
    "validation_count": 6,
    "failed_validation_count": 0,
    "result_admissibility": "LOCAL_VALIDATION_SUMMARY_ONLY",
    "azure_deployment_status": "NOT_DEPLOYED",
    "platform_b_v1_impact": "NONE",
    "thread_d_v1_impact": "NONE",
    "mvp3_activation": "NONE",
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
    "Thread D2 display fixture only.",
    "RAMAT Vision preview display only.",
    "Display fixture only.",
    "Local validation evidence only.",
    "No Azure deployment.",
    "No Azure Digital Twins deployment.",
    "No Platform B v1 change.",
    "No Thread D v1 change.",
    "No MVP3 activation.",
    "No real glasses hardware integration.",
    "No real Halo hardware integration.",
    "No real production system connection.",
    "No real ServiceNow production data.",
    "No real LIS, MES, ERP, eQMS, QMS, VRS, EPCIS, pharmacy, or radiopharma production data.",
    "No PHI.",
    "No company production data.",
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

REQUIRED_MARKDOWN_PHRASES = [
    "LOCKED THREAD D2 DISPLAY FIXTURE ONLY",
    "Thread D2 — RAMAT Vision Advanced Assurance Preview",
    "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED",
    "AI OUTPUT HASHED",
    "HASH VERIFIED",
    "AGENT ACTION NOT ADMISSIBLE",
    "RAMAT VISION DISPLAY READY",
    "PLATFORM B1 DECISION DISPLAYED",
    "Platform B1 evaluates",
    "Thread D2 displays",
    "RAMAT Vision displays only",
    "No real Halo hardware integration",
    "No product release decision",
    "No Quality Unit replacement",
]


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _contains_all(values: List[str], required: List[str]) -> List[str]:
    present = " ".join(values)
    return [item for item in required if item not in present]


def validate_display_fixture() -> Dict[str, Any]:
    errors: List[str] = []

    if not DISPLAY_FIXTURE_JSON.exists():
        errors.append(f"Missing display fixture JSON: {DISPLAY_FIXTURE_JSON}")
        return _report(errors)

    if not DISPLAY_FIXTURE_MD.exists():
        errors.append(f"Missing display fixture markdown: {DISPLAY_FIXTURE_MD}")
        return _report(errors)

    try:
        fixture = _load_json(DISPLAY_FIXTURE_JSON)
    except json.JSONDecodeError as exc:
        errors.append(f"Invalid display fixture JSON: {exc}")
        return _report(errors)

    markdown = DISPLAY_FIXTURE_MD.read_text(encoding="utf-8-sig")

    for field in REQUIRED_TOP_LEVEL_FIELDS:
        if field not in fixture:
            errors.append(f"Missing top-level field: {field}")

    if errors:
        return _report(errors)

    if fixture["display_fixture_name"] != "Thread D2 RAMAT Vision Local Validation Result Summary Display Fixture":
        errors.append("Unexpected display_fixture_name.")

    if fixture["fixture_status"] != "LOCKED_THREAD_D2_DISPLAY_FIXTURE_ONLY":
        errors.append("fixture_status must be LOCKED_THREAD_D2_DISPLAY_FIXTURE_ONLY.")

    if fixture["workstream"] != "Thread D2 — RAMAT Vision Advanced Assurance Preview":
        errors.append("Unexpected Thread D2 workstream.")

    if fixture["source_workstream"] != "Platform B1 / MVP2":
        errors.append("source_workstream must be Platform B1 / MVP2.")

    if fixture["source_bundle"] != "Platform B1 / MVP2 Local Validation Bundle":
        errors.append("source_bundle must be Platform B1 / MVP2 Local Validation Bundle.")

    if fixture["source_result_type"] != "LOCAL_VALIDATION_RESULT_SUMMARY":
        errors.append("source_result_type must be LOCAL_VALIDATION_RESULT_SUMMARY.")

    if fixture["display_type"] != "RAMAT_VISION_PREVIEW_DISPLAY_ONLY":
        errors.append("display_type must be RAMAT_VISION_PREVIEW_DISPLAY_ONLY.")

    display_state = fixture.get("display_state", {})
    for key, expected in REQUIRED_DISPLAY_STATE.items():
        if display_state.get(key) != expected:
            errors.append(f"display_state.{key} must be {expected}.")

    source_summary = fixture.get("source_validation_summary", {})
    for key, expected in REQUIRED_SOURCE_VALIDATION_SUMMARY.items():
        if source_summary.get(key) != expected:
            errors.append(f"source_validation_summary.{key} must be {expected}.")

    cards = fixture.get("ramat_vision_cards", [])
    if len(cards) != 4:
        errors.append("ramat_vision_cards must contain exactly 4 cards.")

    card_titles = [card.get("card_title", "") for card in cards]
    for required_title in REQUIRED_CARD_TITLES:
        if required_title not in card_titles:
            errors.append(f"Missing RAMAT Vision card title: {required_title}")

    for card in cards:
        for field in [
            "card_id",
            "card_title",
            "display_level",
            "display_message",
            "allowed_interpretation",
            "prohibited_interpretation",
        ]:
            if field not in card:
                errors.append(f"RAMAT Vision card missing field {field}: {card}")

    missing_signals = _contains_all(
        fixture.get("required_assurance_signals", []),
        REQUIRED_ASSURANCE_SIGNALS,
    )
    for signal in missing_signals:
        errors.append(f"Missing required assurance signal: {signal}")

    missing_doctrine = _contains_all(
        fixture.get("display_doctrine", []),
        REQUIRED_DOCTRINE_PHRASES,
    )
    for phrase in missing_doctrine:
        errors.append(f"Missing display doctrine phrase: {phrase}")

    missing_boundary = _contains_all(
        fixture.get("boundary", []),
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
        "display_fixture": DISPLAY_FIXTURE_JSON.name,
        "passed": len(errors) == 0,
        "errors": errors,
        "required_assurance_signals": REQUIRED_ASSURANCE_SIGNALS,
        "required_card_titles": REQUIRED_CARD_TITLES,
        "required_display_state": REQUIRED_DISPLAY_STATE,
        "required_source_validation_summary": REQUIRED_SOURCE_VALIDATION_SUMMARY,
        "boundary_mode": [
            "Thread D2 display fixture validator only.",
            "RAMAT Vision preview display only.",
            "No Azure deployment.",
            "No Platform B v1 change.",
            "No Thread D v1 change.",
            "No real glasses hardware integration.",
            "No real Halo hardware integration.",
            "No product release decision.",
            "No GMP approval decision.",
            "No Quality Unit replacement.",
        ],
    }


def main() -> int:
    report = validate_display_fixture()
    print(json.dumps(report, indent=2))

    if report["passed"]:
        print(PASS_SIGNAL)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
