"""
Workflow Dependency Assurance Lens evaluator.

Platform B1 / MVP2 local evaluator.

Boundary:
- Local mock evaluator only.
- No Azure deployment.
- No Platform B v1 modification.
- No Thread D v1 modification.
- No real ServiceNow, LIS, middleware, eQMS, PHI, GMP production data, or company production data.

Core doctrine:
Platform B1 thinks.
Thread D2 shows.
Official records remain in source systems.
The glasses do not release results.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


FEATURE_NAME = "Workflow Dependency Assurance Lens"

GUARDRAIL = (
    "Platform B1 evaluates dependency assurance. Thread D2 displays the dependency state. "
    "Official records remain in source systems. Glasses do not release results."
)


def _norm(value: Any) -> str:
    """Normalize values for simple mock-rule comparison."""
    if value is None:
        return ""
    return str(value).strip().upper()


def _append_unique(items: List[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


def evaluate_workflow_dependency(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate a mock WorkflowDependencyRecord.

    This first MVP2 evaluator focuses on the Prakriti-inspired case:
    Middleware Verified / LIS Held.

    It detects whether a workflow appears complete in middleware but remains blocked
    because LIS, mandatory fields, mapping, identity, communication path, or audit
    evidence state is not ready.
    """

    checks = record.get("checks", {}) or {}
    result = record.get("result", {}) or {}

    lis_status = _norm(checks.get("lis_status"))
    middleware_status = _norm(checks.get("middleware_status"))
    mandatory_field_status = _norm(checks.get("mandatory_field_status"))
    mapping_status = _norm(checks.get("mapping_status"))
    identity_match_status = _norm(checks.get("identity_match_status"))
    interface_latency_status = _norm(checks.get("interface_latency_status"))
    communication_path_status = _norm(checks.get("communication_path_status"))
    shift_site_drift_status = _norm(checks.get("shift_site_drift_status"))
    manual_entry_risk = _norm(checks.get("manual_entry_risk"))
    secondary_review_status = _norm(checks.get("secondary_review_status"))
    audit_evidence_status = _norm(checks.get("audit_evidence_status"))

    outputs: List[str] = []

    status = "WORKFLOW COMPLETE"
    reason = "DEPENDENCY CHAIN READY"
    required_action = "NO ACTION REQUIRED"
    evidence_state = "AUDIT EVIDENCE READY"
    severity = "green"

    # Core Prakriti case: middleware says verified, LIS is held.
    if middleware_status == "VERIFIED" and lis_status in {"HELD", "HOLD", "BLOCKED", "NOT READY"}:
        status = "WORKFLOW APPEARS COMPLETE BUT BLOCKED"
        reason = "LIS HOLD DETECTED"
        required_action = "SECONDARY REVIEW REQUIRED"
        evidence_state = "AUDIT EVIDENCE NOT READY"
        severity = "red"

        _append_unique(outputs, "WORKFLOW APPEARS COMPLETE BUT BLOCKED")
        _append_unique(outputs, "LIS HOLD DETECTED")
        _append_unique(outputs, "MIDDLEWARE VERIFIED ONLY")
        _append_unique(outputs, "RESULT RELEASE NOT ADMISSIBLE")

    if mandatory_field_status in {"MISSING", "INCOMPLETE", "BLANK", "NOT READY"}:
        status = "WORKFLOW APPEARS COMPLETE BUT BLOCKED"
        reason = "LIS HOLD DETECTED" if reason == "DEPENDENCY CHAIN READY" else reason
        required_action = "SECONDARY REVIEW REQUIRED"
        evidence_state = "AUDIT EVIDENCE NOT READY"
        severity = "red"

        _append_unique(outputs, "MANDATORY FIELD MISSING")
        _append_unique(outputs, "SECONDARY REVIEW REQUIRED")
        _append_unique(outputs, "RESULT RELEASE NOT ADMISSIBLE")

    if mapping_status in {"CONFLICT", "MISMATCH", "INVALID"}:
        status = "WORKFLOW APPEARS COMPLETE BUT BLOCKED"
        reason = "MAPPING CONFLICT"
        required_action = "SECONDARY REVIEW REQUIRED"
        evidence_state = "AUDIT EVIDENCE NOT READY"
        severity = "red"

        _append_unique(outputs, "MAPPING CONFLICT")
        _append_unique(outputs, "SECONDARY REVIEW REQUIRED")
        _append_unique(outputs, "RESULT RELEASE NOT ADMISSIBLE")

    if identity_match_status in {"MISMATCH", "CONFLICT", "INVALID"}:
        status = "WORKFLOW APPEARS COMPLETE BUT BLOCKED"
        reason = "IDENTITY MISMATCH"
        required_action = "SECONDARY REVIEW REQUIRED"
        evidence_state = "AUDIT EVIDENCE NOT READY"
        severity = "red"

        _append_unique(outputs, "IDENTITY MISMATCH")
        _append_unique(outputs, "SECONDARY REVIEW REQUIRED")
        _append_unique(outputs, "RESULT RELEASE NOT ADMISSIBLE")

    if interface_latency_status in {"DELAYED", "HIGH", "TIMEOUT", "LATENCY DETECTED"}:
        if severity != "red":
            severity = "amber"
        _append_unique(outputs, "INTERFACE LATENCY DETECTED")

    if communication_path_status in {"BLOCKED", "FAILED", "TIMEOUT", "UNAVAILABLE"}:
        status = "WORKFLOW APPEARS COMPLETE BUT BLOCKED"
        reason = "COMMUNICATION PATH BLOCKED"
        required_action = "SECONDARY REVIEW REQUIRED"
        evidence_state = "AUDIT EVIDENCE NOT READY"
        severity = "red"

        _append_unique(outputs, "COMMUNICATION PATH BLOCKED")
        _append_unique(outputs, "SECONDARY REVIEW REQUIRED")
        _append_unique(outputs, "RESULT RELEASE NOT ADMISSIBLE")

    if shift_site_drift_status not in {"", "NO DRIFT", "NONE", "ALIGNED"}:
        if severity != "red":
            severity = "amber"
        _append_unique(outputs, "SHIFT/SITE PROCESS DRIFT")

    if manual_entry_risk in {"MEDIUM", "HIGH", "REVIEW REQUIRED"}:
        if severity != "red":
            severity = "amber"
        _append_unique(outputs, "MANUAL ENTRY REVIEW REQUIRED")

    if secondary_review_status == "REQUIRED":
        _append_unique(outputs, "SECONDARY REVIEW REQUIRED")

    if audit_evidence_status in {"READY", "COMPLETE"} and severity == "green":
        _append_unique(outputs, "AUDIT EVIDENCE READY")
    elif audit_evidence_status in {"NOT READY", "MISSING", "INCOMPLETE"}:
        evidence_state = "AUDIT EVIDENCE NOT READY"

    if status == "WORKFLOW COMPLETE":
        _append_unique(outputs, "WORKFLOW COMPLETE")
        if audit_evidence_status in {"READY", "COMPLETE"}:
            _append_unique(outputs, "AUDIT EVIDENCE READY")

    if not outputs:
        _append_unique(outputs, "WORKFLOW COMPLETE")
        _append_unique(outputs, "AUDIT EVIDENCE READY")

    # Preserve the source record expected result for traceability, but evaluator output is authoritative for MVP2 mock logic.
    expected_from_record = {
        "status": result.get("status"),
        "reason": result.get("reason"),
        "required_action": result.get("required_action"),
        "evidence_state": result.get("evidence_state"),
    }

    return {
        "feature_name": FEATURE_NAME,
        "workflow_id": record.get("workflow_id"),
        "case_name": record.get("case_name"),
        "status": status,
        "reason": reason,
        "required_action": required_action,
        "evidence_state": evidence_state,
        "severity": severity,
        "outputs": outputs,
        "d2_display": {
            "headline": status,
            "reason": reason,
            "action": required_action,
            "evidence_state": evidence_state,
            "badge": "MVP2 PREVIEW",
        },
        "expected_from_record": expected_from_record,
        "guardrail": GUARDRAIL,
    }


def load_record(path: str | Path) -> Dict[str, Any]:
    record_path = Path(path)
    with record_path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def evaluate_file(path: str | Path) -> Dict[str, Any]:
    return evaluate_workflow_dependency(load_record(path))


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate a mock Workflow Dependency Assurance record.")
    parser.add_argument("record", help="Path to WorkflowDependencyRecord JSON file.")
    args = parser.parse_args()

    evaluation = evaluate_file(args.record)
    print(json.dumps(evaluation, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

