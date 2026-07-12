import json
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[2]
PASSPORT_JSON = ROOT / "research_watch" / "platform_b1_agentic_ambient_ai_vendor_assurance_passport.json"
PASSPORT_MD = ROOT / "research_watch" / "PLATFORM_B1_AGENTIC_AMBIENT_AI_VENDOR_ASSURANCE_PASSPORT.md"

PASS_SIGNAL = "AGENTIC AMBIENT AI VENDOR ASSURANCE PASSPORT VALIDATION PASSED"

EXPECTED_DOMAINS = [
    "Intended Use and Consequence Classification",
    "Regulatory Applicability Map",
    "Data, Privacy, Consent, and Information Governance",
    "Vendor, Subprocessor, and Contract Assurance",
    "Model, Agent, Tool, and Automation Boundary",
    "Human Authority and No-Bind Governance",
    "Evidence Capture and Audit Reconstruction",
    "Validation, Testing, and Real-World Performance",
    "Security, Identity, Access, and Logging",
    "Change Control, Drift, and Lifecycle Monitoring",
    "Incident, Deviation, CAPA, Complaint, and Safety Readiness",
    "Exit, Continuity, Data Return, and Decommissioning",
]

EXPECTED_OUTPUTS = [
    "VENDOR ASSURANCE PASSPORT CREATED",
    "INTENDED USE CLASSIFIED",
    "REGULATORY APPLICABILITY MAPPED",
    "DATA GOVERNANCE REVIEW REQUIRED",
    "HUMAN AUTHORITY REQUIRED",
    "NO-BIND GOVERNANCE REQUIRED",
    "AUDIT RECONSTRUCTION REQUIRED",
    "MODEL AND AGENT BOUNDARY REVIEW REQUIRED",
    "VALIDATION EVIDENCE REQUIRED",
    "CHANGE CONTROL REQUIRED",
    "INCIDENT READINESS REQUIRED",
    "VENDOR EXIT PLAN REQUIRED",
    "ACTION NOT ADMISSIBLE WITHOUT EVIDENCE",
    "AI OUTPUT NOT BINDING",
]

EXPECTED_AUDIT_TRAIL = [
    "ai_system_id",
    "vendor_id",
    "use_case_id",
    "workflow_id",
    "source_input_reference",
    "ai_output_reference",
    "human_reviewer_id_or_role",
    "reviewer_qualification_status",
    "review_started_timestamp",
    "review_completed_timestamp",
    "human_edits_reference",
    "approval_or_rejection_status",
    "authority_basis",
    "no_bind_state",
    "evidence_hash",
    "final_record_reference",
]

EXPECTED_BOUNDARY_PHRASES = [
    "Vendor assurance passport registry only.",
    "Local research watch only.",
    "No architecture change.",
    "No Platform B v1 change.",
    "No Thread D v1 change.",
    "No Platform B1 local validation bundle count change.",
    "No MVP3 activation.",
    "No Azure deployment.",
    "No Azure Digital Twins deployment.",
    "No real production system connection.",
    "No real vendor integration.",
    "No real healthcare system integration.",
    "No real EHR integration.",
    "No PHI.",
    "No company production data.",
    "No clinical decision support claim.",
    "No patient-specific medical decision.",
    "No diagnosis.",
    "No treatment recommendation.",
    "No regulated action execution.",
    "No binding operational consequence.",
]

EXPECTED_MARKDOWN_PHRASES = [
    "Agentic & Ambient AI Vendor Assurance Passport™",
    "trusted, reconstructed, reviewed, governed, and defended",
    "A checklist asks: can we sign this vendor contract?",
    "Human-in-the-loop is not sufficient",
    "Information governance is part of AI governance",
    "Human Authority and No-Bind Governance",
    "Evidence Capture and Audit Reconstruction",
    "ACTION NOT ADMISSIBLE WITHOUT EVIDENCE",
    "AI OUTPUT NOT BINDING",
    "No Platform B v1 change",
    "No Thread D v1 change",
    "No Platform B1 local validation bundle count change",
    "No real EHR integration",
    "No clinical decision support claim",
    "No patient-specific medical decision",
    "No diagnosis",
    "No treatment recommendation",
]


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _load_text(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")
    return path.read_text(encoding="utf-8-sig")


def _require(errors: List[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def validate_passport() -> Dict[str, Any]:
    errors: List[str] = []
    passport = _load_json(PASSPORT_JSON)
    markdown = _load_text(PASSPORT_MD)

    _require(errors, passport.get("registry_name") == "Platform B1 Agentic & Ambient AI Vendor Assurance Passport Registry", "registry_name mismatch")
    _require(errors, passport.get("registry_status") == "LOCKED_AGENTIC_AMBIENT_AI_VENDOR_ASSURANCE_PASSPORT_ONLY", "registry_status mismatch")
    _require(errors, passport.get("registry_type") == "LOCAL_RESEARCH_WATCH_ASSURANCE_PASSPORT_REGISTRY", "registry_type mismatch")
    _require(errors, passport.get("passport_name") == "Agentic & Ambient AI Vendor Assurance Passport™", "passport_name mismatch")

    core_question = passport.get("core_question", "")
    _require(errors, "trusted, reconstructed, reviewed, governed, and defended" in core_question, "core question assurance language missing")
    _require(errors, "moment it matters" in core_question, "moment-it-matters language missing")

    positioning = " ".join(str(value) for value in passport.get("positioning", {}).values())
    _require(errors, "not merely a vendor checklist" in positioning, "not-just-checklist positioning missing")
    _require(errors, "Platform B1 evaluates" in positioning, "Platform B1 relationship missing")
    _require(errors, "RAMAT Vision displays assurance state only" in positioning, "Thread D2 display-only relationship missing")

    source_problem = " ".join(passport.get("source_problem_statement", []))
    _require(errors, "deployed before governance documentation is mature" in source_problem, "deployment-before-governance problem missing")
    _require(errors, "what the AI produced" in source_problem, "AI-produced reconstruction missing")
    _require(errors, "what the human saw" in source_problem, "human-saw reconstruction missing")
    _require(errors, "Human-in-the-loop is not sufficient" in source_problem, "human-in-the-loop insufficiency missing")
    _require(errors, "Information governance is part of AI governance" in source_problem, "information governance doctrine missing")

    domains = passport.get("assurance_domains", [])
    _require(errors, len(domains) == 12, "expected exactly 12 assurance domains")
    _require(errors, [domain.get("domain_name") for domain in domains] == EXPECTED_DOMAINS, "assurance domain sequence mismatch")

    for domain in domains:
        domain_name = domain.get("domain_name", "UNKNOWN")
        _require(errors, bool(domain.get("assurance_question")), f"{domain_name} missing assurance_question")
        _require(errors, len(domain.get("required_evidence", [])) >= 5, f"{domain_name} has insufficient required evidence")
        _require(errors, len(domain.get("red_flags", [])) >= 3, f"{domain_name} has insufficient red flags")

    _require(errors, passport.get("required_outputs", []) == EXPECTED_OUTPUTS, "required outputs sequence mismatch")
    _require(errors, passport.get("minimum_audit_trail", []) == EXPECTED_AUDIT_TRAIL, "minimum audit trail sequence mismatch")

    scoring = passport.get("assurance_scoring_model", {})
    _require(errors, scoring.get("passport_score_range") == "0-100", "passport score range mismatch")
    _require(errors, scoring.get("minimum_passport_threshold") == 80, "minimum passport threshold mismatch")
    _require(errors, "ACTION NOT ADMISSIBLE WITHOUT EVIDENCE" in scoring.get("critical_domain_failure_rule", ""), "critical failure rule missing")

    implementation_status = passport.get("implementation_status", {})
    _require(errors, implementation_status.get("platform_b_v1_impact") == "NONE", "platform_b_v1_impact must be NONE")
    _require(errors, implementation_status.get("thread_d_v1_impact") == "NONE", "thread_d_v1_impact must be NONE")
    _require(errors, implementation_status.get("local_validation_bundle_count_change") == "NONE", "local bundle count change must be NONE")
    _require(errors, implementation_status.get("azure_deployment_status") == "NOT_DEPLOYED", "azure deployment status must be NOT_DEPLOYED")
    _require(errors, implementation_status.get("azure_digital_twins_status") == "NOT_DEPLOYED", "Azure Digital Twins status must be NOT_DEPLOYED")
    _require(errors, implementation_status.get("mvp3_activation") == "NONE", "mvp3 activation must be NONE")

    boundary = passport.get("boundary", [])
    for phrase in EXPECTED_BOUNDARY_PHRASES:
        _require(errors, phrase in boundary, f"boundary missing: {phrase}")

    for phrase in EXPECTED_MARKDOWN_PHRASES:
        _require(errors, phrase in markdown, f"markdown missing: {phrase}")

    passed = not errors
    return {
        "validator_name": "Platform B1 Agentic & Ambient AI Vendor Assurance Passport Validator",
        "validator_status": "LOCKED_AGENTIC_AMBIENT_AI_VENDOR_ASSURANCE_PASSPORT_VALIDATOR_ONLY",
        "passport": PASSPORT_JSON.name,
        "passed": passed,
        "errors": errors,
        "required_domain_count": len(EXPECTED_DOMAINS),
        "required_outputs": EXPECTED_OUTPUTS,
        "minimum_audit_trail": EXPECTED_AUDIT_TRAIL,
        "boundary_mode": EXPECTED_BOUNDARY_PHRASES,
    }


def main() -> int:
    result = validate_passport()
    print(json.dumps(result, indent=2))
    if result["passed"]:
        print(PASS_SIGNAL)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
