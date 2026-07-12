import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"

PASSPORT_JSON = ROOT / "research_watch" / "platform_b1_agentic_ambient_ai_vendor_assurance_passport.json"
PASSPORT_MD = ROOT / "research_watch" / "PLATFORM_B1_AGENTIC_AMBIENT_AI_VENDOR_ASSURANCE_PASSPORT.md"


class PlatformB1AgenticAmbientAIVendorAssurancePassportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.passport = json.loads(PASSPORT_JSON.read_text(encoding="utf-8-sig"))
        cls.markdown = PASSPORT_MD.read_text(encoding="utf-8-sig")

    def test_passport_identity_is_locked(self):
        self.assertEqual(
            self.passport["registry_name"],
            "Platform B1 Agentic & Ambient AI Vendor Assurance Passport Registry",
        )
        self.assertEqual(
            self.passport["registry_status"],
            "LOCKED_AGENTIC_AMBIENT_AI_VENDOR_ASSURANCE_PASSPORT_ONLY",
        )
        self.assertEqual(
            self.passport["registry_type"],
            "LOCAL_RESEARCH_WATCH_ASSURANCE_PASSPORT_REGISTRY",
        )
        self.assertEqual(
            self.passport["passport_name"],
            "Agentic & Ambient AI Vendor Assurance Passport™",
        )

    def test_core_question_is_preserved(self):
        self.assertIn("trusted, reconstructed, reviewed, governed, and defended", self.passport["core_question"])
        self.assertIn("moment it matters", self.passport["core_question"])

    def test_not_just_checklist_positioning_is_preserved(self):
        positioning = " ".join(self.passport["positioning"].values())
        self.assertIn("not merely a vendor checklist", positioning)
        self.assertIn("pre-contract, pre-deployment, runtime, and audit-reconstruction", positioning)
        self.assertIn("Platform B1 evaluates", positioning)
        self.assertIn("RAMAT Vision displays assurance state only", positioning)

    def test_source_problem_statement_is_preserved(self):
        problem = " ".join(self.passport["source_problem_statement"])
        self.assertIn("deployed before governance documentation is mature", problem)
        self.assertIn("what the AI produced", problem)
        self.assertIn("what the human saw", problem)
        self.assertIn("Human-in-the-loop is not sufficient", problem)
        self.assertIn("Information governance is part of AI governance", problem)

    def test_twelve_assurance_domains_are_locked(self):
        domains = self.passport["assurance_domains"]
        self.assertEqual(len(domains), 12)

        expected_names = [
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

        actual_names = [domain["domain_name"] for domain in domains]
        self.assertEqual(actual_names, expected_names)

    def test_required_outputs_are_locked(self):
        outputs = self.passport["required_outputs"]

        self.assertEqual(len(outputs), 14)
        self.assertIn("VENDOR ASSURANCE PASSPORT CREATED", outputs)
        self.assertIn("INTENDED USE CLASSIFIED", outputs)
        self.assertIn("REGULATORY APPLICABILITY MAPPED", outputs)
        self.assertIn("DATA GOVERNANCE REVIEW REQUIRED", outputs)
        self.assertIn("HUMAN AUTHORITY REQUIRED", outputs)
        self.assertIn("NO-BIND GOVERNANCE REQUIRED", outputs)
        self.assertIn("AUDIT RECONSTRUCTION REQUIRED", outputs)
        self.assertIn("MODEL AND AGENT BOUNDARY REVIEW REQUIRED", outputs)
        self.assertIn("VALIDATION EVIDENCE REQUIRED", outputs)
        self.assertIn("CHANGE CONTROL REQUIRED", outputs)
        self.assertIn("INCIDENT READINESS REQUIRED", outputs)
        self.assertIn("VENDOR EXIT PLAN REQUIRED", outputs)
        self.assertIn("ACTION NOT ADMISSIBLE WITHOUT EVIDENCE", outputs)
        self.assertIn("AI OUTPUT NOT BINDING", outputs)

    def test_minimum_audit_trail_is_locked(self):
        audit_trail = self.passport["minimum_audit_trail"]

        self.assertEqual(len(audit_trail), 16)
        self.assertIn("ai_system_id", audit_trail)
        self.assertIn("vendor_id", audit_trail)
        self.assertIn("use_case_id", audit_trail)
        self.assertIn("workflow_id", audit_trail)
        self.assertIn("source_input_reference", audit_trail)
        self.assertIn("ai_output_reference", audit_trail)
        self.assertIn("human_reviewer_id_or_role", audit_trail)
        self.assertIn("reviewer_qualification_status", audit_trail)
        self.assertIn("review_started_timestamp", audit_trail)
        self.assertIn("review_completed_timestamp", audit_trail)
        self.assertIn("human_edits_reference", audit_trail)
        self.assertIn("approval_or_rejection_status", audit_trail)
        self.assertIn("authority_basis", audit_trail)
        self.assertIn("no_bind_state", audit_trail)
        self.assertIn("evidence_hash", audit_trail)
        self.assertIn("final_record_reference", audit_trail)

    def test_scoring_model_is_preserved(self):
        scoring = self.passport["assurance_scoring_model"]

        self.assertEqual(scoring["passport_score_range"], "0-100")
        self.assertEqual(scoring["minimum_passport_threshold"], 80)
        self.assertIn("ACTION NOT ADMISSIBLE WITHOUT EVIDENCE", scoring["critical_domain_failure_rule"])
        self.assertIn("ASSURANCE READY", scoring["status_levels"])
        self.assertIn("NOT ADMISSIBLE", scoring["status_levels"])

    def test_implementation_status_preserves_no_change_boundaries(self):
        status = self.passport["implementation_status"]

        self.assertEqual(status["platform_b_v1_impact"], "NONE")
        self.assertEqual(status["thread_d_v1_impact"], "NONE")
        self.assertEqual(status["platform_b1_bundle_impact"], "NONE")
        self.assertEqual(status["local_validation_bundle_count_change"], "NONE")
        self.assertEqual(status["azure_deployment_status"], "NOT_DEPLOYED")
        self.assertEqual(status["azure_digital_twins_status"], "NOT_DEPLOYED")
        self.assertEqual(status["mvp3_activation"], "NONE")
        self.assertEqual(status["hardware_integration"], "NONE")
        self.assertEqual(status["production_system_connection"], "NONE")

    def test_boundary_preserves_guardrails(self):
        boundary = " ".join(self.passport["boundary"])

        self.assertIn("Vendor assurance passport registry only", boundary)
        self.assertIn("Local research watch only", boundary)
        self.assertIn("No architecture change", boundary)
        self.assertIn("No Platform B v1 change", boundary)
        self.assertIn("No Thread D v1 change", boundary)
        self.assertIn("No Platform B1 local validation bundle count change", boundary)
        self.assertIn("No Azure deployment", boundary)
        self.assertIn("No Azure Digital Twins deployment", boundary)
        self.assertIn("No real EHR integration", boundary)
        self.assertIn("No PHI", boundary)
        self.assertIn("No company production data", boundary)
        self.assertIn("No clinical decision support claim", boundary)
        self.assertIn("No patient-specific medical decision", boundary)
        self.assertIn("No diagnosis", boundary)
        self.assertIn("No treatment recommendation", boundary)
        self.assertIn("No regulated action execution", boundary)
        self.assertIn("No binding operational consequence", boundary)

    def test_markdown_preserves_core_passport_terms(self):
        required_phrases = [
            "LOCKED AGENTIC AMBIENT AI VENDOR ASSURANCE PASSPORT ONLY",
            "Can this AI-supported vendor system",
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

        for phrase in required_phrases:
            self.assertIn(phrase, self.markdown)


if __name__ == "__main__":
    unittest.main()
