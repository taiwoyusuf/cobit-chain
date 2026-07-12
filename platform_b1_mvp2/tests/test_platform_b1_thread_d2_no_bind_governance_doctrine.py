import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"

REGISTRY_JSON = ROOT / "research_watch" / "platform_b1_thread_d2_no_bind_governance_doctrine.json"
REGISTRY_MD = ROOT / "research_watch" / "PLATFORM_B1_THREAD_D2_NO_BIND_GOVERNANCE_DOCTRINE.md"


class PlatformB1ThreadD2NoBindGovernanceDoctrineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = json.loads(REGISTRY_JSON.read_text(encoding="utf-8-sig"))
        cls.markdown = REGISTRY_MD.read_text(encoding="utf-8-sig")

    def test_registry_identity_is_locked(self):
        self.assertEqual(
            self.registry["registry_name"],
            "Platform B1 / Thread D2 No-Bind Governance Doctrine Registry",
        )
        self.assertEqual(
            self.registry["registry_status"],
            "LOCKED_NO_BIND_GOVERNANCE_DOCTRINE_ONLY",
        )
        self.assertEqual(
            self.registry["registry_type"],
            "LOCAL_RESEARCH_WATCH_DOCTRINE_REGISTRY",
        )

    def test_doctrine_principle_is_preserved(self):
        self.assertIn("No-Bind Governance", self.registry["doctrine_name"])
        self.assertIn("Silence Is Not Consent", self.registry["doctrine_name"])
        self.assertEqual(
            self.registry["doctrine_principle"],
            "Absence of human response must not be treated as authorization.",
        )
        self.assertIn("Silence must create a governed hold", self.registry["master_sentence"])

    def test_platform_relationship_is_preserved(self):
        relationship = " ".join(self.registry["platform_relationship"].values())

        self.assertIn("Capture governance intent", relationship)
        self.assertIn("Evaluate whether evidence, authority, timing, accountability, and admissibility", relationship)
        self.assertIn("Display authority, hold, escalation, and non-admissibility state only", relationship)
        self.assertIn("Display only", relationship)
        self.assertIn("Named authorized person", relationship)

    def test_evaluation_dimensions_are_locked(self):
        dimensions = self.registry["evaluation_dimensions"]

        self.assertEqual(len(dimensions), 11)
        self.assertIn("authority_present", dimensions)
        self.assertIn("authority_valid", dimensions)
        self.assertIn("authority_current", dimensions)
        self.assertIn("authority_delegated", dimensions)
        self.assertIn("approver_available", dimensions)
        self.assertIn("escalation_available", dimensions)
        self.assertIn("pre_authorized_rule_exists", dimensions)
        self.assertIn("evidence_sufficient", dimensions)
        self.assertIn("timing_valid", dimensions)
        self.assertIn("action_consequence_level", dimensions)
        self.assertIn("human_accountability_identified", dimensions)

    def test_required_outputs_are_locked(self):
        outputs = self.registry["required_outputs"]

        self.assertEqual(len(outputs), 10)
        self.assertIn("AUTHORITY ABSENT", outputs)
        self.assertIn("NO-BIND STATE ACTIVE", outputs)
        self.assertIn("ACTION HELD", outputs)
        self.assertIn("ESCALATION REQUIRED", outputs)
        self.assertIn("DOCUMENTED PAUSE CREATED", outputs)
        self.assertIn("HUMAN AUTHORITY REQUIRED", outputs)
        self.assertIn("ACTION NOT ADMISSIBLE", outputs)
        self.assertIn("SILENCE IS NOT CONSENT", outputs)
        self.assertIn("GOVERNED RULE REQUIRED", outputs)
        self.assertIn("AI OUTPUT NOT BINDING", outputs)

    def test_implementation_status_preserves_no_change_boundaries(self):
        status = self.registry["implementation_status"]

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
        boundary = " ".join(self.registry["boundary"])

        self.assertIn("Doctrine registry only", boundary)
        self.assertIn("Local research watch only", boundary)
        self.assertIn("No architecture change", boundary)
        self.assertIn("No Platform B v1 change", boundary)
        self.assertIn("No Thread D v1 change", boundary)
        self.assertIn("No Platform B1 local validation bundle count change", boundary)
        self.assertIn("No MVP3 activation", boundary)
        self.assertIn("No Azure deployment", boundary)
        self.assertIn("No Azure Digital Twins deployment", boundary)
        self.assertIn("No PHI", boundary)
        self.assertIn("No company production data", boundary)
        self.assertIn("No clinical decision support claim", boundary)
        self.assertIn("No patient-specific medical decision", boundary)
        self.assertIn("No regulated action execution", boundary)
        self.assertIn("No binding operational consequence", boundary)

    def test_markdown_preserves_core_doctrine_terms(self):
        required_phrases = [
            "LOCKED NO-BIND GOVERNANCE DOCTRINE ONLY",
            "Absence of human response must not be treated as authorization.",
            "Silence must create a governed hold",
            "The workflow is not trustworthy because no one objected.",
            "authority_present",
            "authority_valid",
            "approver_available",
            "pre_authorized_rule_exists",
            "ACTION NOT ADMISSIBLE",
            "SILENCE IS NOT CONSENT",
            "AI OUTPUT NOT BINDING",
            "No Platform B v1 change",
            "No Thread D v1 change",
            "No Platform B1 local validation bundle count change",
            "No clinical decision support claim",
            "No patient-specific medical decision",
        ]

        for phrase in required_phrases:
            self.assertIn(phrase, self.markdown)


if __name__ == "__main__":
    unittest.main()
