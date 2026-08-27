import unittest

from boundary_assurance import (
    evaluate_assurance_control_capacity,
    preserve_epistemic_class,
    create_boundary_assurance_capsule,
    evaluate_recovery_standing,
    evaluate_processing_authority,
    evaluate_disposition_standing,
)


class BoundaryAssuranceTests(unittest.TestCase):
    def test_capacity_failure_holds_high_consequence_work(self):
        result = evaluate_assurance_control_capacity(
            peak_demand=100,
            available_capacity=50,
            queue_delay_ms=3000,
            enforcement_deadline_ms=1000,
            retry_amplification=1.5,
        )
        self.assertEqual(result["control_capacity_standing"], "NOT_ESTABLISHED")
        self.assertEqual(result["required_behavior"], "HOLD_HIGH_CONSEQUENCE")
        self.assertTrue(result["fail_closed"])

    def test_capacity_support_requires_capacity_and_deadline(self):
        result = evaluate_assurance_control_capacity(
            peak_demand=20,
            available_capacity=25,
            queue_delay_ms=50,
            enforcement_deadline_ms=100,
        )
        self.assertEqual(result["control_capacity_standing"], "SUPPORTABLE")

    def test_inferred_cannot_silently_become_measured(self):
        result = preserve_epistemic_class(
            source_class="INFERRED",
            claimed_class="MEASURED",
            transformation_documented=False,
        )
        self.assertEqual(result["standing"], "NOT_ESTABLISHED")
        self.assertTrue(result["fail_closed"])

    def test_independent_verification_may_create_verified_state(self):
        result = preserve_epistemic_class(
            source_class="MEASURED",
            claimed_class="VERIFIED",
            transformation_documented=True,
            independent_verification=True,
        )
        self.assertEqual(result["standing"], "SUPPORTABLE")

    def test_boundary_capsule_refuses_object_substitution(self):
        result = create_boundary_assurance_capsule(
            action_id="A-1",
            object_hash="sha256:evaluated",
            criteria_version="C-7",
            evidence_refs=["E-1"],
            authority_snapshot="AUTH-1",
            standing="SUPPORTABLE",
            unresolved_conditions=[],
            determination="ALLOW",
            committed_object_hash="sha256:different",
        )
        self.assertEqual(result["capsule_state"], "NO_BIND")
        self.assertTrue(result["fail_closed"])

    def test_complete_capsule_can_be_supportable(self):
        result = create_boundary_assurance_capsule(
            action_id="A-2",
            object_hash="sha256:object",
            criteria_version="C-7",
            evidence_refs=["E-1", "E-2"],
            authority_snapshot="AUTH-2",
            standing="SUPPORTABLE",
            unresolved_conditions=[],
            determination="ALLOW",
            committed_object_hash="sha256:object",
        )
        self.assertEqual(result["capsule_state"], "SUPPORTABLE")

    def test_database_rollback_does_not_erase_escaped_consequence(self):
        result = evaluate_recovery_standing(
            execution_stopped=True,
            internal_state_reversed=True,
            escaped_consequence=True,
            downstream_reliance_known=False,
            remediation_complete=False,
        )
        self.assertEqual(result["recovery_standing"], "PARTIAL")

    def test_recovery_requires_required_remediation(self):
        result = evaluate_recovery_standing(
            execution_stopped=True,
            internal_state_reversed=True,
            escaped_consequence=True,
            downstream_reliance_known=True,
            remediation_complete=True,
        )
        self.assertEqual(result["recovery_standing"], "RECOVERED_WITHIN_DECLARED_SCOPE")

    def test_human_access_does_not_authorize_ai_processing(self):
        result = evaluate_processing_authority(
            human_access_authorized=True,
            machine_processing_authorized=False,
            purpose_authorized=False,
            destination_authorized=False,
            retention_authorized=False,
        )
        self.assertEqual(result["processing_authority_standing"], "NO_BIND")
        self.assertTrue(result["fail_closed"])

    def test_processing_authority_requires_purpose_destination_and_retention(self):
        result = evaluate_processing_authority(
            human_access_authorized=True,
            machine_processing_authorized=True,
            purpose_authorized=True,
            destination_authorized=True,
            retention_authorized=True,
        )
        self.assertEqual(result["processing_authority_standing"], "SUPPORTABLE")

    def test_detection_without_disposition_is_not_established(self):
        result = evaluate_disposition_standing(
            condition_detected=True,
            owner_resolved=False,
            deadline_defined=False,
            interim_posture_defined=False,
            escalation_defined=False,
            closure_evidence_present=False,
        )
        self.assertEqual(result["disposition_standing"], "NOT_ESTABLISHED")
        self.assertTrue(result["fail_closed"])

    def test_open_condition_remains_governed_until_closure_evidence(self):
        result = evaluate_disposition_standing(
            condition_detected=True,
            owner_resolved=True,
            deadline_defined=True,
            interim_posture_defined=True,
            escalation_defined=True,
            closure_evidence_present=False,
        )
        self.assertEqual(result["disposition_standing"], "OPEN_GOVERNED_CONDITION")
        self.assertTrue(result["fail_closed"])


if __name__ == "__main__":
    unittest.main()
