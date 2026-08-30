import unittest
from datetime import datetime, timedelta, timezone

from publication_semantic_refinements import (
    evaluate_source_to_artifact_correspondence,
    evaluate_test_semantic_correspondence,
    evaluate_claim_strength_ceiling,
    evaluate_normative_completeness,
    classify_control_failure,
    evaluate_agency_justification,
    evaluate_registry_resolution_standing,
    evaluate_instance_bound_sufficiency,
    evaluate_physical_digital_temporal_correspondence,
    evaluate_institutional_independence,
)


class PublicationSemanticRefinementsTests(unittest.TestCase):
    def test_artifact_digest_does_not_prove_source_correspondence(self):
        r = evaluate_source_to_artifact_correspondence(
            source_digest_bound=True, build_process_identified=True, build_reproducible=False, artifact_digest_verified=True
        )
        self.assertEqual(r["source_to_artifact_correspondence"], "NOT_ESTABLISHED")
        self.assertEqual(r["artifact_integrity_standing"], "SUPPORTABLE")

    def test_test_name_does_not_prove_exercised_property(self):
        r = evaluate_test_semantic_correspondence(
            test_label="physical-drift", exercised_property="simulated-drift", claimed_property="physical-drift", real_world_property_observed=False
        )
        self.assertEqual(r["test_semantic_correspondence"], "NOT_ESTABLISHED")

    def test_finite_successes_do_not_authorize_universal_claim(self):
        r = evaluate_claim_strength_ceiling(
            observation_count=100, independent_repetitions=100, universal_counterexample_found=False, requested_claim_class="UNIVERSAL_CLAIM"
        )
        self.assertFalse(r["requested_claim_permitted"])
        self.assertEqual(r["claim_strength_ceiling"], "REPEATED_OBSERVATION")

    def test_factually_correct_instruction_can_be_normatively_incomplete(self):
        r = evaluate_normative_completeness(
            factual_statements_correct=True, required_normative_elements=["independent-review", "hold-point"], included_normative_elements=["hold-point"]
        )
        self.assertEqual(r["normative_completeness_standing"], "NOT_ESTABLISHED")

    def test_control_can_fail_by_specification_not_enforcement(self):
        r = classify_control_failure(
            control_executed_as_designed=True, control_present_and_enforceable=True, specified_control_sufficient=False
        )
        self.assertEqual(r["control_failure_cause_class"], "SPECIFICATION_FAILURE")

    def test_agentic_autonomy_requires_design_time_justification(self):
        r = evaluate_agency_justification(
            deterministic_alternative_assessed=False, autonomy_necessary_for_purpose=True,
            maximum_delegation_class="HUMAN_APPROVAL_REQUIRED", requested_delegation_class="BOUNDED_AUTONOMOUS"
        )
        self.assertEqual(r["agency_justification_standing"], "NOT_ESTABLISHED")

    def test_registry_identifier_does_not_equal_public_resolution_or_verification(self):
        r = evaluate_registry_resolution_standing(
            identifier_assigned=True, publicly_resolvable=False, evidence_available=False, implementation_verified=False
        )
        self.assertEqual(r["identifier_state"], "ASSIGNED")
        self.assertEqual(r["implementation_verification_state"], "NOT_ESTABLISHED")

    def test_system_standing_does_not_establish_instance_standing(self):
        r = evaluate_instance_bound_sufficiency(
            system_standing_supportable=True, instance_evidence_supportable=False, acceptance_basis_frozen_before_result=True
        )
        self.assertEqual(r["instance_assurance_standing"], "NOT_ESTABLISHED")

    def test_synchronized_clocks_can_still_fail_physical_digital_correspondence(self):
        t0 = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
        r = evaluate_physical_digital_temporal_correspondence(
            clocks_synchronized=True, physical_event_time=t0, digital_event_time=t0 + timedelta(seconds=5), maximum_correspondence_error_seconds=1
        )
        self.assertEqual(r["physical_digital_temporal_correspondence"], "NOT_ESTABLISHED")

    def test_role_concentration_must_be_disclosed_for_independence_claim(self):
        r = evaluate_institutional_independence(
            evidence_custodian="ORG-A", interpreter="ORG-A", decision_authority="ORG-B", executor="ORG-C",
            outcome_verifier="ORG-D", declared_conflicts=[]
        )
        self.assertEqual(r["institutional_independence_standing"], "NOT_ESTABLISHED")


if __name__ == "__main__":
    unittest.main()
