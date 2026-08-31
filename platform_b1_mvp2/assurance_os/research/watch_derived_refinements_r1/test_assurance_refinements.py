import unittest
from datetime import datetime, timedelta, timezone

from assurance_refinements import (
    evaluate_assessor_independence,
    evaluate_claim_identity_and_discharge,
    evaluate_document_parse_fidelity,
    evaluate_governed_interoperability_seam,
    evaluate_human_oversight_queue_standing,
    evaluate_independent_evidence_plane,
    evaluate_non_compensatory_standing,
    evaluate_recovery_path_noninterference,
    evaluate_residual_obligation_liveness,
    evaluate_retrospective_reliance_exposure,
    evaluate_revocation_propagation,
    evaluate_shared_condition_exposure,
    evaluate_tool_sequence_information_flow,
)


class WatchDerivedAssuranceRefinementsTests(unittest.TestCase):
    def test_critical_gate_cannot_be_averaged_away(self):
        r = evaluate_non_compensatory_standing(
            mandatory_gates={"authority": False, "evidence": True}, aggregate_score=0.96
        )
        self.assertEqual(r["assurance_standing"], "NOT_ESTABLISHED")
        self.assertEqual(r["required_behavior"], "HOLD")

    def test_queue_throughput_does_not_replace_meaningful_review(self):
        r = evaluate_human_oversight_queue_standing(
            queue_precision=0.1,
            review_capacity=1000,
            incoming_cases=100,
            required_review_seconds=30,
            available_attention_seconds=5000,
        )
        self.assertEqual(r["human_oversight_standing"], "NOT_ESTABLISHED")

    def test_supported_claim_cannot_discharge_other_claims(self):
        r = evaluate_claim_identity_and_discharge(
            required_claims=["A", "B"], supported_claims=["A"], discharged_claims=["A", "B"]
        )
        self.assertEqual(r["claim_discharge_standing"], "NOT_ESTABLISHED")
        self.assertEqual(r["unsupported_discharges"], ["B"])

    def test_system_log_is_not_independent_evidence(self):
        r = evaluate_independent_evidence_plane(
            record_authentic=True,
            witness_independent=False,
            evidence_plane_available=True,
            act_to_evidence_bound=True,
        )
        self.assertEqual(r["independent_evidence_plane_standing"], "NOT_ESTABLISHED")

    def test_safety_layer_must_not_block_authorized_containment(self):
        r = evaluate_recovery_path_noninterference(
            harmful_path_allowed=True,
            containment_authorized=True,
            containment_blocked_by_safety_control=True,
        )
        self.assertTrue(r["recovery_path_interference"])
        self.assertEqual(r["required_behavior"], "ESCALATE_OR_ISOLATE")

    def test_solution_shaping_qualifies_independence(self):
        r = evaluate_assessor_independence(
            method_guidance_given=True,
            solution_shaping_performed=True,
            secondary_independent_review=False,
        )
        self.assertEqual(r["assessor_independence_standing"], "QUALIFIED_NOT_INDEPENDENT")

    def test_parent_revocation_reaches_child_before_commit(self):
        t0 = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
        r = evaluate_revocation_propagation(
            parent_scope=["read", "write"],
            child_scope=["read"],
            parent_revoked_at=t0,
            enforcement_at=t0 + timedelta(seconds=2),
            attempted_commit_at=t0 + timedelta(seconds=5),
        )
        self.assertFalse(r["derived_authority_current"])
        self.assertTrue(r["enforced_before_commit"])

    def test_custody_transfer_does_not_reset_due_date(self):
        due = datetime(2026, 8, 28, tzinfo=timezone.utc)
        now = datetime(2026, 8, 29, tzinfo=timezone.utc)
        r = evaluate_residual_obligation_liveness(
            duty_accepted=True,
            duty_completed=False,
            due_at=due,
            now=now,
            custody_transferred=True,
        )
        self.assertEqual(r["residual_obligation_standing"], "OPEN_OVERDUE_ESCALATE")
        self.assertTrue(r["overdue"])

    def test_connected_endpoints_do_not_establish_interface_standing(self):
        r = evaluate_governed_interoperability_seam(
            endpoint_a_supportable=True,
            endpoint_b_supportable=True,
            interface_version_bound=False,
            mapping_version_bound=True,
            evidence_provenance_preserved=True,
            authority_transfer_explicitly_prohibited=True,
        )
        self.assertEqual(r["interface_standing"], "NOT_ESTABLISHED")
        self.assertFalse(r["authority_inherited"])

    def test_changed_proposition_exposes_history_without_retroactive_invalidation(self):
        r = evaluate_retrospective_reliance_exposure(
            changed_proposition="P3",
            historical_dependencies={"D1": ["P1", "P3"], "D2": ["P2"]},
        )
        self.assertEqual(r["exposed_historical_decisions"], ["D1"])
        self.assertFalse(r["historical_decisions_automatically_invalidated"])

    def test_common_condition_change_requires_scoped_reassessment(self):
        r = evaluate_shared_condition_exposure(
            condition_changed=True,
            potentially_exposed_routes=["R1", "R2", "R3"],
            explicitly_cleared_routes=["R1"],
        )
        self.assertEqual(r["routes_requiring_reassessment"], ["R2", "R3"])
        self.assertFalse(r["all_dependents_failed"])

    def test_parse_fidelity_fails_when_revision_context_is_lost(self):
        r = evaluate_document_parse_fidelity(
            source_hash_bound=True,
            page_region_grounded=True,
            table_structure_preserved=True,
            revision_context_preserved=False,
            reading_order_preserved=True,
            unknown_missing=False,
        )
        self.assertEqual(r["document_parse_fidelity_standing"], "NOT_ESTABLISHED")

    def test_authorized_tools_can_form_prohibited_sequence(self):
        r = evaluate_tool_sequence_information_flow(
            individual_tools_authorized=True,
            sequence_permitted=False,
            information_flow_permitted=False,
        )
        self.assertEqual(r["tool_sequence_information_flow_standing"], "NOT_ESTABLISHED")
        self.assertEqual(r["required_behavior"], "HOLD_OR_NO_BIND")


if __name__ == "__main__":
    unittest.main()
