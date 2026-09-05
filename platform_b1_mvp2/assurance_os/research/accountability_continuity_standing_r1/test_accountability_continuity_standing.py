import unittest

from accountability_continuity_standing import (
    CONTRADICTED,
    HANDOFF_NOT_ESTABLISHED,
    NOT_ESTABLISHED,
    SUPPORTABLE,
    evaluate_accountability_continuity,
)


BASE_RESPONSIBILITY = {
    "responsible_party_count": 4,
    "shared_responsibility_declared": True,
    "responsibility_assignment_complete": True,
}

BASE_ACCOUNTABILITY = {
    "declared_scope_id": "AI-WORKFLOW-001:CONSEQUENCE-SCOPE-A",
    "accountable_owner_identified": True,
    "accountable_owner_id": "BUSINESS-OWNER-001",
    "accountable_entity_resolvable": True,
    "accountability_scope_defined": True,
    "accountable_mandate_current": True,
    "accountability_acceptance_current": True,
    "accountability_ambiguity_present": False,
    "orphaned_accountability": False,
    "conflicting_accountability_claims_present": False,
    "material_change_after_accountability_assignment": False,
    "accountability_revalidated_after_latest_material_change": False,
}

BASE_HANDOFF = {
    "handoff_occurred": False,
    "successor_owner_identified": True,
    "successor_owner_id": "BUSINESS-OWNER-001",
    "successor_acceptance_current": True,
    "scope_preserved_across_handoff": True,
    "obligations_preserved_across_handoff": True,
    "transfer_traceable": True,
    "predecessor_scope_disposition_established": True,
}

BASE_EVIDENCE = {
    "accountability_assignment_traceable": True,
    "accountability_acceptance_traceable": True,
    "decision_point_traceable": True,
    "outcome_owner_traceable": True,
    "accountability_evidence_current": True,
    "execution_actor_traceable": True,
}


def evaluate(**overrides):
    responsibility = dict(BASE_RESPONSIBILITY)
    responsibility.update(overrides.pop("responsibility", {}))
    accountability = dict(BASE_ACCOUNTABILITY)
    accountability.update(overrides.pop("accountability", {}))
    handoff = dict(BASE_HANDOFF)
    handoff.update(overrides.pop("handoff", {}))
    evidence = dict(BASE_EVIDENCE)
    evidence.update(overrides.pop("evidence", {}))
    return evaluate_accountability_continuity(
        responsibility_context=responsibility,
        accountability_state=accountability,
        handoff_state=handoff,
        evidence_state=evidence,
    )


class AccountabilityContinuityStandingR1Tests(unittest.TestCase):
    def test_clean_shared_responsibility_with_single_accountable_owner_is_supportable(self):
        r = evaluate()
        self.assertEqual(r["accountability_continuity_standing"], SUPPORTABLE)
        self.assertTrue(r["accountability_basis_supportable"])
        self.assertFalse(r["binding_authority_granted"])
        self.assertTrue(r["separate_authority_evaluation_required"])

    def test_multiple_responsible_parties_do_not_substitute_for_accountable_owner(self):
        r = evaluate(accountability={"accountable_owner_identified": False})
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("ACCOUNTABLE_OWNER_NOT_IDENTIFIED", r["reasons"])

    def test_empty_accountable_owner_identity_fails_closed(self):
        r = evaluate(accountability={"accountable_owner_id": ""})
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("ACCOUNTABILITY_ACCOUNTABLE_OWNER_ID_INVALID", r["reasons"])

    def test_unresolvable_owner_fails_closed(self):
        r = evaluate(accountability={"accountable_entity_resolvable": False})
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("ACCOUNTABLE_ENTITY_NOT_RESOLVABLE", r["reasons"])

    def test_undefined_accountability_scope_fails_closed(self):
        r = evaluate(accountability={"accountability_scope_defined": False})
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("ACCOUNTABILITY_SCOPE_NOT_DEFINED", r["reasons"])

    def test_expired_or_stale_mandate_fails_closed(self):
        r = evaluate(accountability={"accountable_mandate_current": False})
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("ACCOUNTABLE_MANDATE_NOT_CURRENT", r["reasons"])

    def test_unaccepted_accountability_fails_closed(self):
        r = evaluate(accountability={"accountability_acceptance_current": False})
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("ACCOUNTABILITY_ACCEPTANCE_NOT_CURRENT", r["reasons"])

    def test_orphaned_accountability_fails_closed(self):
        r = evaluate(accountability={"orphaned_accountability": True})
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("ACCOUNTABILITY_ORPHANED", r["reasons"])

    def test_ambiguous_accountability_fails_closed(self):
        r = evaluate(accountability={"accountability_ambiguity_present": True})
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("ACCOUNTABILITY_AMBIGUITY_PRESENT", r["reasons"])

    def test_conflicting_accountability_claims_are_preserved_as_contradiction(self):
        r = evaluate(accountability={"conflicting_accountability_claims_present": True})
        self.assertEqual(r["accountability_continuity_standing"], CONTRADICTED)
        self.assertIn("CONFLICTING_ACCOUNTABILITY_CLAIMS_PRESENT", r["reasons"])

    def test_material_change_requires_accountability_revalidation(self):
        r = evaluate(accountability={
            "material_change_after_accountability_assignment": True,
            "accountability_revalidated_after_latest_material_change": False,
        })
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("ACCOUNTABILITY_BASIS_STALE_AFTER_MATERIAL_CHANGE", r["reasons"])

    def test_revalidation_after_material_change_restores_temporal_prerequisite(self):
        r = evaluate(accountability={
            "material_change_after_accountability_assignment": True,
            "accountability_revalidated_after_latest_material_change": True,
        })
        self.assertEqual(r["accountability_continuity_standing"], SUPPORTABLE)

    def test_handoff_requires_identified_successor(self):
        r = evaluate(handoff={
            "handoff_occurred": True,
            "successor_owner_identified": False,
        })
        self.assertEqual(r["accountability_continuity_standing"], HANDOFF_NOT_ESTABLISHED)
        self.assertIn("HANDOFF_SUCCESSOR_NOT_IDENTIFIED", r["reasons"])

    def test_handoff_requires_successor_acceptance(self):
        r = evaluate(handoff={
            "handoff_occurred": True,
            "successor_acceptance_current": False,
        })
        self.assertEqual(r["accountability_continuity_standing"], HANDOFF_NOT_ESTABLISHED)
        self.assertIn("HANDOFF_SUCCESSOR_ACCEPTANCE_NOT_CURRENT", r["reasons"])

    def test_handoff_requires_scope_preservation(self):
        r = evaluate(handoff={
            "handoff_occurred": True,
            "scope_preserved_across_handoff": False,
        })
        self.assertEqual(r["accountability_continuity_standing"], HANDOFF_NOT_ESTABLISHED)
        self.assertIn("HANDOFF_SCOPE_NOT_PRESERVED", r["reasons"])

    def test_handoff_requires_obligation_preservation(self):
        r = evaluate(handoff={
            "handoff_occurred": True,
            "obligations_preserved_across_handoff": False,
        })
        self.assertEqual(r["accountability_continuity_standing"], HANDOFF_NOT_ESTABLISHED)
        self.assertIn("HANDOFF_OBLIGATIONS_NOT_PRESERVED", r["reasons"])

    def test_handoff_requires_traceable_transfer(self):
        r = evaluate(handoff={
            "handoff_occurred": True,
            "transfer_traceable": False,
        })
        self.assertEqual(r["accountability_continuity_standing"], HANDOFF_NOT_ESTABLISHED)
        self.assertIn("HANDOFF_TRANSFER_NOT_TRACEABLE", r["reasons"])

    def test_handoff_requires_predecessor_scope_disposition(self):
        r = evaluate(handoff={
            "handoff_occurred": True,
            "predecessor_scope_disposition_established": False,
        })
        self.assertEqual(r["accountability_continuity_standing"], HANDOFF_NOT_ESTABLISHED)
        self.assertIn("HANDOFF_PREDECESSOR_SCOPE_DISPOSITION_NOT_ESTABLISHED", r["reasons"])

    def test_current_owner_must_match_handoff_successor(self):
        r = evaluate(handoff={
            "handoff_occurred": True,
            "successor_owner_id": "BUSINESS-OWNER-002",
        })
        self.assertEqual(r["accountability_continuity_standing"], HANDOFF_NOT_ESTABLISHED)
        self.assertIn("CURRENT_ACCOUNTABLE_OWNER_DOES_NOT_MATCH_HANDOFF_SUCCESSOR", r["reasons"])

    def test_valid_handoff_to_new_owner_is_supportable(self):
        r = evaluate(
            accountability={"accountable_owner_id": "BUSINESS-OWNER-002"},
            handoff={
                "handoff_occurred": True,
                "successor_owner_id": "BUSINESS-OWNER-002",
            },
        )
        self.assertEqual(r["accountability_continuity_standing"], SUPPORTABLE)

    def test_execution_traceability_does_not_substitute_for_accountability_traceability(self):
        r = evaluate(evidence={
            "execution_actor_traceable": True,
            "outcome_owner_traceable": False,
        })
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("ACCOUNTABLE_OUTCOME_OWNER_NOT_TRACEABLE", r["reasons"])

    def test_accountability_assignment_must_be_traceable(self):
        r = evaluate(evidence={"accountability_assignment_traceable": False})
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("ACCOUNTABILITY_ASSIGNMENT_NOT_TRACEABLE", r["reasons"])

    def test_accountability_acceptance_must_be_traceable(self):
        r = evaluate(evidence={"accountability_acceptance_traceable": False})
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("ACCOUNTABILITY_ACCEPTANCE_NOT_TRACEABLE", r["reasons"])

    def test_decision_point_must_be_traceable(self):
        r = evaluate(evidence={"decision_point_traceable": False})
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("ACCOUNTABILITY_DECISION_POINT_NOT_TRACEABLE", r["reasons"])

    def test_accountability_evidence_must_be_current(self):
        r = evaluate(evidence={"accountability_evidence_current": False})
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("ACCOUNTABILITY_EVIDENCE_NOT_CURRENT", r["reasons"])

    def test_incomplete_responsibility_assignment_does_not_become_accountability_failure(self):
        r = evaluate(responsibility={"responsibility_assignment_complete": False})
        self.assertEqual(r["accountability_continuity_standing"], SUPPORTABLE)
        self.assertFalse(r["responsibility_assignment_complete"])
        self.assertFalse(r["responsibility_treated_as_accountability"])

    def test_supportable_accountability_never_grants_authority(self):
        r = evaluate()
        self.assertFalse(r["binding_authority_granted"])
        self.assertFalse(r["physical_action_executed_by_evaluator"])
        self.assertFalse(r["regulated_release_or_disposition_authorized"])
        self.assertEqual(r["no_bind_state"], "SEPARATE_AUTHORITY_AND_ACTION_ADMISSIBILITY_REQUIRED")

    def test_blocked_accountability_never_grants_authority(self):
        r = evaluate(accountability={"orphaned_accountability": True})
        self.assertFalse(r["binding_authority_granted"])
        self.assertTrue(r["action_hold_required_on_accountability_basis"])
        self.assertEqual(r["no_bind_state"], "ACTIVE")

    def test_missing_input_mapping_fails_closed(self):
        r = evaluate_accountability_continuity(
            responsibility_context=dict(BASE_RESPONSIBILITY),
            accountability_state=dict(BASE_ACCOUNTABILITY),
            handoff_state=None,
            evidence_state=dict(BASE_EVIDENCE),
        )
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("REQUIRED_INPUT_MAPPING_MISSING", r["reasons"])


if __name__ == "__main__":
    unittest.main()
