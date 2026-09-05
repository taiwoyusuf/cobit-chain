import unittest

from accountability_continuity_standing import (
    CONTRADICTED,
    HANDOFF_NOT_ESTABLISHED,
    NOT_ESTABLISHED,
    SUPPORTABLE,
    enforce_accountability_prerequisite,
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

VALID_AUTHORITY = {"authority_valid": True, "no_bind_state": "INACTIVE"}
INVALID_AUTHORITY = {"authority_valid": False, "no_bind_state": "ACTIVE"}


def evaluate(*, responsibility=None, accountability=None, handoff=None, evidence=None):
    r = dict(BASE_RESPONSIBILITY)
    if responsibility:
        r.update(responsibility)
    a = dict(BASE_ACCOUNTABILITY)
    if accountability:
        a.update(accountability)
    h = dict(BASE_HANDOFF)
    if handoff:
        h.update(handoff)
    e = dict(BASE_EVIDENCE)
    if evidence:
        e.update(evidence)
    return evaluate_accountability_continuity(
        responsibility_context=r,
        accountability_state=a,
        handoff_state=h,
        evidence_state=e,
    )


class Step185CandidateStandingTests(unittest.TestCase):
    def test_clean_state_supportable(self):
        r = evaluate()
        self.assertEqual(r["candidate_revision"], "STEP_185_R1")
        self.assertEqual(r["accountability_continuity_standing"], SUPPORTABLE)
        self.assertTrue(r["accountability_basis_supportable"])
        self.assertEqual(r["no_bind_state"], "SEPARATE_AUTHORITY_AND_ACTION_ADMISSIBILITY_REQUIRED")

    def test_supportable_never_grants_authority_or_action(self):
        r = evaluate()
        self.assertFalse(r["binding_authority_granted"])
        self.assertFalse(r["physical_action_executed_by_evaluator"])
        self.assertFalse(r["regulated_release_or_disposition_authorized"])
        self.assertTrue(r["separate_authority_evaluation_required"])

    def test_step_number_does_not_assert_semantic_order(self):
        r = evaluate()
        self.assertFalse(r["semantic_lifecycle_order_asserted_by_step_number"])

    def test_many_responsible_parties_do_not_substitute_for_accountable_owner(self):
        r = evaluate(accountability={"accountable_owner_identified": False})
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("ACCOUNTABLE_OWNER_NOT_IDENTIFIED", r["reasons"])

    def test_missing_responsibility_metadata_does_not_defeat_accountability(self):
        r = evaluate_accountability_continuity(
            responsibility_context={},
            accountability_state=dict(BASE_ACCOUNTABILITY),
            handoff_state=dict(BASE_HANDOFF),
            evidence_state=dict(BASE_EVIDENCE),
        )
        self.assertEqual(r["accountability_continuity_standing"], SUPPORTABLE)
        self.assertIsNone(r["responsible_party_count"])

    def test_incomplete_raci_context_does_not_become_accountability_failure(self):
        r = evaluate(responsibility={"responsibility_assignment_complete": False})
        self.assertEqual(r["accountability_continuity_standing"], SUPPORTABLE)
        self.assertFalse(r["responsibility_assignment_complete"])
        self.assertFalse(r["responsibility_treated_as_accountability"])

    def test_missing_owner_identity_fails_closed(self):
        r = evaluate(accountability={"accountable_owner_id": ""})
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("ACCOUNTABILITY_ACCOUNTABLE_OWNER_ID_INVALID", r["reasons"])

    def test_unresolvable_owner_fails_closed(self):
        r = evaluate(accountability={"accountable_entity_resolvable": False})
        self.assertIn("ACCOUNTABLE_ENTITY_NOT_RESOLVABLE", r["reasons"])
        self.assertEqual(r["no_bind_state"], "ACTIVE")

    def test_scope_must_be_defined(self):
        r = evaluate(accountability={"accountability_scope_defined": False})
        self.assertIn("ACCOUNTABILITY_SCOPE_NOT_DEFINED", r["reasons"])

    def test_stale_mandate_fails_closed(self):
        r = evaluate(accountability={"accountable_mandate_current": False})
        self.assertIn("ACCOUNTABLE_MANDATE_NOT_CURRENT", r["reasons"])

    def test_unaccepted_accountability_fails_closed(self):
        r = evaluate(accountability={"accountability_acceptance_current": False})
        self.assertIn("ACCOUNTABILITY_ACCEPTANCE_NOT_CURRENT", r["reasons"])

    def test_orphaned_accountability_fails_closed(self):
        r = evaluate(accountability={"orphaned_accountability": True})
        self.assertIn("ACCOUNTABILITY_ORPHANED", r["reasons"])
        self.assertTrue(r["action_hold_required_on_accountability_basis"])

    def test_ambiguity_fails_closed(self):
        r = evaluate(accountability={"accountability_ambiguity_present": True})
        self.assertIn("ACCOUNTABILITY_AMBIGUITY_PRESENT", r["reasons"])

    def test_conflicting_claims_preserved_as_contradiction(self):
        r = evaluate(accountability={"conflicting_accountability_claims_present": True})
        self.assertEqual(r["accountability_continuity_standing"], CONTRADICTED)
        self.assertIn("CONFLICTING_ACCOUNTABILITY_CLAIMS_PRESENT", r["reasons"])

    def test_material_change_requires_accountability_revalidation(self):
        r = evaluate(accountability={
            "material_change_after_accountability_assignment": True,
            "accountability_revalidated_after_latest_material_change": False,
        })
        self.assertIn("ACCOUNTABILITY_BASIS_STALE_AFTER_MATERIAL_CHANGE", r["reasons"])

    def test_material_change_revalidation_restores_prerequisite(self):
        r = evaluate(accountability={
            "material_change_after_accountability_assignment": True,
            "accountability_revalidated_after_latest_material_change": True,
        })
        self.assertEqual(r["accountability_continuity_standing"], SUPPORTABLE)

    def test_accountability_assignment_must_be_traceable(self):
        r = evaluate(evidence={"accountability_assignment_traceable": False})
        self.assertIn("ACCOUNTABILITY_ASSIGNMENT_NOT_TRACEABLE", r["reasons"])

    def test_accountability_acceptance_must_be_traceable(self):
        r = evaluate(evidence={"accountability_acceptance_traceable": False})
        self.assertIn("ACCOUNTABILITY_ACCEPTANCE_NOT_TRACEABLE", r["reasons"])

    def test_decision_point_must_be_traceable(self):
        r = evaluate(evidence={"decision_point_traceable": False})
        self.assertIn("ACCOUNTABILITY_DECISION_POINT_NOT_TRACEABLE", r["reasons"])

    def test_outcome_owner_must_be_traceable(self):
        r = evaluate(evidence={"outcome_owner_traceable": False})
        self.assertIn("ACCOUNTABLE_OUTCOME_OWNER_NOT_TRACEABLE", r["reasons"])

    def test_accountability_evidence_must_be_current(self):
        r = evaluate(evidence={"accountability_evidence_current": False})
        self.assertIn("ACCOUNTABILITY_EVIDENCE_NOT_CURRENT", r["reasons"])

    def test_execution_actor_traceability_is_context_only(self):
        r = evaluate(evidence={"execution_actor_traceable": False})
        self.assertEqual(r["accountability_continuity_standing"], SUPPORTABLE)
        self.assertFalse(r["execution_actor_traceable"])

    def test_handoff_requires_identified_successor(self):
        r = evaluate(handoff={"handoff_occurred": True, "successor_owner_identified": False})
        self.assertEqual(r["accountability_continuity_standing"], HANDOFF_NOT_ESTABLISHED)
        self.assertIn("HANDOFF_SUCCESSOR_NOT_IDENTIFIED", r["reasons"])

    def test_handoff_requires_successor_acceptance(self):
        r = evaluate(handoff={"handoff_occurred": True, "successor_acceptance_current": False})
        self.assertIn("HANDOFF_SUCCESSOR_ACCEPTANCE_NOT_CURRENT", r["reasons"])

    def test_handoff_requires_scope_preservation(self):
        r = evaluate(handoff={"handoff_occurred": True, "scope_preserved_across_handoff": False})
        self.assertIn("HANDOFF_SCOPE_NOT_PRESERVED", r["reasons"])

    def test_handoff_requires_obligation_preservation(self):
        r = evaluate(handoff={"handoff_occurred": True, "obligations_preserved_across_handoff": False})
        self.assertIn("HANDOFF_OBLIGATIONS_NOT_PRESERVED", r["reasons"])

    def test_handoff_requires_traceable_transfer(self):
        r = evaluate(handoff={"handoff_occurred": True, "transfer_traceable": False})
        self.assertIn("HANDOFF_TRANSFER_NOT_TRACEABLE", r["reasons"])

    def test_handoff_requires_predecessor_scope_disposition(self):
        r = evaluate(handoff={"handoff_occurred": True, "predecessor_scope_disposition_established": False})
        self.assertIn("HANDOFF_PREDECESSOR_SCOPE_DISPOSITION_NOT_ESTABLISHED", r["reasons"])

    def test_handoff_successor_must_match_current_owner(self):
        r = evaluate(handoff={"handoff_occurred": True, "successor_owner_id": "BUSINESS-OWNER-002"})
        self.assertIn("CURRENT_ACCOUNTABLE_OWNER_DOES_NOT_MATCH_HANDOFF_SUCCESSOR", r["reasons"])

    def test_valid_handoff_to_new_owner_supportable(self):
        r = evaluate(
            accountability={"accountable_owner_id": "BUSINESS-OWNER-002"},
            handoff={"handoff_occurred": True, "successor_owner_id": "BUSINESS-OWNER-002"},
        )
        self.assertEqual(r["accountability_continuity_standing"], SUPPORTABLE)

    def test_missing_required_mapping_fails_closed(self):
        r = evaluate_accountability_continuity(
            responsibility_context={},
            accountability_state=dict(BASE_ACCOUNTABILITY),
            handoff_state=None,
            evidence_state=dict(BASE_EVIDENCE),
        )
        self.assertEqual(r["accountability_continuity_standing"], NOT_ESTABLISHED)
        self.assertIn("REQUIRED_INPUT_MAPPING_MISSING", r["reasons"])


class Step185CandidateCompositionTests(unittest.TestCase):
    def test_valid_authority_cannot_override_failed_accountability(self):
        accountability = evaluate(accountability={"orphaned_accountability": True})
        r = enforce_accountability_prerequisite(
            accountability_result=accountability,
            authority_result=VALID_AUTHORITY,
            caller_requested_decision="ADMISSIBLE",
        )
        self.assertEqual(r["composition_decision"], "NOT_ADMISSIBLE")
        self.assertTrue(r["caller_override_rejected"])
        self.assertIn("ACCOUNTABILITY_CONTINUITY_NOT_SUPPORTABLE", r["reasons"])

    def test_supportable_accountability_cannot_override_invalid_authority(self):
        r = enforce_accountability_prerequisite(
            accountability_result=evaluate(),
            authority_result=INVALID_AUTHORITY,
            caller_requested_decision="ADMISSIBLE",
        )
        self.assertEqual(r["composition_decision"], "NOT_ADMISSIBLE")
        self.assertIn("SEPARATE_AUTHORITY_STANDING_NOT_SUPPORTABLE", r["reasons"])

    def test_both_prerequisites_supportable_still_require_action_admissibility(self):
        r = enforce_accountability_prerequisite(
            accountability_result=evaluate(),
            authority_result=VALID_AUTHORITY,
            caller_requested_decision="ADMISSIBLE",
        )
        self.assertEqual(r["composition_decision"], "ACCOUNTABILITY_AND_AUTHORITY_PREREQUISITES_SUPPORTABLE")
        self.assertEqual(r["no_bind_state"], "SEPARATE_ACTION_ADMISSIBILITY_REQUIRED")
        self.assertFalse(r["action_admissibility_granted"])
        self.assertFalse(r["binding_authority_granted"])

    def test_missing_accountability_result_fails_closed(self):
        r = enforce_accountability_prerequisite(
            accountability_result={},
            authority_result=VALID_AUTHORITY,
            caller_requested_decision="ADMISSIBLE",
        )
        self.assertEqual(r["composition_decision"], "NOT_ADMISSIBLE")
        self.assertIn("ACCOUNTABILITY_CONTINUITY_NOT_SUPPORTABLE", r["reasons"])

    def test_missing_authority_result_fails_closed(self):
        r = enforce_accountability_prerequisite(
            accountability_result=evaluate(),
            authority_result={},
            caller_requested_decision="ADMISSIBLE",
        )
        self.assertEqual(r["composition_decision"], "NOT_ADMISSIBLE")
        self.assertIn("SEPARATE_AUTHORITY_STANDING_NOT_SUPPORTABLE", r["reasons"])

    def test_composition_never_executes_or_changes_irlt(self):
        r = enforce_accountability_prerequisite(
            accountability_result=evaluate(),
            authority_result=VALID_AUTHORITY,
            caller_requested_decision="ADMISSIBLE",
        )
        self.assertFalse(r["binding_authority_granted"])
        self.assertFalse(r["action_admissibility_granted"])
        self.assertFalse(r["physical_action_executed"])
        self.assertFalse(r["irlt_mag_state_changed"])


if __name__ == "__main__":
    unittest.main()
