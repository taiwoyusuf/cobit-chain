import unittest

from accountability_commit_time_revalidation import (
    NOT_ESTABLISHED,
    SUPPORTABLE,
    STEP180_EVALUATOR_BLOB,
    STEP180_TEST_BLOB,
    STEP186_EVALUATOR_BLOB,
    STEP186_TEST_BLOB,
    canonical_payload_digest,
    evaluate_accountability_commit_time_revalidation,
)

SCOPE = "AI-WORKFLOW-001:CONSEQUENCE-SCOPE-A"
ACTION = "ACTION-001"
OBJECT = "sha256:object-001"

STEP186 = {
    "integration_revision": "STEP_186_R1",
    "integration_standing": "ACCOUNTABILITY_BOUNDARY_INTEGRATION_SUPPORTABLE",
    "integration_decision": "ACCOUNTABILITY_BOUNDARY_PREREQUISITES_SUPPORTABLE",
    "no_bind_state": "SEPARATE_EXECUTION_TIME_REVALIDATION_REQUIRED",
    "action_held": False,
    "expected_scope_id": SCOPE,
    "expected_action_id": ACTION,
    "expected_object_hash": OBJECT,
    "reasons": [],
    "step_185_result_consumed": True,
    "step_179_result_consumed": True,
    "scope_action_object_binding_checked": True,
    "payload_digest_binding_checked": True,
    "binding_temporal_currentness_checked": True,
    "binding_provenance_manufactured": False,
    "binding_authority_granted": False,
    "action_admissibility_granted": False,
    "execution_authorized": False,
    "physical_action_executed": False,
    "historical_facts_rewritten": False,
    "irlt_mag_state_changed": False,
    "separate_execution_time_revalidation_required": True,
}

STEP180 = {
    "execution_time_standing": "SUPPORTABLE",
    "execution_time_decision": "ADMISSIBLE",
    "no_bind_state": "INACTIVE",
    "action_held": False,
    "escalation_required": False,
    "changed_dimensions": [],
    "immaterial_changes": [],
    "material_changes": [],
    "unclassified_changes": [],
    "decision_age_ms": 100,
    "max_decision_age_ms": 1000,
    "reasons": [],
    "prior_decision_preserved_as_history": True,
    "binding_authority_granted": False,
    "physical_action_executed": False,
    "commit_revalidation_performed": True,
}

SNAPSHOT = {
    "action_id": ACTION,
    "object_hash": OBJECT,
    "authority_current": True,
    "evidence_digest": "sha256:evidence",
    "criteria_version": "v1",
    "configuration_hash": "sha256:config",
    "environment_context_hash": "sha256:env",
}


def binding_for(step186=None, step180=None, snapshot=None):
    s186 = dict(STEP186) if step186 is None else step186
    s180 = dict(STEP180) if step180 is None else step180
    snap = dict(SNAPSHOT) if snapshot is None else snapshot
    return {
        "declared_scope_id": SCOPE,
        "action_id": ACTION,
        "object_hash": OBJECT,
        "commit_point_id": "COMMIT-001",
        "commit_binding_evidence_ref": "EVIDENCE-COMMIT-001",
        "commit_binding_basis_version": "1.0",
        "binding_traceable": True,
        "binding_current": True,
        "binding_ambiguity_present": False,
        "binding_temporal_ordering_established": True,
        "binding_change_assessment_complete": True,
        "material_change_after_commit_binding": False,
        "commit_binding_revalidated_after_latest_material_change": False,
        "step186_result_digest": canonical_payload_digest(s186),
        "step180_result_digest": canonical_payload_digest(s180),
        "current_snapshot_digest": canonical_payload_digest(snap),
        "step186_evaluator_blob": STEP186_EVALUATOR_BLOB,
        "step186_test_blob": STEP186_TEST_BLOB,
        "step180_evaluator_blob": STEP180_EVALUATOR_BLOB,
        "step180_test_blob": STEP180_TEST_BLOB,
    }


def run(*, step186=None, step180=None, snapshot=None, binding=None, scope=SCOPE, action=ACTION, obj=OBJECT, caller="COMMIT"):
    s186 = dict(STEP186) if step186 is None else step186
    s180 = dict(STEP180) if step180 is None else step180
    snap = dict(SNAPSHOT) if snapshot is None else snapshot
    b = binding_for(s186, s180, snap) if binding is None else binding
    return evaluate_accountability_commit_time_revalidation(
        step186_result=s186,
        step180_result=s180,
        current_snapshot=snap,
        commit_binding_record=b,
        expected_scope_id=scope,
        expected_action_id=action,
        expected_object_hash=obj,
        caller_requested_decision=caller,
    )


class Step187Tests(unittest.TestCase):
    def test_clean_composition_supportable(self):
        r = run()
        self.assertEqual(r["commit_time_accountability_standing"], SUPPORTABLE)
        self.assertEqual(r["commit_time_decision"], "ACCOUNTABILITY_COMMIT_PREREQUISITES_SUPPORTABLE")
        self.assertEqual(r["no_bind_state"], "SEPARATE_AUTHORIZED_COMMIT_MECHANISM_REQUIRED")
        self.assertFalse(r["commit_authorized"])

    def test_step186_failure_blocks(self):
        s = dict(STEP186); s["integration_standing"] = "ACCOUNTABILITY_BOUNDARY_INTEGRATION_NOT_ESTABLISHED"
        r = run(step186=s)
        self.assertEqual(r["commit_time_accountability_standing"], NOT_ESTABLISHED)
        self.assertIn("STEP_186_INTEGRATION_NOT_SUPPORTABLE", r["reasons"])

    def test_step180_failure_blocks(self):
        s = dict(STEP180); s["execution_time_standing"] = "REASSESSMENT_REQUIRED"
        self.assertIn("STEP_180_EXECUTION_TIME_STANDING_NOT_SUPPORTABLE", run(step180=s)["reasons"])

    def test_current_authority_required(self):
        s = dict(SNAPSHOT); s["authority_current"] = False
        self.assertIn("CURRENT_AUTHORITY_NOT_ESTABLISHED_AT_COMMIT", run(snapshot=s)["reasons"])

    def test_scope_must_match_step186(self):
        self.assertIn("STEP_186_SCOPE_MISMATCH", run(scope="OTHER")["reasons"])

    def test_action_must_match_step186_and_snapshot(self):
        self.assertIn("STEP_186_ACTION_MISMATCH", run(action="OTHER")["reasons"])
        self.assertIn("CURRENT_ACTION_MISMATCH", run(action="OTHER")["reasons"])

    def test_object_must_match_step186_and_snapshot(self):
        self.assertIn("STEP_186_OBJECT_MISMATCH", run(obj="sha256:other")["reasons"])
        self.assertIn("CURRENT_OBJECT_MISMATCH", run(obj="sha256:other")["reasons"])

    def test_step186_payload_swap_detected(self):
        b = binding_for()
        s = dict(STEP186); s["expected_action_id"] = "SWAPPED"
        self.assertIn("COMMIT_BINDING_STEP_186_PAYLOAD_DIGEST_MISMATCH", run(step186=s, binding=b)["reasons"])

    def test_step180_payload_swap_detected(self):
        b = binding_for()
        s = dict(STEP180); s["decision_age_ms"] = 101
        self.assertIn("COMMIT_BINDING_STEP_180_PAYLOAD_DIGEST_MISMATCH", run(step180=s, binding=b)["reasons"])

    def test_current_snapshot_swap_detected(self):
        b = binding_for()
        s = dict(SNAPSHOT); s["evidence_digest"] = "sha256:swapped"
        self.assertIn("COMMIT_BINDING_CURRENT_SNAPSHOT_DIGEST_MISMATCH", run(snapshot=s, binding=b)["reasons"])

    def test_wrong_step186_source_identity_blocks(self):
        b = binding_for(); b["step186_evaluator_blob"] = "bad"
        self.assertIn("STEP_186_FROZEN_EVALUATOR_IDENTITY_MISMATCH", run(binding=b)["reasons"])

    def test_wrong_step180_source_identity_blocks(self):
        b = binding_for(); b["step180_evaluator_blob"] = "bad"
        self.assertIn("STEP_180_EVALUATOR_IDENTITY_MISMATCH", run(binding=b)["reasons"])

    def test_binding_traceability_required(self):
        b = binding_for(); b["binding_traceable"] = False
        self.assertIn("COMMIT_BINDING_NOT_TRACEABLE", run(binding=b)["reasons"])

    def test_binding_current_required(self):
        b = binding_for(); b["binding_current"] = False
        self.assertIn("COMMIT_BINDING_NOT_CURRENT", run(binding=b)["reasons"])

    def test_binding_temporal_ordering_required(self):
        b = binding_for(); b["binding_temporal_ordering_established"] = False
        self.assertIn("COMMIT_BINDING_TEMPORAL_ORDERING_NOT_ESTABLISHED", run(binding=b)["reasons"])

    def test_binding_change_assessment_required(self):
        b = binding_for(); b["binding_change_assessment_complete"] = False
        self.assertIn("COMMIT_BINDING_CHANGE_ASSESSMENT_INCOMPLETE", run(binding=b)["reasons"])

    def test_material_change_requires_revalidation(self):
        b = binding_for(); b["material_change_after_commit_binding"] = True
        self.assertIn("COMMIT_BINDING_STALE_AFTER_MATERIAL_CHANGE", run(binding=b)["reasons"])

    def test_material_change_revalidation_restores_supportability(self):
        b = binding_for(); b["material_change_after_commit_binding"] = True; b["commit_binding_revalidated_after_latest_material_change"] = True
        self.assertEqual(run(binding=b)["commit_time_accountability_standing"], SUPPORTABLE)

    def test_missing_material_change_state_fails_closed(self):
        b = binding_for(); b.pop("material_change_after_commit_binding")
        self.assertIn("COMMIT_BINDING_MATERIAL_CHANGE_STATE_INVALID", run(binding=b)["reasons"])

    def test_stale_step180_decision_blocks(self):
        s = dict(STEP180); s["decision_age_ms"] = 1001
        self.assertIn("STEP_180_PRIOR_DECISION_STALE", run(step180=s)["reasons"])

    def test_step180_material_change_contract_blocks(self):
        s = dict(STEP180); s["material_changes"] = ["criteria_version"]
        self.assertIn("STEP_180_MATERIAL_CHANGE_CONTRACT_INVALID", run(step180=s)["reasons"])

    def test_step180_unclassified_change_contract_blocks(self):
        s = dict(STEP180); s["unclassified_changes"] = ["configuration_hash"]
        self.assertIn("STEP_180_UNCLASSIFIED_CHANGE_CONTRACT_INVALID", run(step180=s)["reasons"])

    def test_supportable_step186_reasons_must_be_empty(self):
        s = dict(STEP186); s["reasons"] = ["SHOULD_NOT_BE_HERE"]
        self.assertIn("STEP_186_SUPPORTABLE_RESULT_REASONS_INVALID", run(step186=s)["reasons"])

    def test_supportable_step180_reasons_must_be_empty(self):
        s = dict(STEP180); s["reasons"] = ["SHOULD_NOT_BE_HERE"]
        self.assertIn("STEP_180_SUPPORTABLE_RESULT_REASONS_INVALID", run(step180=s)["reasons"])

    def test_missing_expected_ids_fail_closed(self):
        self.assertIn("EXPECTED_SCOPE_ID_MISSING_OR_INVALID", run(scope="")["reasons"])
        self.assertIn("EXPECTED_ACTION_ID_MISSING_OR_INVALID", run(action="")["reasons"])
        self.assertIn("EXPECTED_OBJECT_HASH_MISSING_OR_INVALID", run(obj="")["reasons"])

    def test_caller_commit_override_rejected_when_blocked(self):
        s = dict(SNAPSHOT); s["authority_current"] = False
        self.assertTrue(run(snapshot=s)["caller_override_rejected"])

    def test_supportable_result_never_authorizes_commit_or_execution(self):
        r = run()
        self.assertFalse(r["binding_authority_granted"])
        self.assertFalse(r["action_admissibility_granted"])
        self.assertFalse(r["commit_authorized"])
        self.assertFalse(r["execution_authorized"])
        self.assertFalse(r["physical_action_executed"])
        self.assertFalse(r["regulated_release_or_disposition_authorized"])
        self.assertFalse(r["binding_provenance_manufactured"])
        self.assertFalse(r["irlt_mag_state_changed"])


if __name__ == "__main__":
    unittest.main()
