import unittest

from accountability_atomic_commit_nonbypass import (
    NOT_ESTABLISHED,
    SUPPORTABLE,
    STEP181_EVALUATOR_BLOB,
    STEP181_TEST_BLOB,
    STEP187_EVALUATOR_BLOB,
    STEP187_HARDENING_TEST_BLOB,
    STEP187_PRIMARY_TEST_BLOB,
    canonical_payload_digest,
    evaluate_accountability_atomic_commit_nonbypass,
    step181_digest,
    verification_input_payload,
)

SCOPE = "AI-WORKFLOW-001:CONSEQUENCE-SCOPE-A"
ACTION = "ACTION-001"
OBJECT = "sha256:object-001"
TRANSACTION = "TX-001"
NONCE = "NONCE-001"

STEP187 = {
    "integration_revision": "STEP_187_R1",
    "commit_time_accountability_standing": "ACCOUNTABILITY_COMMIT_TIME_CONTINUITY_SUPPORTABLE",
    "commit_time_decision": "ACCOUNTABILITY_COMMIT_PREREQUISITES_SUPPORTABLE",
    "no_bind_state": "SEPARATE_AUTHORIZED_COMMIT_MECHANISM_REQUIRED",
    "action_held": False,
    "expected_scope_id": SCOPE,
    "expected_action_id": ACTION,
    "expected_object_hash": OBJECT,
    "reasons": [],
    "step_186_result_consumed": True,
    "step_180_result_consumed": True,
    "current_snapshot_consumed": True,
    "commit_binding_checked": True,
    "source_identity_checked": True,
    "payload_digest_binding_checked": True,
    "commit_temporal_currentness_checked": True,
    "binding_provenance_manufactured": False,
    "binding_authority_granted": False,
    "action_admissibility_granted": False,
    "commit_authorized": False,
    "execution_authorized": False,
    "physical_action_executed": False,
    "regulated_release_or_disposition_authorized": False,
    "historical_facts_rewritten": False,
    "irlt_mag_state_changed": False,
}

SNAPSHOT = {
    "object_hash": OBJECT,
    "authority_current": True,
    "evidence_digest": "sha256:evidence",
    "criteria_version": "v1",
    "configuration_hash": "sha256:config",
    "environment_context_hash": "sha256:env",
}


def token_for(snapshot=None, action=ACTION, transaction=TRANSACTION, nonce=NONCE):
    snap = dict(SNAPSHOT) if snapshot is None else snapshot
    snapshot_digest = step181_digest(snap)
    token_material = {
        "action_id": action,
        "transaction_id": transaction,
        "commit_nonce": nonce,
        "object_hash": snap.get("object_hash"),
        "snapshot_digest": snapshot_digest,
    }
    return {
        "token_state": "ISSUED",
        "token_id": step181_digest(token_material),
        "action_id": action,
        "transaction_id": transaction,
        "commit_nonce": nonce,
        "object_hash": snap.get("object_hash"),
        "snapshot_digest": snapshot_digest,
        "revalidation_decision": "ADMISSIBLE",
        "reasons": [],
        "single_use_required": True,
        "binding_authority_granted": False,
        "physical_action_executed": False,
    }


COMMIT_RESULT = {
    "atomic_commit_standing": "SUPPORTABLE",
    "commit_decision": "COMMIT_ROUTE_ADMISSIBLE",
    "no_bind_state": "INACTIVE",
    "action_held": False,
    "token_consumption_required_on_commit": True,
    "reasons": [],
    "evaluated_to_committed_binding_verified": True,
    "binding_authority_granted": False,
    "physical_action_executed": False,
}


def binding_for(step187=None, token=None, commit_result=None, snapshot=None):
    s187 = dict(STEP187) if step187 is None else step187
    tok = token_for() if token is None else token
    result = dict(COMMIT_RESULT) if commit_result is None else commit_result
    snap = dict(SNAPSHOT) if snapshot is None else snapshot
    verification = verification_input_payload(
        token=tok,
        commit_snapshot=snap,
        action_id=ACTION,
        transaction_id=TRANSACTION,
        commit_nonce=NONCE,
    )
    return {
        "declared_scope_id": SCOPE,
        "action_id": ACTION,
        "object_hash": OBJECT,
        "transaction_id": TRANSACTION,
        "commit_nonce": NONCE,
        "commit_point_id": "COMMIT-POINT-001",
        "binding_evidence_ref": "EVIDENCE-ATOMIC-001",
        "binding_basis_version": "1.0",
        "binding_traceable": True,
        "binding_current": True,
        "binding_ambiguity_present": False,
        "binding_temporal_ordering_established": True,
        "binding_change_assessment_complete": True,
        "material_change_after_atomic_binding": False,
        "atomic_binding_revalidated_after_latest_material_change": False,
        "step187_result_digest": canonical_payload_digest(s187),
        "step181_token_digest": canonical_payload_digest(tok),
        "step181_commit_result_digest": canonical_payload_digest(result),
        "commit_snapshot_digest": canonical_payload_digest(snap),
        "step181_verification_input_digest": canonical_payload_digest(verification),
        "step187_evaluator_blob": STEP187_EVALUATOR_BLOB,
        "step187_primary_test_blob": STEP187_PRIMARY_TEST_BLOB,
        "step187_hardening_test_blob": STEP187_HARDENING_TEST_BLOB,
        "step181_evaluator_blob": STEP181_EVALUATOR_BLOB,
        "step181_test_blob": STEP181_TEST_BLOB,
    }


def run(*, step187=None, token=None, commit_result=None, snapshot=None, binding=None,
        scope=SCOPE, action=ACTION, obj=OBJECT, transaction=TRANSACTION, nonce=NONCE,
        caller="COMMIT"):
    s187 = dict(STEP187) if step187 is None else step187
    tok = token_for() if token is None else token
    result = dict(COMMIT_RESULT) if commit_result is None else commit_result
    snap = dict(SNAPSHOT) if snapshot is None else snapshot
    b = binding_for(s187, tok, result, snap) if binding is None else binding
    return evaluate_accountability_atomic_commit_nonbypass(
        step187_result=s187,
        step181_token=tok,
        step181_commit_result=result,
        commit_snapshot=snap,
        atomic_binding_record=b,
        expected_scope_id=scope,
        expected_action_id=action,
        expected_object_hash=obj,
        expected_transaction_id=transaction,
        expected_commit_nonce=nonce,
        caller_requested_decision=caller,
    )


class Step188Tests(unittest.TestCase):
    def test_clean_composition_supportable(self):
        r = run()
        self.assertEqual(r["atomic_accountability_standing"], SUPPORTABLE)
        self.assertEqual(r["atomic_accountability_decision"], "ACCOUNTABILITY_ATOMIC_COMMIT_PREREQUISITES_SUPPORTABLE")
        self.assertEqual(r["no_bind_state"], "SEPARATE_AUTHORIZED_COMMIT_EXECUTION_AND_TOKEN_CONSUMPTION_REQUIRED")
        self.assertFalse(r["commit_authorized"])

    def test_step187_failure_blocks(self):
        s = dict(STEP187); s["commit_time_accountability_standing"] = NOT_ESTABLISHED
        self.assertIn("STEP_187_STANDING_NOT_SUPPORTABLE", run(step187=s)["reasons"])

    def test_step187_scope_action_object_mismatch_blocks(self):
        self.assertIn("STEP_187_SCOPE_MISMATCH", run(scope="OTHER")["reasons"])
        self.assertIn("STEP_187_ACTION_MISMATCH", run(action="OTHER")["reasons"])
        self.assertIn("STEP_187_OBJECT_MISMATCH", run(obj="sha256:other")["reasons"])

    def test_step187_reasons_must_be_empty(self):
        s = dict(STEP187); s["reasons"] = ["BAD"]
        self.assertIn("STEP_187_SUPPORTABLE_RESULT_REASONS_INVALID", run(step187=s)["reasons"])

    def test_step187_cannot_claim_commit_authority(self):
        s = dict(STEP187); s["commit_authorized"] = True
        self.assertIn("STEP_187_COMMIT_AUTHORITY_BOUNDARY_INVALID", run(step187=s)["reasons"])

    def test_invalid_step181_token_blocks(self):
        t = token_for(); t["token_state"] = "NOT_ISSUED"
        self.assertIn("STEP_181_VALID_TOKEN_NOT_ISSUED", run(token=t)["reasons"])

    def test_step181_token_must_be_single_use(self):
        t = token_for(); t["single_use_required"] = False
        self.assertIn("STEP_181_SINGLE_USE_REQUIREMENT_NOT_ESTABLISHED", run(token=t)["reasons"])

    def test_step181_token_reasons_must_be_empty(self):
        t = token_for(); t["reasons"] = ["BAD"]
        self.assertIn("STEP_181_ISSUED_TOKEN_REASONS_INVALID", run(token=t)["reasons"])

    def test_token_action_transaction_nonce_object_mismatch_blocks(self):
        t = token_for(action="OTHER")
        self.assertIn("STEP_181_TOKEN_ACTION_MISMATCH", run(token=t)["reasons"])
        t = token_for(transaction="OTHER")
        self.assertIn("STEP_181_TOKEN_TRANSACTION_MISMATCH", run(token=t)["reasons"])
        t = token_for(nonce="OTHER")
        self.assertIn("STEP_181_TOKEN_NONCE_MISMATCH", run(token=t)["reasons"])
        t = token_for(); t["object_hash"] = "sha256:other"
        self.assertIn("STEP_181_TOKEN_OBJECT_MISMATCH", run(token=t)["reasons"])

    def test_token_id_reconstruction_detects_forgery(self):
        t = token_for(); t["token_id"] = "forged"
        self.assertIn("STEP_181_TOKEN_ID_MISMATCH", run(token=t)["reasons"])

    def test_step181_commit_result_failure_blocks(self):
        c = dict(COMMIT_RESULT); c["atomic_commit_standing"] = "NO_BIND"
        self.assertIn("STEP_181_ATOMIC_COMMIT_NOT_SUPPORTABLE", run(commit_result=c)["reasons"])

    def test_step181_commit_route_must_be_admissible(self):
        c = dict(COMMIT_RESULT); c["commit_decision"] = "NOT_ADMISSIBLE"
        self.assertIn("STEP_181_COMMIT_ROUTE_NOT_ADMISSIBLE", run(commit_result=c)["reasons"])

    def test_token_consumption_requirement_must_survive(self):
        c = dict(COMMIT_RESULT); c["token_consumption_required_on_commit"] = False
        self.assertIn("STEP_181_TOKEN_CONSUMPTION_REQUIREMENT_NOT_ESTABLISHED", run(commit_result=c)["reasons"])

    def test_commit_snapshot_authority_must_be_current(self):
        s = dict(SNAPSHOT); s["authority_current"] = False
        self.assertIn("COMMIT_AUTHORITY_NOT_CURRENT", run(snapshot=s)["reasons"])

    def test_commit_snapshot_object_must_match(self):
        s = dict(SNAPSHOT); s["object_hash"] = "sha256:other"
        self.assertIn("COMMIT_OBJECT_MISMATCH", run(snapshot=s)["reasons"])

    def test_token_snapshot_digest_must_match_commit_snapshot(self):
        t = token_for()
        s = dict(SNAPSHOT); s["evidence_digest"] = "sha256:changed"
        self.assertIn("STEP_181_TOKEN_SNAPSHOT_DIGEST_MISMATCH", run(token=t, snapshot=s)["reasons"])

    def test_step187_payload_swap_detected(self):
        b = binding_for()
        s = dict(STEP187); s["expected_action_id"] = "SWAPPED"
        self.assertIn("ATOMIC_BINDING_STEP_187_PAYLOAD_DIGEST_MISMATCH", run(step187=s, binding=b)["reasons"])

    def test_step181_token_payload_swap_detected(self):
        b = binding_for()
        t = token_for(); t["transaction_id"] = "SWAPPED"
        self.assertIn("ATOMIC_BINDING_STEP_181_TOKEN_DIGEST_MISMATCH", run(token=t, binding=b)["reasons"])

    def test_step181_commit_result_payload_swap_detected(self):
        b = binding_for()
        c = dict(COMMIT_RESULT); c["extra"] = "changed"
        self.assertIn("ATOMIC_BINDING_STEP_181_COMMIT_RESULT_DIGEST_MISMATCH", run(commit_result=c, binding=b)["reasons"])

    def test_commit_snapshot_payload_swap_detected(self):
        b = binding_for()
        s = dict(SNAPSHOT); s["evidence_digest"] = "sha256:swapped"
        self.assertIn("ATOMIC_BINDING_COMMIT_SNAPSHOT_DIGEST_MISMATCH", run(snapshot=s, binding=b)["reasons"])

    def test_verification_input_bundle_swap_detected(self):
        b = binding_for(); b["step181_verification_input_digest"] = "sha256:bad"
        self.assertIn("ATOMIC_BINDING_STEP_181_VERIFICATION_INPUT_DIGEST_MISMATCH", run(binding=b)["reasons"])

    def test_wrong_source_identity_blocks(self):
        b = binding_for(); b["step187_evaluator_blob"] = "bad"
        self.assertIn("STEP_187_FROZEN_EVALUATOR_IDENTITY_MISMATCH", run(binding=b)["reasons"])
        b = binding_for(); b["step181_evaluator_blob"] = "bad"
        self.assertIn("STEP_181_EVALUATOR_IDENTITY_MISMATCH", run(binding=b)["reasons"])

    def test_binding_traceability_currentness_ambiguity_required(self):
        b = binding_for(); b["binding_traceable"] = False
        self.assertIn("ATOMIC_BINDING_NOT_TRACEABLE", run(binding=b)["reasons"])
        b = binding_for(); b["binding_current"] = False
        self.assertIn("ATOMIC_BINDING_NOT_CURRENT", run(binding=b)["reasons"])
        b = binding_for(); b["binding_ambiguity_present"] = True
        self.assertIn("ATOMIC_BINDING_AMBIGUOUS_OR_INVALID", run(binding=b)["reasons"])

    def test_temporal_ordering_and_change_assessment_required(self):
        b = binding_for(); b["binding_temporal_ordering_established"] = False
        self.assertIn("ATOMIC_BINDING_TEMPORAL_ORDERING_NOT_ESTABLISHED", run(binding=b)["reasons"])
        b = binding_for(); b["binding_change_assessment_complete"] = False
        self.assertIn("ATOMIC_BINDING_CHANGE_ASSESSMENT_INCOMPLETE", run(binding=b)["reasons"])

    def test_material_change_requires_revalidation(self):
        b = binding_for(); b["material_change_after_atomic_binding"] = True
        self.assertIn("ATOMIC_BINDING_STALE_AFTER_MATERIAL_CHANGE", run(binding=b)["reasons"])

    def test_material_change_revalidation_restores_supportability(self):
        b = binding_for(); b["material_change_after_atomic_binding"] = True; b["atomic_binding_revalidated_after_latest_material_change"] = True
        self.assertEqual(run(binding=b)["atomic_accountability_standing"], SUPPORTABLE)

    def test_missing_expected_ids_fail_closed(self):
        self.assertIn("EXPECTED_SCOPE_ID_MISSING_OR_INVALID", run(scope="")["reasons"])
        self.assertIn("EXPECTED_ACTION_ID_MISSING_OR_INVALID", run(action="")["reasons"])
        self.assertIn("EXPECTED_OBJECT_HASH_MISSING_OR_INVALID", run(obj="")["reasons"])
        self.assertIn("EXPECTED_TRANSACTION_ID_MISSING_OR_INVALID", run(transaction="")["reasons"])
        self.assertIn("EXPECTED_COMMIT_NONCE_MISSING_OR_INVALID", run(nonce="")["reasons"])

    def test_caller_override_rejected_when_blocked(self):
        s = dict(SNAPSHOT); s["authority_current"] = False
        self.assertTrue(run(snapshot=s)["caller_override_rejected"])

    def test_supportable_result_never_authorizes_or_consumes(self):
        r = run()
        self.assertFalse(r["binding_authority_granted"])
        self.assertFalse(r["action_admissibility_granted"])
        self.assertFalse(r["commit_authorized"])
        self.assertFalse(r["execution_authorized"])
        self.assertFalse(r["commit_token_consumed_by_evaluator"])
        self.assertFalse(r["physical_action_executed"])
        self.assertFalse(r["regulated_release_or_disposition_authorized"])
        self.assertFalse(r["binding_provenance_manufactured"])
        self.assertFalse(r["historical_facts_rewritten"])
        self.assertFalse(r["irlt_mag_state_changed"])


if __name__ == "__main__":
    unittest.main()
