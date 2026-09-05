import importlib.util
import unittest
from pathlib import Path

from accountability_postcommit_correspondence_nonbypass import (
    NOT_ESTABLISHED,
    STEP182_EVALUATOR_BLOB,
    STEP182_TEST_BLOB,
    STEP188_EVALUATOR_BLOB,
    STEP188_TEST_BLOB,
    SUPPORTABLE,
    canonical_digest,
    evaluate_accountability_postcommit_correspondence_nonbypass,
)

HERE = Path(__file__).resolve().parent
IMPLEMENTATION_DIR = HERE.parent


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


step188 = load_module(
    IMPLEMENTATION_DIR / "step_188_accountability_continuity_atomic_commit_nonbypass_r1" / "accountability_atomic_commit_nonbypass.py",
    "step189_test_step188",
)
step182 = load_module(
    IMPLEMENTATION_DIR / "step_182_commit_execution_outcome_correspondence_r1" / "commit_execution_outcome_correspondence.py",
    "step189_test_step182",
)

SCOPE = "AI-WORKFLOW-001:CONSEQUENCE-SCOPE-A"
ACTION = "ACTION-001"
OBJECT = "sha256:object-001"
TRANSACTION = "TX-001"
NONCE = "NONCE-001"
COMMIT_POINT = "ATOMIC-COMMIT-001"

SNAPSHOT = {
    "object_hash": OBJECT,
    "authority_current": True,
    "evidence_digest": "sha256:evidence",
    "criteria_version": "v1",
    "configuration_hash": "sha256:config",
    "environment_context_hash": "sha256:env",
}
STEP187_SNAPSHOT = {"action_id": ACTION, **SNAPSHOT}

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


def step187_binding():
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
        "step186_result_digest": "sha256:step186",
        "step180_result_digest": "sha256:step180",
        "current_snapshot_digest": step188.canonical_payload_digest(STEP187_SNAPSHOT),
        "step186_evaluator_blob": "356d7b249dff4c0c48be24e6470f2519cae0594d",
        "step186_test_blob": "a9acc4cdc0d1288999744760eac2223d55963a54",
        "step180_evaluator_blob": "c5d84fc6532632a282fe4f80fbbec9bd3594772f",
        "step180_test_blob": "07ce7a902be2542d77bd50f70892680e54af026a",
    }


def token():
    snapshot_digest = step188.step181_digest(SNAPSHOT)
    material = {
        "action_id": ACTION,
        "transaction_id": TRANSACTION,
        "commit_nonce": NONCE,
        "object_hash": OBJECT,
        "snapshot_digest": snapshot_digest,
    }
    return {
        "token_state": "ISSUED",
        "token_id": step188.step181_digest(material),
        "action_id": ACTION,
        "transaction_id": TRANSACTION,
        "commit_nonce": NONCE,
        "object_hash": OBJECT,
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


def atomic_binding(tok):
    verification = step188.verification_input_payload(
        token=tok,
        commit_snapshot=SNAPSHOT,
        action_id=ACTION,
        transaction_id=TRANSACTION,
        commit_nonce=NONCE,
    )
    b187 = step187_binding()
    return {
        "declared_scope_id": SCOPE,
        "action_id": ACTION,
        "object_hash": OBJECT,
        "transaction_id": TRANSACTION,
        "commit_nonce": NONCE,
        "commit_point_id": COMMIT_POINT,
        "binding_evidence_ref": "EVIDENCE-ATOMIC-001",
        "binding_basis_version": "1.0",
        "binding_traceable": True,
        "binding_current": True,
        "binding_ambiguity_present": False,
        "binding_temporal_ordering_established": True,
        "binding_change_assessment_complete": True,
        "material_change_after_atomic_binding": False,
        "atomic_binding_revalidated_after_latest_material_change": False,
        "step187_result_digest": step188.canonical_payload_digest(STEP187),
        "step187_commit_binding_record_digest": step188.canonical_payload_digest(b187),
        "step187_current_snapshot_digest": step188.canonical_payload_digest(STEP187_SNAPSHOT),
        "step181_token_digest": step188.canonical_payload_digest(tok),
        "step181_commit_result_digest": step188.canonical_payload_digest(COMMIT_RESULT),
        "commit_snapshot_digest": step188.canonical_payload_digest(SNAPSHOT),
        "step181_verification_input_digest": step188.canonical_payload_digest(verification),
        "step187_evaluator_blob": step188.STEP187_EVALUATOR_BLOB,
        "step187_primary_test_blob": step188.STEP187_PRIMARY_TEST_BLOB,
        "step187_hardening_test_blob": step188.STEP187_HARDENING_TEST_BLOB,
        "step181_evaluator_blob": step188.STEP181_EVALUATOR_BLOB,
        "step181_test_blob": step188.STEP181_TEST_BLOB,
    }


def bundles():
    tok = token()
    b187 = step187_binding()
    b188 = atomic_binding(tok)
    s188_inputs = {
        "step187_result": STEP187,
        "step187_commit_binding_record": b187,
        "step187_current_snapshot": STEP187_SNAPSHOT,
        "step181_token": tok,
        "step181_commit_result": COMMIT_RESULT,
        "commit_snapshot": SNAPSHOT,
        "atomic_binding_record": b188,
        "expected_scope_id": SCOPE,
        "expected_action_id": ACTION,
        "expected_object_hash": OBJECT,
        "expected_transaction_id": TRANSACTION,
        "expected_commit_nonce": NONCE,
        "caller_requested_decision": "COMMIT",
    }
    s188_result = step188.evaluate_accountability_atomic_commit_nonbypass(**s188_inputs)

    commit = {
        "action_id": ACTION,
        "transaction_id": TRANSACTION,
        "object_hash": OBJECT,
        "commit_nonce": NONCE,
        "commit_token_id": tok["token_id"],
        "commit_point_id": COMMIT_POINT,
        "commit_status": "COMMITTED",
        "token_consumed": True,
        "token_consumption_count": 1,
        "token_replay_detected": False,
        "commit_event_id": "COMMIT-EVENT-001",
        "token_consumption_evidence_ref": "TOKEN-CONSUME-EVIDENCE-001",
    }
    execution = {
        "action_id": ACTION,
        "transaction_id": TRANSACTION,
        "object_hash": OBJECT,
        "target": "TARGET-1",
        "destination": "DEST-1",
        "execution_status": "SUCCEEDED",
    }
    outcome = {
        "action_id": ACTION,
        "transaction_id": TRANSACTION,
        "object_hash": OBJECT,
        "target": "TARGET-1",
        "destination": "DEST-1",
        "outcome_status": "OBSERVED",
        "observed_outcome": "OUTCOME-OK",
    }
    expected = {
        "action_id": ACTION,
        "transaction_id": TRANSACTION,
        "object_hash": OBJECT,
        "target": "TARGET-1",
        "destination": "DEST-1",
        "intended_outcome": "OUTCOME-OK",
    }
    s182_inputs = {
        "prior_commit_result": COMMIT_RESULT,
        "commit_receipt": commit,
        "execution_receipt": execution,
        "outcome_evidence": outcome,
        "expected": expected,
    }
    s182_result = step182.evaluate_commit_execution_outcome_correspondence(**s182_inputs)
    return s188_inputs, s188_result, s182_inputs, s182_result


def postcommit_binding(s188_inputs, s188_result, s182_inputs, s182_result):
    commit = s182_inputs["commit_receipt"]
    execution = s182_inputs["execution_receipt"]
    outcome = s182_inputs["outcome_evidence"]
    expected = s182_inputs["expected"]
    return {
        "declared_scope_id": SCOPE,
        "action_id": ACTION,
        "object_hash": OBJECT,
        "transaction_id": TRANSACTION,
        "commit_nonce": NONCE,
        "commit_point_id": COMMIT_POINT,
        "binding_evidence_ref": "EVIDENCE-POSTCOMMIT-001",
        "binding_basis_version": "1.0",
        "binding_traceable": True,
        "binding_current": True,
        "binding_ambiguity_present": False,
        "binding_temporal_ordering_established": True,
        "binding_change_assessment_complete": True,
        "material_change_after_postcommit_binding": False,
        "postcommit_binding_revalidated_after_latest_material_change": False,
        "step188_input_bundle_digest": canonical_digest(s188_inputs),
        "step188_result_digest": canonical_digest(s188_result),
        "step182_input_bundle_digest": canonical_digest(s182_inputs),
        "step182_result_digest": canonical_digest(s182_result),
        "step181_token_digest": canonical_digest(s188_inputs["step181_token"]),
        "commit_receipt_digest": canonical_digest(commit),
        "execution_receipt_digest": canonical_digest(execution),
        "outcome_evidence_digest": canonical_digest(outcome),
        "expected_digest": canonical_digest(expected),
        "step188_evaluator_blob": STEP188_EVALUATOR_BLOB,
        "step188_test_blob": STEP188_TEST_BLOB,
        "step182_evaluator_blob": STEP182_EVALUATOR_BLOB,
        "step182_test_blob": STEP182_TEST_BLOB,
    }


def run(mutator=None, caller="EVALUATE"):
    s188_inputs, s188_result, s182_inputs, s182_result = bundles()
    if mutator:
        mutator(s188_inputs, s188_result, s182_inputs, s182_result)
    binding = postcommit_binding(s188_inputs, s188_result, s182_inputs, s182_result)
    return evaluate_accountability_postcommit_correspondence_nonbypass(
        step188_inputs=s188_inputs,
        step188_result=s188_result,
        step182_inputs=s182_inputs,
        step182_result=s182_result,
        postcommit_binding_record=binding,
        caller_requested_decision=caller,
    )


class Step189Tests(unittest.TestCase):
    def test_clean_composition_supportable(self):
        result = run()
        self.assertEqual(result["accountability_postcommit_standing"], SUPPORTABLE)
        self.assertFalse(result["postcommit_reliance_held"])
        self.assertTrue(result["step_188_result_reproduced"])
        self.assertTrue(result["step_182_result_reproduced"])
        self.assertTrue(result["token_consumption_correspondence_supportable"])
        self.assertFalse(result["binding_authority_granted"])
        self.assertFalse(result["commit_token_consumed_by_evaluator"])

    def test_step188_result_substitution_fails_closed(self):
        def mutate(_, r188, __, ___):
            r188["expected_action_id"] = "OTHER"
        result = run(mutate)
        self.assertIn("STEP_188_RESULT_NOT_REPRODUCIBLE_FROM_EXACT_INPUTS", result["reasons"])
        self.assertEqual(result["accountability_postcommit_standing"], NOT_ESTABLISHED)

    def test_step182_result_substitution_fails_closed(self):
        def mutate(_, __, ___, r182):
            r182["intended_outcome_established"] = False
        result = run(mutate)
        self.assertIn("STEP_182_RESULT_NOT_REPRODUCIBLE_FROM_EXACT_INPUTS", result["reasons"])

    def test_step182_cannot_use_different_favorable_step181_shape(self):
        def mutate(_, __, i182, ___):
            prior = dict(i182["prior_commit_result"])
            prior["extra_favorable_field"] = True
            i182["prior_commit_result"] = prior
        result = run(mutate)
        self.assertIn("STEP_182_PRIOR_COMMIT_RESULT_NOT_EXACT_STEP_188_STEP_181_RESULT", result["reasons"])

    def test_commit_receipt_requires_exact_step188_token(self):
        def mutate(_, __, i182, ___):
            i182["commit_receipt"]["commit_token_id"] = "wrong-token"
        result = run(mutate)
        self.assertIn("COMMIT_RECEIPT_TOKEN_ID_NOT_STEP_188_BOUND", result["reasons"])

    def test_token_consumption_must_be_explicit(self):
        def mutate(_, __, i182, ___):
            i182["commit_receipt"]["token_consumed"] = False
        result = run(mutate)
        self.assertIn("BOUND_COMMIT_TOKEN_CONSUMPTION_NOT_ESTABLISHED", result["reasons"])

    def test_token_consumption_must_be_single_use(self):
        def mutate(_, __, i182, ___):
            i182["commit_receipt"]["token_consumption_count"] = 2
        result = run(mutate)
        self.assertIn("BOUND_COMMIT_TOKEN_SINGLE_USE_CONSUMPTION_NOT_ESTABLISHED", result["reasons"])

    def test_replay_state_must_be_clear(self):
        def mutate(_, __, i182, ___):
            i182["commit_receipt"]["token_replay_detected"] = True
        result = run(mutate)
        self.assertIn("BOUND_COMMIT_TOKEN_REPLAY_STATE_NOT_CLEAR", result["reasons"])

    def test_commit_nonce_must_match_step188(self):
        def mutate(_, __, i182, ___):
            i182["commit_receipt"]["commit_nonce"] = "OTHER"
        result = run(mutate)
        self.assertIn("COMMIT_RECEIPT_NONCE_NOT_STEP_188_BOUND", result["reasons"])

    def test_commit_point_must_match_step188_atomic_binding(self):
        def mutate(_, __, i182, ___):
            i182["commit_receipt"]["commit_point_id"] = "OTHER"
        result = run(mutate)
        self.assertIn("COMMIT_RECEIPT_COMMIT_POINT_NOT_STEP_188_BOUND", result["reasons"])

    def test_step182_expected_action_is_bound_to_step188(self):
        def mutate(_, __, i182, ___):
            i182["expected"]["action_id"] = "OTHER"
        result = run(mutate)
        self.assertIn("STEP_182_EXPECTED_ACTION_NOT_STEP_188_BOUND", result["reasons"])

    def test_step182_expected_transaction_is_bound_to_step188(self):
        def mutate(_, __, i182, ___):
            i182["expected"]["transaction_id"] = "OTHER"
        result = run(mutate)
        self.assertIn("STEP_182_EXPECTED_TRANSACTION_NOT_STEP_188_BOUND", result["reasons"])

    def test_step182_expected_object_is_bound_to_step188(self):
        def mutate(_, __, i182, ___):
            i182["expected"]["object_hash"] = "OTHER"
        result = run(mutate)
        self.assertIn("STEP_182_EXPECTED_OBJECT_NOT_STEP_188_BOUND", result["reasons"])

    def test_missing_commit_event_id_fails_closed(self):
        def mutate(_, __, i182, ___):
            i182["commit_receipt"].pop("commit_event_id")
        result = run(mutate)
        self.assertIn("COMMIT_RECEIPT_COMMIT_EVENT_ID_MISSING_OR_INVALID", result["reasons"])

    def test_missing_token_consumption_evidence_ref_fails_closed(self):
        def mutate(_, __, i182, ___):
            i182["commit_receipt"].pop("token_consumption_evidence_ref")
        result = run(mutate)
        self.assertIn("COMMIT_RECEIPT_TOKEN_CONSUMPTION_EVIDENCE_REF_MISSING_OR_INVALID", result["reasons"])

    def test_postcommit_binding_substitution_fails_closed(self):
        s188_inputs, s188_result, s182_inputs, s182_result = bundles()
        binding = postcommit_binding(s188_inputs, s188_result, s182_inputs, s182_result)
        binding["step188_result_digest"] = "sha256:bad"
        result = evaluate_accountability_postcommit_correspondence_nonbypass(
            step188_inputs=s188_inputs,
            step188_result=s188_result,
            step182_inputs=s182_inputs,
            step182_result=s182_result,
            postcommit_binding_record=binding,
        )
        self.assertIn("POSTCOMMIT_BINDING_STEP_188_RESULT_DIGEST_MISMATCH", result["reasons"])

    def test_postcommit_binding_currentness_required(self):
        s188_inputs, s188_result, s182_inputs, s182_result = bundles()
        binding = postcommit_binding(s188_inputs, s188_result, s182_inputs, s182_result)
        binding["binding_current"] = False
        result = evaluate_accountability_postcommit_correspondence_nonbypass(
            step188_inputs=s188_inputs,
            step188_result=s188_result,
            step182_inputs=s182_inputs,
            step182_result=s182_result,
            postcommit_binding_record=binding,
        )
        self.assertIn("POSTCOMMIT_BINDING_NOT_CURRENT", result["reasons"])

    def test_material_change_requires_revalidation(self):
        s188_inputs, s188_result, s182_inputs, s182_result = bundles()
        binding = postcommit_binding(s188_inputs, s188_result, s182_inputs, s182_result)
        binding["material_change_after_postcommit_binding"] = True
        result = evaluate_accountability_postcommit_correspondence_nonbypass(
            step188_inputs=s188_inputs,
            step188_result=s188_result,
            step182_inputs=s182_inputs,
            step182_result=s182_result,
            postcommit_binding_record=binding,
        )
        self.assertIn("POSTCOMMIT_BINDING_STALE_AFTER_MATERIAL_CHANGE", result["reasons"])

    def test_caller_cannot_turn_evaluation_into_authority(self):
        result = run(caller="EXECUTE")
        self.assertIn("CALLER_AUTHORITY_OVERRIDE_REJECTED", result["reasons"])
        self.assertTrue(result["caller_override_rejected"])
        self.assertFalse(result["execution_authorized"])

    def test_extra_step188_input_is_rejected(self):
        def mutate(i188, _, __, ___):
            i188["unexpected"] = "x"
        result = run(mutate)
        self.assertIn("STEP_188_INPUT_UNEXPECTED_UNEXPECTED", result["reasons"])

    def test_extra_step182_input_is_rejected(self):
        def mutate(_, __, i182, ___):
            i182["unexpected"] = "x"
        result = run(mutate)
        self.assertIn("STEP_182_INPUT_UNEXPECTED_UNEXPECTED", result["reasons"])

    def test_historical_commit_execution_are_preserved_in_supportable_route(self):
        result = run()
        self.assertTrue(result["historical_facts"]["commit_occurred"])
        self.assertTrue(result["historical_facts"]["execution_succeeded"])
        self.assertFalse(result["historical_facts_rewritten"])


if __name__ == "__main__":
    unittest.main()
