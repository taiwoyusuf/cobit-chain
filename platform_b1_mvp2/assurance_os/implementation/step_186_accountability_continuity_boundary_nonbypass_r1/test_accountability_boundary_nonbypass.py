import unittest

from accountability_boundary_nonbypass import (
    INTEGRATION_NOT_ESTABLISHED,
    INTEGRATION_SUPPORTABLE,
    evaluate_accountability_boundary_nonbypass,
)

SCOPE = "AI-WORKFLOW-001:CONSEQUENCE-SCOPE-A"
ACTION = "ACTION-001"
OBJECT = "sha256:object-001"

STEP185 = {
    "candidate_revision": "STEP_185_R1",
    "accountability_continuity_standing": "ACCOUNTABILITY_CONTINUITY_SUPPORTABLE",
    "accountability_basis_supportable": True,
    "no_bind_state": "SEPARATE_AUTHORITY_AND_ACTION_ADMISSIBILITY_REQUIRED",
    "binding_authority_granted": False,
    "accountability_manufactured_by_evaluator": False,
    "irlt_mag_state_changed": False,
    "declared_scope_id": SCOPE,
}

STEP179 = {
    "enforcement_decision": "ADMISSIBLE",
    "no_bind_state": "INACTIVE",
    "action_held": False,
    "non_bypassability_enforced": True,
    "binding_authority_granted": False,
    "physical_action_executed": False,
    "requested_object_hash": OBJECT,
}

BINDING = {
    "declared_scope_id": SCOPE,
    "action_id": ACTION,
    "object_hash": OBJECT,
    "binding_evidence_ref": "EVIDENCE-REF-001",
    "binding_basis_version": "1.0",
    "binding_traceable": True,
    "binding_current": True,
    "binding_ambiguity_present": False,
}


def run(*, step185=None, step179=None, binding=None, scope=SCOPE, action=ACTION, obj=OBJECT):
    return evaluate_accountability_boundary_nonbypass(
        accountability_result=dict(STEP185) if step185 is None else step185,
        boundary_enforcement_result=dict(STEP179) if step179 is None else step179,
        binding_record=dict(BINDING) if binding is None else binding,
        expected_scope_id=scope,
        expected_action_id=action,
        expected_object_hash=obj,
        caller_requested_decision="ADMISSIBLE",
    )


class Step186Tests(unittest.TestCase):
    def test_clean_composition_supportable(self):
        r = run()
        self.assertEqual(r["integration_standing"], INTEGRATION_SUPPORTABLE)
        self.assertEqual(r["integration_decision"], "ACCOUNTABILITY_BOUNDARY_PREREQUISITES_SUPPORTABLE")
        self.assertEqual(r["no_bind_state"], "SEPARATE_EXECUTION_TIME_REVALIDATION_REQUIRED")
        self.assertFalse(r["execution_authorized"])

    def test_step185_failure_blocks(self):
        s = dict(STEP185)
        s["accountability_continuity_standing"] = "ACCOUNTABILITY_CONTINUITY_NOT_ESTABLISHED"
        r = run(step185=s)
        self.assertEqual(r["integration_standing"], INTEGRATION_NOT_ESTABLISHED)
        self.assertIn("STEP_185_ACCOUNTABILITY_CONTINUITY_NOT_SUPPORTABLE", r["reasons"])

    def test_step179_failure_blocks(self):
        s = dict(STEP179)
        s["enforcement_decision"] = "NOT_ADMISSIBLE"
        s["no_bind_state"] = "ACTIVE"
        s["action_held"] = True
        r = run(step179=s)
        self.assertEqual(r["integration_standing"], INTEGRATION_NOT_ESTABLISHED)
        self.assertIn("STEP_179_BOUNDARY_DECISION_NOT_ADMISSIBLE", r["reasons"])

    def test_step185_scope_must_match_expected(self):
        s = dict(STEP185)
        s["declared_scope_id"] = "OTHER"
        r = run(step185=s)
        self.assertIn("STEP_185_DECLARED_SCOPE_MISMATCH", r["reasons"])

    def test_step179_object_must_match_expected(self):
        s = dict(STEP179)
        s["requested_object_hash"] = "sha256:other"
        r = run(step179=s)
        self.assertIn("STEP_179_REQUESTED_OBJECT_MISMATCH", r["reasons"])

    def test_binding_scope_mismatch_blocks(self):
        b = dict(BINDING)
        b["declared_scope_id"] = "OTHER"
        r = run(binding=b)
        self.assertIn("BINDING_SCOPE_MISMATCH", r["reasons"])
        self.assertIn("BINDING_SCOPE_DOES_NOT_MATCH_STEP_185_RESULT", r["reasons"])

    def test_binding_action_mismatch_blocks(self):
        b = dict(BINDING)
        b["action_id"] = "OTHER-ACTION"
        r = run(binding=b)
        self.assertIn("BINDING_ACTION_MISMATCH", r["reasons"])

    def test_binding_object_mismatch_blocks(self):
        b = dict(BINDING)
        b["object_hash"] = "sha256:other"
        r = run(binding=b)
        self.assertIn("BINDING_OBJECT_MISMATCH", r["reasons"])
        self.assertIn("BINDING_OBJECT_DOES_NOT_MATCH_STEP_179_RESULT", r["reasons"])

    def test_binding_must_be_traceable(self):
        b = dict(BINDING)
        b["binding_traceable"] = False
        self.assertIn("SCOPE_ACTION_OBJECT_BINDING_NOT_TRACEABLE", run(binding=b)["reasons"])

    def test_binding_must_be_current(self):
        b = dict(BINDING)
        b["binding_current"] = False
        self.assertIn("SCOPE_ACTION_OBJECT_BINDING_NOT_CURRENT", run(binding=b)["reasons"])

    def test_binding_ambiguity_blocks(self):
        b = dict(BINDING)
        b["binding_ambiguity_present"] = True
        self.assertIn("SCOPE_ACTION_OBJECT_BINDING_AMBIGUOUS_OR_INVALID", run(binding=b)["reasons"])

    def test_missing_binding_record_blocks(self):
        r = run(binding={})
        self.assertEqual(r["integration_standing"], INTEGRATION_NOT_ESTABLISHED)
        self.assertIn("BINDING_SCOPE_ID_MISSING_OR_INVALID", r["reasons"])

    def test_wrong_step185_revision_blocks(self):
        s = dict(STEP185)
        s["candidate_revision"] = "OTHER"
        self.assertIn("STEP_185_RESULT_REVISION_NOT_ESTABLISHED", run(step185=s)["reasons"])

    def test_step185_forged_authority_blocks(self):
        s = dict(STEP185)
        s["binding_authority_granted"] = True
        self.assertIn("STEP_185_AUTHORITY_BOUNDARY_INVALID", run(step185=s)["reasons"])

    def test_step179_forged_authority_blocks(self):
        s = dict(STEP179)
        s["binding_authority_granted"] = True
        self.assertIn("STEP_179_AUTHORITY_BOUNDARY_INVALID", run(step179=s)["reasons"])

    def test_step179_claimed_execution_blocks(self):
        s = dict(STEP179)
        s["physical_action_executed"] = True
        self.assertIn("STEP_179_PHYSICAL_ACTION_BOUNDARY_INVALID", run(step179=s)["reasons"])

    def test_missing_expected_scope_blocks(self):
        self.assertIn("EXPECTED_SCOPE_ID_MISSING_OR_INVALID", run(scope="")["reasons"])

    def test_missing_expected_action_blocks(self):
        self.assertIn("EXPECTED_ACTION_ID_MISSING_OR_INVALID", run(action="")["reasons"])

    def test_missing_expected_object_blocks(self):
        self.assertIn("EXPECTED_OBJECT_HASH_MISSING_OR_INVALID", run(obj="")["reasons"])

    def test_caller_override_rejected_when_blocked(self):
        b = dict(BINDING)
        b["binding_current"] = False
        self.assertTrue(run(binding=b)["caller_override_rejected"])

    def test_supportable_result_never_grants_execution_or_authority(self):
        r = run()
        self.assertFalse(r["binding_authority_granted"])
        self.assertFalse(r["action_admissibility_granted"])
        self.assertFalse(r["execution_authorized"])
        self.assertFalse(r["physical_action_executed"])
        self.assertFalse(r["irlt_mag_state_changed"])


if __name__ == "__main__":
    unittest.main()
