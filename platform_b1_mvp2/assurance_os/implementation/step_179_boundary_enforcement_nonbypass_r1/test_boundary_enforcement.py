import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMPLEMENTATION_ROOT = HERE.parent


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


step178 = load_module(
    "step178_boundary_assurance",
    IMPLEMENTATION_ROOT / "step_178_boundary_assurance_invariants_r1" / "boundary_assurance.py",
)
step170_authority = load_module(
    "step170_authority_no_bind",
    IMPLEMENTATION_ROOT / "step_170_assurance_os_integrated_runtime" / "src" / "authority_no_bind.py",
)
step179 = load_module("step179_boundary_enforcement", HERE / "boundary_enforcement.py")


def valid_authority():
    return step170_authority.evaluate_authority({
        "authority_present": True,
        "authority_valid": True,
        "authority_current": True,
        "authority_delegated": True,
        "approver_available": True,
        "escalation_available": True,
        "evidence_sufficient": True,
        "timing_valid": True,
        "human_accountability_identified": True,
    })


def valid_boundaries():
    return {
        "control_capacity": step178.evaluate_assurance_control_capacity(
            peak_demand=10,
            available_capacity=20,
            queue_delay_ms=10,
            enforcement_deadline_ms=100,
        ),
        "epistemic_class": step178.preserve_epistemic_class(
            source_class="MEASURED",
            claimed_class="MEASURED",
            transformation_documented=False,
        ),
        "processing_authority": step178.evaluate_processing_authority(
            human_access_authorized=True,
            machine_processing_authorized=True,
            purpose_authorized=True,
            destination_authorized=True,
            retention_authorized=True,
        ),
        "disposition": step178.evaluate_disposition_standing(
            condition_detected=False,
            owner_resolved=False,
            deadline_defined=False,
            interim_posture_defined=False,
            escalation_defined=False,
            closure_evidence_present=False,
        ),
    }


def valid_capsule(object_hash="sha256:object-a"):
    return step178.create_boundary_assurance_capsule(
        action_id="ACTION-001",
        object_hash=object_hash,
        criteria_version="CRIT-1",
        evidence_refs=["EV-1"],
        authority_snapshot="AUTH-SNAPSHOT-1",
        standing="SUPPORTABLE",
        unresolved_conditions=[],
        determination="ADMISSIBLE",
        committed_object_hash=object_hash,
    )


class BoundaryEnforcementIntegrationTests(unittest.TestCase):
    def evaluate(self, **overrides):
        params = {
            "authority_result": valid_authority(),
            "boundary_results": valid_boundaries(),
            "capsule": valid_capsule(),
            "requested_object_hash": "sha256:object-a",
            "caller_requested_decision": "ADMISSIBLE",
        }
        params.update(overrides)
        return step179.enforce_boundary_decision(**params)

    def test_all_supportable_inputs_can_reach_admissible(self):
        result = self.evaluate()
        self.assertEqual(result["enforcement_decision"], "ADMISSIBLE")
        self.assertEqual(result["no_bind_state"], "INACTIVE")
        self.assertFalse(result["action_held"])

    def test_caller_cannot_override_capacity_failure(self):
        boundaries = valid_boundaries()
        boundaries["control_capacity"] = step178.evaluate_assurance_control_capacity(
            peak_demand=100,
            available_capacity=10,
            queue_delay_ms=500,
            enforcement_deadline_ms=100,
        )
        result = self.evaluate(boundary_results=boundaries)
        self.assertEqual(result["enforcement_decision"], "NOT_ADMISSIBLE")
        self.assertTrue(result["caller_override_rejected"])

    def test_valid_authority_cannot_override_processing_authority_failure(self):
        boundaries = valid_boundaries()
        boundaries["processing_authority"] = step178.evaluate_processing_authority(
            human_access_authorized=True,
            machine_processing_authorized=False,
            purpose_authorized=True,
            destination_authorized=True,
            retention_authorized=True,
        )
        result = self.evaluate(boundary_results=boundaries)
        self.assertEqual(result["no_bind_state"], "ACTIVE")
        self.assertIn("PROCESSING_AUTHORITY_FAIL_CLOSED", result["reasons"])

    def test_silent_epistemic_upgrade_cannot_be_bypassed(self):
        boundaries = valid_boundaries()
        boundaries["epistemic_class"] = step178.preserve_epistemic_class(
            source_class="INFERRED",
            claimed_class="MEASURED",
            transformation_documented=False,
        )
        result = self.evaluate(boundary_results=boundaries)
        self.assertEqual(result["enforcement_decision"], "NOT_ADMISSIBLE")

    def test_open_disposition_condition_blocks_action(self):
        boundaries = valid_boundaries()
        boundaries["disposition"] = step178.evaluate_disposition_standing(
            condition_detected=True,
            owner_resolved=True,
            deadline_defined=True,
            interim_posture_defined=True,
            escalation_defined=True,
            closure_evidence_present=False,
        )
        result = self.evaluate(boundary_results=boundaries)
        self.assertIn("DISPOSITION_FAIL_CLOSED", result["reasons"])

    def test_no_detected_condition_does_not_create_artificial_block(self):
        result = self.evaluate()
        self.assertEqual(result["enforcement_decision"], "ADMISSIBLE")

    def test_missing_boundary_result_fails_closed(self):
        boundaries = valid_boundaries()
        del boundaries["processing_authority"]
        result = self.evaluate(boundary_results=boundaries)
        self.assertIn("PROCESSING_AUTHORITY_RESULT_MISSING", result["reasons"])
        self.assertTrue(result["action_held"])

    def test_evaluated_to_committed_object_substitution_is_blocked(self):
        capsule = step178.create_boundary_assurance_capsule(
            action_id="ACTION-001",
            object_hash="sha256:object-a",
            criteria_version="CRIT-1",
            evidence_refs=["EV-1"],
            authority_snapshot="AUTH-SNAPSHOT-1",
            standing="SUPPORTABLE",
            unresolved_conditions=[],
            determination="ADMISSIBLE",
            committed_object_hash="sha256:object-b",
        )
        result = self.evaluate(capsule=capsule)
        self.assertEqual(result["enforcement_decision"], "NOT_ADMISSIBLE")
        self.assertIn("BOUNDARY_CAPSULE_NOT_SUPPORTABLE", result["reasons"])

    def test_requested_object_must_match_frozen_capsule(self):
        result = self.evaluate(requested_object_hash="sha256:object-b")
        self.assertIn("REQUESTED_OBJECT_DIFFERS_FROM_EVALUATED_OBJECT", result["reasons"])
        self.assertTrue(result["caller_override_rejected"])

    def test_step170_authority_failure_still_blocks_when_step178_is_green(self):
        authority = valid_authority()
        authority["authority_valid"] = False
        authority["no_bind_state"] = "ACTIVE"
        result = self.evaluate(authority_result=authority)
        self.assertIn("AUTHORITY_NOT_VERIFIED", result["reasons"])
        self.assertEqual(result["no_bind_state"], "ACTIVE")

    def test_partial_recovery_cannot_be_claimed_as_recovered(self):
        recovery = step178.evaluate_recovery_standing(
            execution_stopped=True,
            internal_state_reversed=True,
            escaped_consequence=True,
            downstream_reliance_known=False,
            remediation_complete=False,
        )
        result = self.evaluate(consequence_mode="RECOVERY", recovery_result=recovery)
        self.assertIn("RECOVERY_STANDING_NOT_ESTABLISHED", result["reasons"])
        self.assertEqual(result["enforcement_decision"], "NOT_ADMISSIBLE")

    def test_recovery_mode_accepts_only_declared_scope_recovery(self):
        recovery = step178.evaluate_recovery_standing(
            execution_stopped=True,
            internal_state_reversed=True,
            escaped_consequence=True,
            downstream_reliance_known=True,
            remediation_complete=True,
        )
        result = self.evaluate(consequence_mode="RECOVERY", recovery_result=recovery)
        self.assertEqual(result["enforcement_decision"], "ADMISSIBLE")


if __name__ == "__main__":
    unittest.main()
