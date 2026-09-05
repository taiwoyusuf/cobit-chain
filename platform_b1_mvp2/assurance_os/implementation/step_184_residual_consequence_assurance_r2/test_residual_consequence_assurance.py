import unittest

from residual_consequence_assurance import evaluate_residual_consequence_assurance


CLOSED = "RESIDUAL_CONSEQUENCE_CLOSED_WITHIN_DECLARED_SCOPE"
NOT_ESTABLISHED = "RESIDUAL_CONSEQUENCE_STANDING_NOT_ESTABLISHED"
OPEN = "RESIDUAL_CONSEQUENCE_PRESENT_OR_OPEN"
CONTRADICTED = "RESIDUAL_CONSEQUENCE_CONTRADICTED"
CONTROL_OPEN = "CONSEQUENCE_CONTROL_CLOSURE_NOT_ESTABLISHED"

BASE_EXEC = {
    "execution_time_standing": "SUPPORTABLE",
    "execution_time_decision": "ADMISSIBLE",
    "no_bind_state": "INACTIVE",
    "binding_authority_granted": False,
    "prior_decision_preserved_as_history": True,
}
BASE_OUTCOME = {
    "correspondence_standing": "OUTCOME_CORRESPONDENCE_SUPPORTABLE",
    "commit_occurred": True,
    "execution_succeeded": True,
    "intended_outcome_established": True,
    "historical_facts": {"commit_occurred": True, "execution_succeeded": True},
    "no_bind_state": "INACTIVE",
    "binding_authority_granted": False,
}
BASE_RECLOSURE = {
    "reclosure_standing": "RECLOSURE_SUPPORTABLE",
    "return_to_reliance_supportable": True,
    "no_bind_state": "SEPARATE_AUTHORITY_AND_ACTION_ADMISSIBILITY_REQUIRED",
    "binding_authority_granted": False,
    "historical_facts_rewritten": False,
}
BASE_CONSEQUENCE = {
    "historical_event_preserved": True,
    "authority_current_at_irreversible_boundary": True,
    "irreversible_boundary_crossed": False,
    "stop_command_succeeded": False,
    "consequence_termination_observed": True,
    "partial_irreversible_consequence": False,
    "residual_propagation_active": False,
    "latent_consequence_window_open": False,
    "residual_effects_present": False,
    "current_physical_correspondence_established": True,
    "witness_proposition_qualified": True,
    "observation_current": True,
}
BASE_RACE_RETRY = {
    "active_competing_claim_count": 1,
    "single_winner_serialized": True,
    "losing_claims_retired": True,
    "retry_requested": False,
    "prior_attempt_consequence_state_known": True,
    "idempotency_identity_matches": True,
    "duplicate_consequence_prevention_established": True,
}
BASE_EVIDENCE = {
    "contradiction_present": False,
    "independent_failure_domains_established": True,
    "negative_evidence_basis_complete": True,
}
BASE_TEMPORAL = {
    "temporal_ordering_established": True,
    "material_change_assessment_complete": True,
    "material_change_after_reclosure": False,
    "reclosure_reevaluated_after_latest_material_change": False,
}


def evaluate(**overrides):
    consequence = dict(BASE_CONSEQUENCE)
    consequence.update(overrides.pop("consequence", {}))
    race_retry = dict(BASE_RACE_RETRY)
    race_retry.update(overrides.pop("race_retry", {}))
    evidence = dict(BASE_EVIDENCE)
    evidence.update(overrides.pop("evidence", {}))
    temporal = dict(BASE_TEMPORAL)
    temporal.update(overrides.pop("temporal", {}))
    return evaluate_residual_consequence_assurance(
        execution_time_result=overrides.pop("execution", dict(BASE_EXEC)),
        outcome_result=overrides.pop("outcome", dict(BASE_OUTCOME)),
        reclosure_result=overrides.pop("reclosure", dict(BASE_RECLOSURE)),
        consequence_state=consequence,
        race_retry_state=race_retry,
        evidence_state=evidence,
        temporal_state=temporal,
    )


class Step184ResidualConsequenceAssuranceR2Tests(unittest.TestCase):
    def test_clean_closure_is_supportable_but_nonbinding(self):
        r = evaluate()
        self.assertEqual(r["residual_consequence_standing"], CLOSED)
        self.assertTrue(r["return_to_reliance_supportable"])
        self.assertEqual(r["candidate_revision"], "STEP_184_R2")
        self.assertFalse(r["binding_authority_granted"])
        self.assertFalse(r["irlt_mag_state_changed"])

    def test_r2_requires_explicit_termination_even_without_stop(self):
        r = evaluate(consequence={"consequence_termination_observed": False})
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("CONSEQUENCE_TERMINATION_NOT_OBSERVED", r["reasons"])

    def test_stop_without_termination_preserves_stop_specific_reason_too(self):
        r = evaluate(consequence={
            "stop_command_succeeded": True,
            "consequence_termination_observed": False,
        })
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("CONSEQUENCE_TERMINATION_NOT_OBSERVED", r["reasons"])
        self.assertIn("STOP_SUCCESS_WITHOUT_CONSEQUENCE_TERMINATION_EVIDENCE", r["reasons"])

    def test_material_change_after_reclosure_requires_reclosure_reevaluation(self):
        r = evaluate(temporal={
            "material_change_after_reclosure": True,
            "reclosure_reevaluated_after_latest_material_change": False,
        })
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("RECLOSURE_BASIS_STALE_AFTER_MATERIAL_CHANGE", r["reasons"])

    def test_reclosure_reevaluation_after_material_change_restores_temporal_basis(self):
        r = evaluate(temporal={
            "material_change_after_reclosure": True,
            "reclosure_reevaluated_after_latest_material_change": True,
        })
        self.assertEqual(r["residual_consequence_standing"], CLOSED)

    def test_temporal_ordering_must_be_established(self):
        r = evaluate(temporal={"temporal_ordering_established": False})
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("TEMPORAL_ORDERING_NOT_ESTABLISHED", r["reasons"])

    def test_material_change_assessment_must_be_complete(self):
        r = evaluate(temporal={"material_change_assessment_complete": False})
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("MATERIAL_CHANGE_ASSESSMENT_INCOMPLETE", r["reasons"])

    def test_missing_temporal_ordering_fails_closed(self):
        temporal = dict(BASE_TEMPORAL)
        temporal.pop("temporal_ordering_established")
        r = evaluate_residual_consequence_assurance(
            execution_time_result=dict(BASE_EXEC),
            outcome_result=dict(BASE_OUTCOME),
            reclosure_result=dict(BASE_RECLOSURE),
            consequence_state=dict(BASE_CONSEQUENCE),
            race_retry_state=dict(BASE_RACE_RETRY),
            evidence_state=dict(BASE_EVIDENCE),
            temporal_state=temporal,
        )
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("TEMPORAL_TEMPORAL_ORDERING_ESTABLISHED_MISSING", r["reasons"])

    def test_missing_material_change_assessment_fails_closed(self):
        temporal = dict(BASE_TEMPORAL)
        temporal.pop("material_change_assessment_complete")
        r = evaluate_residual_consequence_assurance(
            execution_time_result=dict(BASE_EXEC),
            outcome_result=dict(BASE_OUTCOME),
            reclosure_result=dict(BASE_RECLOSURE),
            consequence_state=dict(BASE_CONSEQUENCE),
            race_retry_state=dict(BASE_RACE_RETRY),
            evidence_state=dict(BASE_EVIDENCE),
            temporal_state=temporal,
        )
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("TEMPORAL_MATERIAL_CHANGE_ASSESSMENT_COMPLETE_MISSING", r["reasons"])

    def test_missing_temporal_material_change_state_fails_closed(self):
        temporal = dict(BASE_TEMPORAL)
        temporal.pop("material_change_after_reclosure")
        r = evaluate_residual_consequence_assurance(
            execution_time_result=dict(BASE_EXEC),
            outcome_result=dict(BASE_OUTCOME),
            reclosure_result=dict(BASE_RECLOSURE),
            consequence_state=dict(BASE_CONSEQUENCE),
            race_retry_state=dict(BASE_RACE_RETRY),
            evidence_state=dict(BASE_EVIDENCE),
            temporal_state=temporal,
        )
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("TEMPORAL_MATERIAL_CHANGE_AFTER_RECLOSURE_MISSING", r["reasons"])

    def test_missing_reclosure_reevaluation_state_fails_closed(self):
        temporal = dict(BASE_TEMPORAL)
        temporal.pop("reclosure_reevaluated_after_latest_material_change")
        r = evaluate_residual_consequence_assurance(
            execution_time_result=dict(BASE_EXEC),
            outcome_result=dict(BASE_OUTCOME),
            reclosure_result=dict(BASE_RECLOSURE),
            consequence_state=dict(BASE_CONSEQUENCE),
            race_retry_state=dict(BASE_RACE_RETRY),
            evidence_state=dict(BASE_EVIDENCE),
            temporal_state=temporal,
        )
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("TEMPORAL_RECLOSURE_REEVALUATED_AFTER_LATEST_MATERIAL_CHANGE_MISSING", r["reasons"])

    def test_temporal_state_must_be_mapping(self):
        r = evaluate_residual_consequence_assurance(
            execution_time_result=dict(BASE_EXEC),
            outcome_result=dict(BASE_OUTCOME),
            reclosure_result=dict(BASE_RECLOSURE),
            consequence_state=dict(BASE_CONSEQUENCE),
            race_retry_state=dict(BASE_RACE_RETRY),
            evidence_state=dict(BASE_EVIDENCE),
            temporal_state=None,
        )
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("REQUIRED_INPUT_MAPPING_MISSING", r["reasons"])

    def test_partial_irreversible_consequence_remains_open(self):
        r = evaluate(consequence={"partial_irreversible_consequence": True})
        self.assertEqual(r["residual_consequence_standing"], OPEN)

    def test_residual_propagation_remains_open(self):
        r = evaluate(consequence={"residual_propagation_active": True})
        self.assertEqual(r["residual_consequence_standing"], OPEN)

    def test_latent_window_remains_open(self):
        r = evaluate(consequence={"latent_consequence_window_open": True})
        self.assertEqual(r["residual_consequence_standing"], OPEN)

    def test_contradiction_remains_preserved(self):
        r = evaluate(evidence={"contradiction_present": True})
        self.assertEqual(r["residual_consequence_standing"], CONTRADICTED)

    def test_failure_domain_independence_still_required(self):
        r = evaluate(evidence={"independent_failure_domains_established": False})
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)

    def test_competing_claims_still_require_serialization(self):
        r = evaluate(race_retry={
            "active_competing_claim_count": 2,
            "single_winner_serialized": False,
            "losing_claims_retired": False,
        })
        self.assertEqual(r["residual_consequence_standing"], CONTROL_OPEN)

    def test_retry_unknown_prior_state_still_blocks(self):
        r = evaluate(race_retry={
            "retry_requested": True,
            "prior_attempt_consequence_state_known": False,
        })
        self.assertEqual(r["residual_consequence_standing"], CONTROL_OPEN)

    def test_negative_evidence_basis_still_required(self):
        r = evaluate(evidence={"negative_evidence_basis_complete": False})
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)

    def test_upstream_nonauthority_contract_still_enforced(self):
        forged = dict(BASE_EXEC)
        forged["binding_authority_granted"] = True
        r = evaluate(execution=forged)
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)

    def test_reclosure_history_preservation_still_enforced(self):
        forged = dict(BASE_RECLOSURE)
        forged["historical_facts_rewritten"] = True
        r = evaluate(reclosure=forged)
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)

    def test_r2_never_grants_authority_on_blocked_result(self):
        r = evaluate(consequence={"consequence_termination_observed": False})
        self.assertFalse(r["binding_authority_granted"])
        self.assertTrue(r["action_hold_required"])
        self.assertEqual(r["no_bind_state"], "ACTIVE")

    def test_r2_never_grants_authority_on_clean_result(self):
        r = evaluate()
        self.assertFalse(r["binding_authority_granted"])
        self.assertEqual(r["no_bind_state"], "SEPARATE_AUTHORITY_AND_ACTION_ADMISSIBILITY_REQUIRED")

    def test_material_change_without_reclosure_recheck_blocks_despite_fresh_termination(self):
        r = evaluate(
            consequence={"consequence_termination_observed": True, "observation_current": True},
            temporal={
                "material_change_after_reclosure": True,
                "reclosure_reevaluated_after_latest_material_change": False,
            },
        )
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("RECLOSURE_BASIS_STALE_AFTER_MATERIAL_CHANGE", r["reasons"])


if __name__ == "__main__":
    unittest.main()
