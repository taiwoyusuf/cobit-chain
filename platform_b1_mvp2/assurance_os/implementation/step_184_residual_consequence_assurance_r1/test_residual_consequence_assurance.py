import unittest

from residual_consequence_assurance import evaluate_residual_consequence_assurance


BASE_EXEC = {"execution_time_standing": "SUPPORTABLE"}
BASE_OUTCOME = {"correspondence_standing": "OUTCOME_CORRESPONDENCE_SUPPORTABLE"}
BASE_RECLOSURE = {"reclosure_standing": "RECLOSURE_SUPPORTABLE"}
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


def evaluate(**overrides):
    consequence = dict(BASE_CONSEQUENCE)
    consequence.update(overrides.pop("consequence", {}))
    race_retry = dict(BASE_RACE_RETRY)
    race_retry.update(overrides.pop("race_retry", {}))
    evidence = dict(BASE_EVIDENCE)
    evidence.update(overrides.pop("evidence", {}))
    return evaluate_residual_consequence_assurance(
        execution_time_result=overrides.pop("execution", BASE_EXEC),
        outcome_result=overrides.pop("outcome", BASE_OUTCOME),
        reclosure_result=overrides.pop("reclosure", BASE_RECLOSURE),
        consequence_state=consequence,
        race_retry_state=race_retry,
        evidence_state=evidence,
    )


class Step184ResidualConsequenceAssuranceTests(unittest.TestCase):
    def test_clean_closure_is_supportable_but_nonbinding(self):
        r = evaluate()
        self.assertEqual(r["residual_consequence_standing"], "RESIDUAL_CONSEQUENCE_CLOSED_WITHIN_DECLARED_SCOPE")
        self.assertTrue(r["return_to_reliance_supportable"])
        self.assertEqual(r["no_bind_state"], "SEPARATE_AUTHORITY_AND_ACTION_ADMISSIBILITY_REQUIRED")
        self.assertFalse(r["binding_authority_granted"])
        self.assertFalse(r["irlt_mag_state_changed"])

    def test_revocation_at_irreversible_boundary_blocks_closure(self):
        r = evaluate(consequence={"irreversible_boundary_crossed": True, "authority_current_at_irreversible_boundary": False})
        self.assertEqual(r["residual_consequence_standing"], "RESIDUAL_CONSEQUENCE_STANDING_NOT_ESTABLISHED")
        self.assertIn("AUTHORITY_NOT_CURRENT_AT_IRREVERSIBLE_BOUNDARY", r["reasons"])

    def test_stop_success_without_termination_evidence_blocks_closure(self):
        r = evaluate(consequence={"stop_command_succeeded": True, "consequence_termination_observed": False})
        self.assertEqual(r["residual_consequence_standing"], "RESIDUAL_CONSEQUENCE_STANDING_NOT_ESTABLISHED")
        self.assertIn("STOP_SUCCESS_WITHOUT_CONSEQUENCE_TERMINATION_EVIDENCE", r["reasons"])

    def test_partial_irreversible_consequence_remains_open(self):
        r = evaluate(consequence={"partial_irreversible_consequence": True})
        self.assertEqual(r["residual_consequence_standing"], "RESIDUAL_CONSEQUENCE_PRESENT_OR_OPEN")

    def test_residual_propagation_after_stop_remains_open(self):
        r = evaluate(consequence={"stop_command_succeeded": True, "residual_propagation_active": True})
        self.assertEqual(r["residual_consequence_standing"], "RESIDUAL_CONSEQUENCE_PRESENT_OR_OPEN")
        self.assertIn("RESIDUAL_PROPAGATION_ACTIVE", r["reasons"])

    def test_latent_window_blocks_premature_reclosure(self):
        r = evaluate(consequence={"latent_consequence_window_open": True})
        self.assertEqual(r["residual_consequence_standing"], "RESIDUAL_CONSEQUENCE_PRESENT_OR_OPEN")

    def test_digital_physical_contradiction_is_preserved(self):
        r = evaluate(evidence={"contradiction_present": True})
        self.assertEqual(r["residual_consequence_standing"], "RESIDUAL_CONSEQUENCE_CONTRADICTED")

    def test_shared_failure_domain_blocks_independence(self):
        r = evaluate(evidence={"independent_failure_domains_established": False})
        self.assertEqual(r["residual_consequence_standing"], "RESIDUAL_CONSEQUENCE_STANDING_NOT_ESTABLISHED")
        self.assertIn("WITNESS_FAILURE_DOMAIN_INDEPENDENCE_NOT_ESTABLISHED", r["reasons"])

    def test_competing_claims_require_serialization(self):
        r = evaluate(race_retry={
            "active_competing_claim_count": 2,
            "single_winner_serialized": False,
            "losing_claims_retired": False,
        })
        self.assertEqual(r["residual_consequence_standing"], "CONSEQUENCE_CONTROL_CLOSURE_NOT_ESTABLISHED")
        self.assertIn("COMPETING_EXECUTION_CLAIMS_NOT_SERIALIZED", r["reasons"])

    def test_retry_requires_known_prior_consequence_and_idempotency(self):
        r = evaluate(race_retry={
            "retry_requested": True,
            "prior_attempt_consequence_state_known": False,
            "idempotency_identity_matches": False,
            "duplicate_consequence_prevention_established": False,
        })
        self.assertEqual(r["residual_consequence_standing"], "CONSEQUENCE_CONTROL_CLOSURE_NOT_ESTABLISHED")
        self.assertIn("PRIOR_ATTEMPT_CONSEQUENCE_STATE_UNKNOWN", r["reasons"])
        self.assertIn("DUPLICATE_CONSEQUENCE_PREVENTION_NOT_ESTABLISHED", r["reasons"])

    def test_prior_outcome_must_be_supportable(self):
        r = evaluate(outcome={"correspondence_standing": "OUTCOME_DIVERGED"})
        self.assertEqual(r["residual_consequence_standing"], "RESIDUAL_CONSEQUENCE_STANDING_NOT_ESTABLISHED")
        self.assertIn("OUTCOME_CORRESPONDENCE_NOT_SUPPORTABLE", r["reasons"])

    def test_negative_evidence_basis_must_be_complete(self):
        r = evaluate(evidence={"negative_evidence_basis_complete": False})
        self.assertEqual(r["residual_consequence_standing"], "RESIDUAL_CONSEQUENCE_STANDING_NOT_ESTABLISHED")
        self.assertIn("NEGATIVE_EVIDENCE_BASIS_NOT_ESTABLISHED", r["reasons"])


if __name__ == "__main__":
    unittest.main()
