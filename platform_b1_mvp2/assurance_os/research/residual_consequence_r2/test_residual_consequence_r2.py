import unittest

from residual_consequence_r2 import DOMAINS, evaluate_trace


CLOSED = "RESIDUAL_CONSEQUENCE_CLOSED_WITHIN_DECLARED_SCOPE"
NOT_ESTABLISHED = "RESIDUAL_CONSEQUENCE_STANDING_NOT_ESTABLISHED"
CONTRADICTED = "RESIDUAL_CONSEQUENCE_CONTRADICTED"
OPEN = "RESIDUAL_CONSEQUENCE_PRESENT_OR_OPEN"
CONTROL_OPEN = "CONSEQUENCE_CONTROL_CLOSURE_NOT_ESTABLISHED"


def trace(domain="RADIOPHARMA", **overrides):
    base = {
        "domain": domain,
        "events": [{"sequence": 1, "kind": "OBSERVATION"}],
        "consequence_termination_observed": True,
    }
    base.update(overrides)
    return base


class ResidualConsequenceR2Tests(unittest.TestCase):
    def test_baseline_trace_closes_nonbinding(self):
        r = evaluate_trace(trace())["r1_result"]
        self.assertEqual(r["residual_consequence_standing"], CLOSED)
        self.assertTrue(r["return_to_reliance_supportable"])
        self.assertFalse(r["binding_authority_granted"])

    def test_observation_before_stop_is_stale(self):
        r = evaluate_trace(trace(events=[
            {"sequence": 1, "kind": "OBSERVATION"},
            {"sequence": 2, "kind": "STOP"},
        ]))["r1_result"]
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("CONSEQUENCE_OBSERVATION_NOT_CURRENT", r["reasons"])

    def test_observation_after_stop_can_close_if_termination_observed(self):
        r = evaluate_trace(trace(events=[
            {"sequence": 1, "kind": "STOP"},
            {"sequence": 2, "kind": "OBSERVATION"},
        ]))["r1_result"]
        self.assertEqual(r["residual_consequence_standing"], CLOSED)

    def test_material_change_after_observation_invalidates_freshness(self):
        r = evaluate_trace(trace(events=[
            {"sequence": 1, "kind": "OBSERVATION"},
            {"sequence": 2, "kind": "MATERIAL_CHANGE"},
        ]))["r1_result"]
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("CONSEQUENCE_OBSERVATION_NOT_CURRENT", r["reasons"])

    def test_reobservation_after_material_change_restores_freshness_basis(self):
        r = evaluate_trace(trace(events=[
            {"sequence": 1, "kind": "OBSERVATION"},
            {"sequence": 2, "kind": "MATERIAL_CHANGE"},
            {"sequence": 3, "kind": "OBSERVATION"},
        ]))["r1_result"]
        self.assertEqual(r["residual_consequence_standing"], CLOSED)

    def test_latent_window_is_monotonic_block(self):
        r = evaluate_trace(trace(latent_consequence_window_open=True))["r1_result"]
        self.assertEqual(r["residual_consequence_standing"], OPEN)
        self.assertIn("LATENT_CONSEQUENCE_WINDOW_OPEN", r["reasons"])

    def test_independent_contradiction_cannot_improve_standing(self):
        clean = evaluate_trace(trace())["r1_result"]
        contradicted = evaluate_trace(trace(contradiction_present=True))["r1_result"]
        self.assertEqual(clean["residual_consequence_standing"], CLOSED)
        self.assertEqual(contradicted["residual_consequence_standing"], CONTRADICTED)
        self.assertFalse(contradicted["return_to_reliance_supportable"])

    def test_failure_domain_collapse_blocks_corrobation(self):
        r = evaluate_trace(trace(independent_failure_domains_established=False))["r1_result"]
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("WITNESS_FAILURE_DOMAIN_INDEPENDENCE_NOT_ESTABLISHED", r["reasons"])

    def test_claim_order_does_not_change_race_result(self):
        claims_a = [
            {"claim_id": "A", "active": True},
            {"claim_id": "B", "active": True},
        ]
        claims_b = list(reversed(claims_a))
        kwargs = {"single_winner_serialized": False, "losing_claims_retired": False}
        r1 = evaluate_trace(trace(claims=claims_a, **kwargs))["r1_result"]
        r2 = evaluate_trace(trace(claims=claims_b, **kwargs))["r1_result"]
        self.assertEqual(r1["residual_consequence_standing"], CONTROL_OPEN)
        self.assertEqual(r1["reasons"], r2["reasons"])

    def test_retry_unknown_prior_state_blocks_in_every_domain(self):
        for domain in sorted(DOMAINS):
            with self.subTest(domain=domain):
                r = evaluate_trace(trace(
                    domain=domain,
                    retry_requested=True,
                    prior_attempt_consequence_state_known=False,
                ))["r1_result"]
                self.assertEqual(r["residual_consequence_standing"], CONTROL_OPEN)
                self.assertIn("PRIOR_ATTEMPT_CONSEQUENCE_STATE_UNKNOWN", r["reasons"])

    def test_cross_domain_semantics_are_identical_for_same_vector(self):
        states = set()
        reasons = set()
        for domain in sorted(DOMAINS):
            r = evaluate_trace(trace(
                domain=domain,
                residual_propagation_active=True,
                events=[
                    {"sequence": 1, "kind": "STOP"},
                    {"sequence": 2, "kind": "OBSERVATION"},
                ],
            ))["r1_result"]
            states.add(r["residual_consequence_standing"])
            reasons.add(tuple(r["reasons"]))
        self.assertEqual(states, {OPEN})
        self.assertEqual(len(reasons), 1)

    def test_domain_label_does_not_manufacture_authority(self):
        for domain in sorted(DOMAINS):
            with self.subTest(domain=domain):
                r = evaluate_trace(trace(domain=domain))["r1_result"]
                self.assertFalse(r["binding_authority_granted"])
                self.assertEqual(
                    r["no_bind_state"],
                    "SEPARATE_AUTHORITY_AND_ACTION_ADMISSIBILITY_REQUIRED",
                )

    def test_partial_irreversible_consequence_remains_open_after_stop(self):
        r = evaluate_trace(trace(
            partial_irreversible_consequence=True,
            events=[
                {"sequence": 1, "kind": "STOP"},
                {"sequence": 2, "kind": "OBSERVATION"},
            ],
        ))["r1_result"]
        self.assertEqual(r["residual_consequence_standing"], OPEN)

    def test_negative_evidence_basis_incomplete_blocks_absence_claim(self):
        r = evaluate_trace(trace(negative_evidence_basis_complete=False))["r1_result"]
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("NEGATIVE_EVIDENCE_BASIS_NOT_ESTABLISHED", r["reasons"])

    def test_forged_upstream_authority_is_rejected(self):
        r = evaluate_trace(trace(
            execution_overrides={"binding_authority_granted": True}
        ))["r1_result"]
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("EXECUTION_TIME_NONAUTHORITY_CONTRACT_NOT_ESTABLISHED", r["reasons"])

    def test_invalid_domain_is_rejected_before_r1(self):
        with self.assertRaises(ValueError):
            evaluate_trace(trace(domain="UNDECLARED_DOMAIN"))

    def test_duplicate_event_sequence_is_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_trace(trace(events=[
                {"sequence": 1, "kind": "STOP"},
                {"sequence": 1, "kind": "OBSERVATION"},
            ]))


if __name__ == "__main__":
    unittest.main()
