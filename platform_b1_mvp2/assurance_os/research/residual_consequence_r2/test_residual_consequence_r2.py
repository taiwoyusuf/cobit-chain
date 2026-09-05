import unittest

from residual_consequence_r2 import DOMAINS, evaluate_trace, evaluate_trace_raw_r1


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


def r2_result(t):
    return evaluate_trace(t)["r2_result"]


def raw_result(t):
    return evaluate_trace_raw_r1(t)["r1_result"]


class ResidualConsequenceR2Tests(unittest.TestCase):
    def test_baseline_trace_closes_nonbinding(self):
        r = r2_result(trace())
        self.assertEqual(r["residual_consequence_standing"], CLOSED)
        self.assertTrue(r["return_to_reliance_supportable"])
        self.assertFalse(r["binding_authority_granted"])

    def test_observation_before_stop_is_stale(self):
        r = r2_result(trace(events=[
            {"sequence": 1, "kind": "OBSERVATION"},
            {"sequence": 2, "kind": "STOP"},
        ]))
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("CONSEQUENCE_OBSERVATION_NOT_CURRENT", r["reasons"])

    def test_observation_after_stop_can_close_if_termination_observed(self):
        r = r2_result(trace(events=[
            {"sequence": 1, "kind": "STOP"},
            {"sequence": 2, "kind": "OBSERVATION"},
        ]))
        self.assertEqual(r["residual_consequence_standing"], CLOSED)

    def test_material_change_after_observation_invalidates_freshness(self):
        r = r2_result(trace(events=[
            {"sequence": 1, "kind": "OBSERVATION"},
            {"sequence": 2, "kind": "MATERIAL_CHANGE"},
        ]))
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("CONSEQUENCE_OBSERVATION_NOT_CURRENT", r["reasons"])

    def test_reobservation_after_material_change_restores_freshness_basis(self):
        r = r2_result(trace(events=[
            {"sequence": 1, "kind": "OBSERVATION"},
            {"sequence": 2, "kind": "MATERIAL_CHANGE"},
            {"sequence": 3, "kind": "OBSERVATION"},
        ]))
        self.assertEqual(r["residual_consequence_standing"], CLOSED)

    def test_latent_window_is_monotonic_block(self):
        r = r2_result(trace(latent_consequence_window_open=True))
        self.assertEqual(r["residual_consequence_standing"], OPEN)
        self.assertIn("LATENT_CONSEQUENCE_WINDOW_OPEN", r["reasons"])

    def test_independent_contradiction_cannot_improve_standing(self):
        clean = r2_result(trace())
        contradicted = r2_result(trace(contradiction_present=True))
        self.assertEqual(clean["residual_consequence_standing"], CLOSED)
        self.assertEqual(contradicted["residual_consequence_standing"], CONTRADICTED)
        self.assertFalse(contradicted["return_to_reliance_supportable"])

    def test_failure_domain_collapse_blocks_corrobation(self):
        r = r2_result(trace(independent_failure_domains_established=False))
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("WITNESS_FAILURE_DOMAIN_INDEPENDENCE_NOT_ESTABLISHED", r["reasons"])

    def test_claim_order_does_not_change_race_result(self):
        claims_a = [
            {"claim_id": "A", "active": True},
            {"claim_id": "B", "active": True},
        ]
        claims_b = list(reversed(claims_a))
        kwargs = {"single_winner_serialized": False, "losing_claims_retired": False}
        r1 = r2_result(trace(claims=claims_a, **kwargs))
        r2 = r2_result(trace(claims=claims_b, **kwargs))
        self.assertEqual(r1["residual_consequence_standing"], CONTROL_OPEN)
        self.assertEqual(r1["reasons"], r2["reasons"])

    def test_retry_unknown_prior_state_blocks_in_every_domain(self):
        for domain in sorted(DOMAINS):
            with self.subTest(domain=domain):
                r = r2_result(trace(
                    domain=domain,
                    retry_requested=True,
                    prior_attempt_consequence_state_known=False,
                ))
                self.assertEqual(r["residual_consequence_standing"], CONTROL_OPEN)
                self.assertIn("PRIOR_ATTEMPT_CONSEQUENCE_STATE_UNKNOWN", r["reasons"])

    def test_cross_domain_semantics_are_identical_for_same_vector(self):
        states = set()
        reasons = set()
        for domain in sorted(DOMAINS):
            r = r2_result(trace(
                domain=domain,
                residual_propagation_active=True,
                events=[
                    {"sequence": 1, "kind": "STOP"},
                    {"sequence": 2, "kind": "OBSERVATION"},
                ],
            ))
            states.add(r["residual_consequence_standing"])
            reasons.add(tuple(r["reasons"]))
        self.assertEqual(states, {OPEN})
        self.assertEqual(len(reasons), 1)

    def test_domain_label_does_not_manufacture_authority(self):
        for domain in sorted(DOMAINS):
            with self.subTest(domain=domain):
                r = r2_result(trace(domain=domain))
                self.assertFalse(r["binding_authority_granted"])
                self.assertEqual(
                    r["no_bind_state"],
                    "SEPARATE_AUTHORITY_AND_ACTION_ADMISSIBILITY_REQUIRED",
                )

    def test_partial_irreversible_consequence_remains_open_after_stop(self):
        r = r2_result(trace(
            partial_irreversible_consequence=True,
            events=[
                {"sequence": 1, "kind": "STOP"},
                {"sequence": 2, "kind": "OBSERVATION"},
            ],
        ))
        self.assertEqual(r["residual_consequence_standing"], OPEN)

    def test_negative_evidence_basis_incomplete_blocks_absence_claim(self):
        r = r2_result(trace(negative_evidence_basis_complete=False))
        self.assertEqual(r["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("NEGATIVE_EVIDENCE_BASIS_NOT_ESTABLISHED", r["reasons"])

    def test_forged_upstream_authority_is_rejected(self):
        r = r2_result(trace(
            execution_overrides={"binding_authority_granted": True}
        ))
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

    def test_r1_gap_closes_without_explicit_termination_when_no_stop(self):
        t = trace(consequence_termination_observed=False)
        raw = raw_result(t)
        guarded = r2_result(t)
        self.assertEqual(raw["residual_consequence_standing"], CLOSED)
        self.assertTrue(raw["return_to_reliance_supportable"])
        self.assertEqual(guarded["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("CONSEQUENCE_TERMINATION_NOT_OBSERVED", guarded["reasons"])
        self.assertFalse(guarded["return_to_reliance_supportable"])

    def test_r2_requires_explicit_termination_in_every_domain_without_stop(self):
        for domain in sorted(DOMAINS):
            with self.subTest(domain=domain):
                guarded = r2_result(trace(
                    domain=domain,
                    consequence_termination_observed=False,
                ))
                self.assertEqual(guarded["residual_consequence_standing"], NOT_ESTABLISHED)
                self.assertIn("CONSEQUENCE_TERMINATION_NOT_OBSERVED", guarded["reasons"])

    def test_r1_gap_accepts_stale_reclosure_after_material_change(self):
        t = trace(events=[
            {"sequence": 1, "kind": "RECLOSURE_EVALUATED"},
            {"sequence": 2, "kind": "MATERIAL_CHANGE"},
            {"sequence": 3, "kind": "OBSERVATION"},
        ])
        raw = raw_result(t)
        guarded = r2_result(t)
        self.assertEqual(raw["residual_consequence_standing"], CLOSED)
        self.assertEqual(guarded["residual_consequence_standing"], NOT_ESTABLISHED)
        self.assertIn("RECLOSURE_BASIS_STALE_AFTER_MATERIAL_CHANGE", guarded["reasons"])

    def test_reclosure_re_evaluated_after_material_change_can_close(self):
        guarded = r2_result(trace(events=[
            {"sequence": 1, "kind": "RECLOSURE_EVALUATED"},
            {"sequence": 2, "kind": "MATERIAL_CHANGE"},
            {"sequence": 3, "kind": "OBSERVATION"},
            {"sequence": 4, "kind": "RECLOSURE_EVALUATED"},
        ]))
        self.assertEqual(guarded["residual_consequence_standing"], CLOSED)

    def test_r2_guard_never_upgrades_blocked_r1_result(self):
        t = trace(
            contradiction_present=True,
            consequence_termination_observed=False,
        )
        raw = raw_result(t)
        guarded = r2_result(t)
        self.assertEqual(raw["residual_consequence_standing"], CONTRADICTED)
        self.assertEqual(guarded["residual_consequence_standing"], CONTRADICTED)
        self.assertFalse(guarded["return_to_reliance_supportable"])
        self.assertIn("CONSEQUENCE_TERMINATION_NOT_OBSERVED", guarded["reasons"])


if __name__ == "__main__":
    unittest.main()
