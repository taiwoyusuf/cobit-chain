import unittest

from accountability_postcommit_correspondence_nonbypass import canonical_digest
from accountability_postcommit_correspondence_nonbypass_hardened import (
    evaluate_accountability_postcommit_correspondence_nonbypass_hardened,
    event_lineage_payload,
)
from test_accountability_postcommit_correspondence_nonbypass import (
    bundles,
    postcommit_binding,
)


def hardened_run(mutator=None):
    s188_inputs, s188_result, s182_inputs, s182_result = bundles()

    commit = s182_inputs["commit_receipt"]
    execution = s182_inputs["execution_receipt"]
    outcome = s182_inputs["outcome_evidence"]

    commit["event_sequence"] = 10
    execution.update({
        "execution_event_id": "EXEC-EVENT-001",
        "source_commit_event_id": commit["commit_event_id"],
        "commit_token_id": commit["commit_token_id"],
        "event_sequence": 20,
    })
    outcome.update({
        "outcome_observation_id": "OUTCOME-OBS-001",
        "source_execution_event_id": execution["execution_event_id"],
        "source_commit_event_id": commit["commit_event_id"],
        "event_sequence": 30,
    })

    # Reproduce Step 182 after adding lineage-only fields; Step 182 ignores these
    # additional fields but its input-bundle digest in Step 189 must bind them.
    import importlib.util
    from pathlib import Path
    here = Path(__file__).resolve().parent
    p = here.parent / "step_182_commit_execution_outcome_correspondence_r1" / "commit_execution_outcome_correspondence.py"
    spec = importlib.util.spec_from_file_location("step189_hardening_step182", p)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    s182_result = module.evaluate_commit_execution_outcome_correspondence(**s182_inputs)

    if mutator:
        mutator(s188_inputs, s188_result, s182_inputs, s182_result)

    binding = postcommit_binding(s188_inputs, s188_result, s182_inputs, s182_result)
    commit = s182_inputs["commit_receipt"]
    execution = s182_inputs["execution_receipt"]
    outcome = s182_inputs["outcome_evidence"]
    binding.update({
        "commit_event_id": commit.get("commit_event_id"),
        "execution_event_id": execution.get("execution_event_id"),
        "outcome_observation_id": outcome.get("outcome_observation_id"),
        "event_lineage_digest": canonical_digest(event_lineage_payload(
            commit_receipt=commit,
            execution_receipt=execution,
            outcome_evidence=outcome,
        )),
    })

    return evaluate_accountability_postcommit_correspondence_nonbypass_hardened(
        step188_inputs=s188_inputs,
        step188_result=s188_result,
        step182_inputs=s182_inputs,
        step182_result=s182_result,
        postcommit_binding_record=binding,
    )


class Step189HardeningTests(unittest.TestCase):
    def test_clean_exact_event_lineage_supportable(self):
        r = hardened_run()
        self.assertTrue(r["event_lineage_correspondence_supportable"])
        self.assertTrue(r["sr_189_01_closed"])
        self.assertEqual(r["reasons"], [])

    def test_execution_must_link_exact_commit_event(self):
        def mutate(_, __, i182, ___):
            i182["execution_receipt"]["source_commit_event_id"] = "OTHER-COMMIT"
        r = hardened_run(mutate)
        self.assertIn("EXECUTION_NOT_LINKED_TO_EXACT_COMMIT_EVENT", r["reasons"])

    def test_execution_must_link_exact_commit_token(self):
        def mutate(_, __, i182, ___):
            i182["execution_receipt"]["commit_token_id"] = "OTHER-TOKEN"
        r = hardened_run(mutate)
        self.assertIn("EXECUTION_NOT_LINKED_TO_EXACT_COMMIT_TOKEN", r["reasons"])

    def test_outcome_must_link_exact_execution_event(self):
        def mutate(_, __, i182, ___):
            i182["outcome_evidence"]["source_execution_event_id"] = "OTHER-EXEC"
        r = hardened_run(mutate)
        self.assertIn("OUTCOME_NOT_LINKED_TO_EXACT_EXECUTION_EVENT", r["reasons"])

    def test_outcome_must_link_exact_commit_event(self):
        def mutate(_, __, i182, ___):
            i182["outcome_evidence"]["source_commit_event_id"] = "OTHER-COMMIT"
        r = hardened_run(mutate)
        self.assertIn("OUTCOME_NOT_LINKED_TO_EXACT_COMMIT_EVENT", r["reasons"])

    def test_event_order_must_be_commit_execution_outcome(self):
        def mutate(_, __, i182, ___):
            i182["execution_receipt"]["event_sequence"] = 5
        r = hardened_run(mutate)
        self.assertIn("EVENT_LINEAGE_ORDERING_NOT_ESTABLISHED", r["reasons"])

    def test_missing_execution_event_id_fails_closed(self):
        def mutate(_, __, i182, ___):
            i182["execution_receipt"].pop("execution_event_id")
        r = hardened_run(mutate)
        self.assertIn("EXECUTION_EXECUTION_EVENT_ID_MISSING_OR_INVALID", r["reasons"])

    def test_missing_outcome_observation_id_fails_closed(self):
        def mutate(_, __, i182, ___):
            i182["outcome_evidence"].pop("outcome_observation_id")
        r = hardened_run(mutate)
        self.assertIn("OUTCOME_OUTCOME_OBSERVATION_ID_MISSING_OR_INVALID", r["reasons"])

    def test_lineage_binding_digest_substitution_fails_closed(self):
        s188_inputs, s188_result, s182_inputs, s182_result = bundles()
        commit = s182_inputs["commit_receipt"]
        execution = s182_inputs["execution_receipt"]
        outcome = s182_inputs["outcome_evidence"]
        commit["event_sequence"] = 10
        execution.update({"execution_event_id": "EXEC-EVENT-001", "source_commit_event_id": commit["commit_event_id"], "commit_token_id": commit["commit_token_id"], "event_sequence": 20})
        outcome.update({"outcome_observation_id": "OUTCOME-OBS-001", "source_execution_event_id": execution["execution_event_id"], "source_commit_event_id": commit["commit_event_id"], "event_sequence": 30})
        import importlib.util
        from pathlib import Path
        here = Path(__file__).resolve().parent
        p = here.parent / "step_182_commit_execution_outcome_correspondence_r1" / "commit_execution_outcome_correspondence.py"
        spec = importlib.util.spec_from_file_location("step189_hardening_step182_2", p)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        s182_result = module.evaluate_commit_execution_outcome_correspondence(**s182_inputs)
        binding = postcommit_binding(s188_inputs, s188_result, s182_inputs, s182_result)
        binding.update({"commit_event_id": commit["commit_event_id"], "execution_event_id": execution["execution_event_id"], "outcome_observation_id": outcome["outcome_observation_id"], "event_lineage_digest": "sha256:bad"})
        r = evaluate_accountability_postcommit_correspondence_nonbypass_hardened(
            step188_inputs=s188_inputs, step188_result=s188_result,
            step182_inputs=s182_inputs, step182_result=s182_result,
            postcommit_binding_record=binding)
        self.assertIn("POSTCOMMIT_BINDING_EVENT_LINEAGE_DIGEST_MISMATCH", r["reasons"])


if __name__ == "__main__":
    unittest.main()
