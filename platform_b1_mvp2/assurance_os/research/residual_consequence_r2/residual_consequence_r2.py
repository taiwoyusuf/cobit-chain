"""Residual-Consequence R2 reproducibility harness.

Research-only adapter around the frozen Step 184 R1 evaluator. This module does
not modify, fork, or replace the frozen evaluator. It derives explicit R1 input
records from bounded scenario traces and evaluates metamorphic properties around
that frozen interface.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Mapping


FROZEN_R1_BLOB = "607694656829b294b7d9d1b5cd742eebce5dd0b5"
FROZEN_R1_TEST_BLOB = "2d0d4d9e6d3edf14ad3e98973db0cc5aaece0711"

_R1_PATH = (
    Path(__file__).resolve().parents[2]
    / "implementation"
    / "step_184_residual_consequence_assurance_r1"
    / "residual_consequence_assurance.py"
)

_spec = importlib.util.spec_from_file_location("step184_frozen_r1", _R1_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError("FROZEN_R1_IMPORT_NOT_ESTABLISHED")
_r1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_r1)


DOMAINS = {
    "RADIOPHARMA",
    "GMP_COMPOUNDING",
    "ENVIRONMENTAL_BMS",
    "AI_PAYMENT",
    "CYBERSECURITY",
    "CLINICAL_TRIAL",
}


def _base_upstream() -> tuple[dict, dict, dict]:
    execution = {
        "execution_time_standing": "SUPPORTABLE",
        "execution_time_decision": "ADMISSIBLE",
        "no_bind_state": "INACTIVE",
        "binding_authority_granted": False,
        "prior_decision_preserved_as_history": True,
    }
    outcome = {
        "correspondence_standing": "OUTCOME_CORRESPONDENCE_SUPPORTABLE",
        "commit_occurred": True,
        "execution_succeeded": True,
        "intended_outcome_established": True,
        "historical_facts": {"commit_occurred": True, "execution_succeeded": True},
        "no_bind_state": "INACTIVE",
        "binding_authority_granted": False,
    }
    reclosure = {
        "reclosure_standing": "RECLOSURE_SUPPORTABLE",
        "return_to_reliance_supportable": True,
        "no_bind_state": "SEPARATE_AUTHORITY_AND_ACTION_ADMISSIBILITY_REQUIRED",
        "binding_authority_granted": False,
        "historical_facts_rewritten": False,
    }
    return execution, outcome, reclosure


def derive_r1_inputs(trace: Mapping[str, object]) -> dict:
    """Derive explicit frozen-R1 inputs from an R2 scenario trace.

    R2 uses event ordering to decide whether an observation is current. An
    observation taken before a later material change or before a STOP cannot be
    treated as current termination evidence unless a later qualifying observation
    is supplied.
    """
    domain = trace.get("domain")
    if domain not in DOMAINS:
        raise ValueError("R2_DOMAIN_NOT_RECOGNIZED")

    events = list(trace.get("events", []))
    if not all(isinstance(event, Mapping) for event in events):
        raise ValueError("R2_EVENTS_INVALID")

    ordered = sorted(events, key=lambda item: int(item.get("sequence", -1)))
    sequences = [int(item.get("sequence", -1)) for item in ordered]
    if any(seq < 0 for seq in sequences) or len(sequences) != len(set(sequences)):
        raise ValueError("R2_EVENT_SEQUENCE_INVALID")

    last_observation = max(
        (int(e["sequence"]) for e in ordered if e.get("kind") == "OBSERVATION"),
        default=None,
    )
    last_material_change = max(
        (int(e["sequence"]) for e in ordered if e.get("kind") == "MATERIAL_CHANGE"),
        default=None,
    )
    last_stop = max(
        (int(e["sequence"]) for e in ordered if e.get("kind") == "STOP"),
        default=None,
    )

    observation_current = last_observation is not None
    if last_material_change is not None and (last_observation is None or last_observation < last_material_change):
        observation_current = False
    if last_stop is not None and (last_observation is None or last_observation < last_stop):
        observation_current = False

    consequence = {
        "historical_event_preserved": trace.get("historical_event_preserved", True),
        "authority_current_at_irreversible_boundary": trace.get(
            "authority_current_at_irreversible_boundary", True
        ),
        "irreversible_boundary_crossed": trace.get("irreversible_boundary_crossed", False),
        "stop_command_succeeded": last_stop is not None and trace.get("stop_command_succeeded", True),
        "consequence_termination_observed": trace.get("consequence_termination_observed", False),
        "partial_irreversible_consequence": trace.get("partial_irreversible_consequence", False),
        "residual_propagation_active": trace.get("residual_propagation_active", False),
        "latent_consequence_window_open": trace.get("latent_consequence_window_open", False),
        "residual_effects_present": trace.get("residual_effects_present", False),
        "current_physical_correspondence_established": trace.get(
            "current_physical_correspondence_established", True
        ),
        "witness_proposition_qualified": trace.get("witness_proposition_qualified", True),
        "observation_current": observation_current,
    }

    evidence = {
        "contradiction_present": trace.get("contradiction_present", False),
        "independent_failure_domains_established": trace.get(
            "independent_failure_domains_established", True
        ),
        "negative_evidence_basis_complete": trace.get("negative_evidence_basis_complete", True),
    }

    claims = list(trace.get("claims", [{"claim_id": "C1", "active": True}]))
    active_claims = [claim for claim in claims if isinstance(claim, Mapping) and claim.get("active") is True]
    competing_count = len(active_claims)

    race_retry = {
        "active_competing_claim_count": competing_count,
        "single_winner_serialized": trace.get("single_winner_serialized", competing_count <= 1),
        "losing_claims_retired": trace.get("losing_claims_retired", competing_count <= 1),
        "retry_requested": trace.get("retry_requested", False),
        "prior_attempt_consequence_state_known": trace.get("prior_attempt_consequence_state_known", True),
        "idempotency_identity_matches": trace.get("idempotency_identity_matches", True),
        "duplicate_consequence_prevention_established": trace.get(
            "duplicate_consequence_prevention_established", True
        ),
    }

    execution, outcome, reclosure = _base_upstream()
    execution.update(dict(trace.get("execution_overrides", {})))
    outcome.update(dict(trace.get("outcome_overrides", {})))
    reclosure.update(dict(trace.get("reclosure_overrides", {})))

    return {
        "execution_time_result": execution,
        "outcome_result": outcome,
        "reclosure_result": reclosure,
        "consequence_state": consequence,
        "race_retry_state": race_retry,
        "evidence_state": evidence,
    }


def evaluate_trace(trace: Mapping[str, object]) -> dict:
    inputs = derive_r1_inputs(trace)
    result = _r1.evaluate_residual_consequence_assurance(**inputs)
    return {
        "domain": trace.get("domain"),
        "r1_blob_expected": FROZEN_R1_BLOB,
        "r1_test_blob_expected": FROZEN_R1_TEST_BLOB,
        "r1_result": result,
    }
