"""Absorbed Aug. 18 structural/replay/interaction refinements.

These bounded evaluators preserve the useful semantic deltas from superseded
PR #57 without creating new top-level capability families or binding authority.
Structural operating-envelope standing is implemented in Step 176; this file
retains the replay-legitimacy and interacting-decision challenge contracts.
"""

from __future__ import annotations

from typing import Mapping, Sequence


def evaluate_replay_legitimacy_and_promotion(*, replay_succeeded: bool,
                                              current_basis_established: bool,
                                              custody_complete: bool,
                                              record_present: bool,
                                              record_current: bool,
                                              record_applicable: bool,
                                              inference_supported: bool,
                                              reliance_permitted: bool,
                                              action_admissible: bool) -> dict:
    """Replay success and persisted proof do not establish present legitimacy."""
    if action_admissible and not all([
        record_present,
        record_current,
        record_applicable,
        inference_supported,
        reliance_permitted,
        current_basis_established,
    ]):
        standing = "ILLEGAL_PROMOTION_TO_CONSEQUENCE"
        behavior = "HOLD_NO_BIND"
        reason = "PERSISTENCE_DOES_NOT_ESTABLISH_PROMOTION_TO_CONSEQUENCE"
    elif replay_succeeded and not current_basis_established:
        standing = "REPLAY_VALID_LEGITIMACY_NOT_ESTABLISHED"
        behavior = "REQUALIFICATION_REQUIRED"
        reason = "REPLAY_SUCCEEDED_DOES_NOT_ESTABLISH_CURRENT_LEGITIMACY"
    elif record_present and not custody_complete:
        standing = "PROOF_PRESENT_CUSTODY_INCOMPLETE"
        behavior = "REVIEW_REQUIRED"
        reason = "PROOF_PRESENT_DOES_NOT_ESTABLISH_CUSTODY_COMPLETE"
    else:
        chain = all([
            record_present,
            record_current,
            record_applicable,
            inference_supported,
            reliance_permitted,
            current_basis_established,
        ])
        standing = "LEGITIMACY_CHAIN_ESTABLISHED" if chain else "LEGITIMACY_CHAIN_NOT_ESTABLISHED"
        behavior = "SEPARATE_ACTION_ADMISSIBILITY_REQUIRED" if chain else "REVIEW_REQUIRED"
        reason = "CURRENT_LEGITIMACY_CHAIN_EVALUATED"

    return {
        "replay_legitimacy_standing": standing,
        "required_behavior": behavior,
        "reason": reason,
        "binding_decision_made": False,
        "fail_closed": standing != "LEGITIMACY_CHAIN_ESTABLISHED",
    }


def evaluate_interacting_decision_condition(*, decisions: Sequence[Mapping[str, object]],
                                            interaction_assessed: bool,
                                            interaction_basis_current: bool,
                                            intended_outcome_compatible: bool,
                                            emergent_exposure: bool) -> dict:
    """Individually supportable decisions may still create an unsafe combination."""
    if not decisions:
        standing = "NOT_ESTABLISHED"
        behavior = "REVIEW_REQUIRED"
        reason = "NO_GOVERNED_DECISIONS_SUPPLIED"
    elif not all(bool(item.get("individually_valid", False)) for item in decisions):
        standing = "CONSTITUENT_DECISION_NOT_VALID"
        behavior = "HOLD_NO_BIND"
        reason = "ONE_OR_MORE_CONSTITUENT_DECISIONS_NOT_SUPPORTABLE"
    elif not interaction_assessed:
        standing = "INTERACTION_STANDING_NOT_ESTABLISHED"
        behavior = "REVIEW_REQUIRED"
        reason = "INDIVIDUAL_VALIDITY_DOES_NOT_ESTABLISH_COMBINED_CONDITION"
    elif not interaction_basis_current:
        standing = "INTERACTION_BASIS_STALE"
        behavior = "REQUALIFICATION_REQUIRED"
        reason = "COMBINED_CONDITION_BASIS_NOT_CURRENT"
    elif emergent_exposure or not intended_outcome_compatible:
        standing = "COMPOSITE_CONDITION_INCOMPATIBLE"
        behavior = "HOLD_NO_BIND"
        reason = "VALID_COMPONENT_DECISIONS_CREATE_INCOMPATIBLE_COMBINED_CONDITION"
    else:
        standing = "INTERACTING_DECISION_CONDITION_SUPPORTABLE"
        behavior = "SEPARATE_ACTION_ADMISSIBILITY_REQUIRED"
        reason = "INDIVIDUAL_AND_INTERACTION_STANDING_SUPPORTABLE"

    return {
        "interacting_decision_condition_standing": standing,
        "required_behavior": behavior,
        "reason": reason,
        "binding_decision_made": False,
        "fail_closed": standing != "INTERACTING_DECISION_CONDITION_SUPPORTABLE",
    }
