"""Aug. 31 publication and external-review governance refinements.

These records govern research provenance and examination boundaries. They are
not Platform B1 execution authority and are not legal determinations of IP.
"""

from __future__ import annotations

RELATIONSHIP_CLASSES = {
    "PRE_EXISTING",
    "REVIEW_INFLUENCED",
    "INDEPENDENTLY_DERIVED",
    "JOINTLY_DEVELOPED",
    "ATTRIBUTION_AGREED",
    "ATTRIBUTION_UNRESOLVED",
}


def evaluate_lineage_challenge_record(*, alleged_parent_artifact_identified: bool,
                                     chronology_established: bool,
                                     artifact_level_correspondence_established: bool,
                                     evidence_of_access_established: bool,
                                     derivation_route_established: bool,
                                     independent_comparison_performed: bool) -> dict:
    """Chronology alone must not be promoted into derivation, authorship, or ownership."""
    derivation = all([
        alleged_parent_artifact_identified,
        chronology_established,
        artifact_level_correspondence_established,
        evidence_of_access_established,
        derivation_route_established,
        independent_comparison_performed,
    ])
    return {
        "lineage_derivation_standing": "ESTABLISHED" if derivation else "NOT_ESTABLISHED",
        "chronology_standing": "ESTABLISHED" if chronology_established else "NOT_ESTABLISHED",
        "chronology_proves_derivation": False,
        "derivation_proves_ownership": False,
        "binding_ip_determination_made": False,
    }


def evaluate_architecture_influence_provenance(*, pre_review_artifact_frozen: bool,
                                               external_input_dated: bool,
                                               pre_existing_mechanism_recorded: bool,
                                               subsequent_change_identified: bool,
                                               relationship_class: str,
                                               attribution_recorded: bool,
                                               authorship_boundary_recorded: bool,
                                               ownership_nonclaim_recorded: bool) -> dict:
    """Influence, contribution, authorship, ownership, and implementation remain separate propositions."""
    if relationship_class not in RELATIONSHIP_CLASSES:
        raise ValueError("unknown relationship_class")
    complete = all([
        pre_review_artifact_frozen,
        external_input_dated,
        pre_existing_mechanism_recorded,
        subsequent_change_identified,
        attribution_recorded,
        authorship_boundary_recorded,
        ownership_nonclaim_recorded,
    ])
    return {
        "architecture_influence_provenance_standing": "SUPPORTABLE" if complete else "NOT_ESTABLISHED",
        "relationship_class": relationship_class,
        "attribution_unresolved": relationship_class == "ATTRIBUTION_UNRESOLVED",
        "influence_equals_authorship": False,
        "authorship_equals_ownership": False,
        "binding_ip_determination_made": False,
    }


def evaluate_demonstration_participation_record(*, subject_version_frozen: bool,
                                                bounded_proposition_frozen: bool,
                                                nonclaims_frozen: bool,
                                                evidence_boundary_frozen: bool,
                                                acceptance_criteria_frozen: bool,
                                                reviewer_role_and_independence_bound: bool,
                                                ip_preexisting_rights_bound: bool,
                                                confidentiality_bound: bool,
                                                publication_rights_bound: bool,
                                                claim_ceiling_bound: bool,
                                                correction_dispute_path_bound: bool,
                                                frozen_before_evidence_exchange: bool) -> dict:
    """External review terms should be frozen before evidence changes hands."""
    fields = {
        "subject_version": subject_version_frozen,
        "bounded_proposition": bounded_proposition_frozen,
        "nonclaims": nonclaims_frozen,
        "evidence_boundary": evidence_boundary_frozen,
        "acceptance_criteria": acceptance_criteria_frozen,
        "reviewer_role_and_independence": reviewer_role_and_independence_bound,
        "ip_preexisting_rights": ip_preexisting_rights_bound,
        "confidentiality": confidentiality_bound,
        "publication_rights": publication_rights_bound,
        "claim_ceiling": claim_ceiling_bound,
        "correction_dispute_path": correction_dispute_path_bound,
        "frozen_before_evidence_exchange": frozen_before_evidence_exchange,
    }
    missing = sorted(name for name, ok in fields.items() if not ok)
    supportable = not missing
    return {
        "demonstration_participation_record_standing": "SUPPORTABLE" if supportable else "NOT_ESTABLISHED",
        "missing_or_unfrozen_elements": missing,
        "participation_equals_authorship": False,
        "participation_equals_ownership": False,
        "participation_equals_certification": False,
        "participation_equals_authority": False,
        "binding_decision_made": False,
    }


def evaluate_framework_neutral_qualification(*, claim_defined_before_results: bool,
                                             falsification_criteria_frozen: bool,
                                             native_architecture_identity_preserved: bool,
                                             evidence_boundary_frozen: bool,
                                             counterfactual_cases_executed: bool,
                                             uncertainty_preserved: bool,
                                             determination_separate_from_authority: bool,
                                             authority_non_transfer_explicit: bool,
                                             replay_manifest_present: bool,
                                             native_ontology_preserved: bool) -> dict:
    """Architectures may be compared at a claim boundary without ontology or authority transfer."""
    supportable = all([
        claim_defined_before_results,
        falsification_criteria_frozen,
        native_architecture_identity_preserved,
        evidence_boundary_frozen,
        counterfactual_cases_executed,
        uncertainty_preserved,
        determination_separate_from_authority,
        authority_non_transfer_explicit,
        replay_manifest_present,
        native_ontology_preserved,
    ])
    return {
        "framework_neutral_qualification_standing": "SUPPORTABLE" if supportable else "NOT_ESTABLISHED",
        "cross_architecture_review_requires_ontology_convergence": False,
        "qualification_transfers_authority": False,
        "binding_decision_made": False,
        "fail_closed": not supportable,
    }
