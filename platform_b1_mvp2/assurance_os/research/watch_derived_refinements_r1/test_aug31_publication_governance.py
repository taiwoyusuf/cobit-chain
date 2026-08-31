import unittest

from aug31_publication_governance import (
    evaluate_architecture_influence_provenance,
    evaluate_demonstration_participation_record,
    evaluate_framework_neutral_qualification,
    evaluate_lineage_challenge_record,
)


class Aug31PublicationGovernanceTests(unittest.TestCase):
    def test_chronology_alone_does_not_establish_derivation(self):
        r = evaluate_lineage_challenge_record(
            alleged_parent_artifact_identified=True,
            chronology_established=True,
            artifact_level_correspondence_established=False,
            evidence_of_access_established=False,
            derivation_route_established=False,
            independent_comparison_performed=False,
        )
        self.assertEqual(r["lineage_derivation_standing"], "NOT_ESTABLISHED")
        self.assertFalse(r["chronology_proves_derivation"])

    def test_unresolved_attribution_can_be_preserved_without_ip_overclaim(self):
        r = evaluate_architecture_influence_provenance(
            pre_review_artifact_frozen=True,
            external_input_dated=True,
            pre_existing_mechanism_recorded=True,
            subsequent_change_identified=True,
            relationship_class="ATTRIBUTION_UNRESOLVED",
            attribution_recorded=True,
            authorship_boundary_recorded=True,
            ownership_nonclaim_recorded=True,
        )
        self.assertEqual(r["architecture_influence_provenance_standing"], "SUPPORTABLE")
        self.assertTrue(r["attribution_unresolved"])
        self.assertFalse(r["influence_equals_authorship"])

    def test_demo_terms_must_be_frozen_before_evidence_exchange(self):
        r = evaluate_demonstration_participation_record(
            subject_version_frozen=True,
            bounded_proposition_frozen=True,
            nonclaims_frozen=True,
            evidence_boundary_frozen=True,
            acceptance_criteria_frozen=True,
            reviewer_role_and_independence_bound=True,
            ip_preexisting_rights_bound=True,
            confidentiality_bound=True,
            publication_rights_bound=True,
            claim_ceiling_bound=True,
            correction_dispute_path_bound=True,
            frozen_before_evidence_exchange=False,
        )
        self.assertEqual(r["demonstration_participation_record_standing"], "NOT_ESTABLISHED")
        self.assertIn("frozen_before_evidence_exchange", r["missing_or_unfrozen_elements"])

    def test_cross_architecture_review_preserves_native_ontology_and_authority(self):
        r = evaluate_framework_neutral_qualification(
            claim_defined_before_results=True,
            falsification_criteria_frozen=True,
            native_architecture_identity_preserved=True,
            evidence_boundary_frozen=True,
            counterfactual_cases_executed=True,
            uncertainty_preserved=True,
            determination_separate_from_authority=True,
            authority_non_transfer_explicit=True,
            replay_manifest_present=True,
            native_ontology_preserved=True,
        )
        self.assertEqual(r["framework_neutral_qualification_standing"], "SUPPORTABLE")
        self.assertFalse(r["cross_architecture_review_requires_ontology_convergence"])
        self.assertFalse(r["qualification_transfers_authority"])


if __name__ == "__main__":
    unittest.main()
