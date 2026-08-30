"""Publication, semantic, and design-time assurance refinements R1.

Additive experiments only; no binding authority.
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable


def evaluate_source_to_artifact_correspondence(*, source_digest_bound: bool, build_process_identified: bool,
                                               build_reproducible: bool, artifact_digest_verified: bool) -> dict:
    """Artifact digest does not establish reproducible correspondence to source."""
    ok = all([source_digest_bound, build_process_identified, build_reproducible, artifact_digest_verified])
    return {
        "source_to_artifact_correspondence": "ESTABLISHED" if ok else "NOT_ESTABLISHED",
        "artifact_integrity_standing": "SUPPORTABLE" if artifact_digest_verified else "NOT_ESTABLISHED",
        "binding_decision_made": False,
        "fail_closed": not ok,
    }


def evaluate_test_semantic_correspondence(*, test_label: str, exercised_property: str,
                                          claimed_property: str, real_world_property_observed: bool) -> dict:
    """A test name must not be treated as evidence that the named property was exercised."""
    label_matches_claim = test_label.strip().lower() == claimed_property.strip().lower()
    exercised_matches_claim = exercised_property.strip().lower() == claimed_property.strip().lower()
    ok = exercised_matches_claim and real_world_property_observed
    return {
        "test_semantic_correspondence": "ESTABLISHED" if ok else "NOT_ESTABLISHED",
        "label_matches_claim": label_matches_claim,
        "exercised_property_matches_claim": exercised_matches_claim,
        "real_world_property_observed": real_world_property_observed,
        "binding_decision_made": False,
        "fail_closed": not ok,
    }


def evaluate_claim_strength_ceiling(*, observation_count: int, independent_repetitions: int,
                                    universal_counterexample_found: bool, requested_claim_class: str) -> dict:
    """Finite evidence cannot silently promote a bounded observation into a universal claim."""
    allowed = {"SINGLE_OBSERVATION", "REPEATED_OBSERVATION", "GENERAL_PROPERTY", "UNIVERSAL_CLAIM"}
    if requested_claim_class not in allowed:
        raise ValueError("unknown requested_claim_class")
    if universal_counterexample_found:
        ceiling = "REPEATED_OBSERVATION" if independent_repetitions > 1 else "SINGLE_OBSERVATION"
    elif independent_repetitions > 1:
        ceiling = "REPEATED_OBSERVATION"
    elif observation_count > 0:
        ceiling = "SINGLE_OBSERVATION"
    else:
        ceiling = "NOT_ESTABLISHED"
    rank = {"NOT_ESTABLISHED": 0, "SINGLE_OBSERVATION": 1, "REPEATED_OBSERVATION": 2,
            "GENERAL_PROPERTY": 3, "UNIVERSAL_CLAIM": 4}
    permitted = rank.get(requested_claim_class, 99) <= rank[ceiling]
    return {
        "claim_strength_ceiling": ceiling,
        "requested_claim_class": requested_claim_class,
        "requested_claim_permitted": permitted,
        "binding_decision_made": False,
        "fail_closed": not permitted,
    }


def evaluate_normative_completeness(*, factual_statements_correct: bool,
                                    required_normative_elements: Iterable[str],
                                    included_normative_elements: Iterable[str]) -> dict:
    """Factual correctness does not establish regulated/normative completeness."""
    required = set(required_normative_elements)
    included = set(included_normative_elements)
    missing = sorted(required - included)
    complete = factual_statements_correct and not missing
    return {
        "factual_correctness": factual_statements_correct,
        "normative_completeness_standing": "SUPPORTABLE" if complete else "NOT_ESTABLISHED",
        "missing_normative_elements": missing,
        "binding_decision_made": False,
        "fail_closed": not complete,
    }


def classify_control_failure(*, control_executed_as_designed: bool, control_present_and_enforceable: bool,
                             specified_control_sufficient: bool) -> dict:
    """Separate enforcement failure from specification failure for corrective action."""
    enforcement_failure = not control_present_and_enforceable or not control_executed_as_designed
    specification_failure = control_executed_as_designed and not specified_control_sufficient
    if enforcement_failure and specification_failure:
        cause = "MIXED"
    elif enforcement_failure:
        cause = "ENFORCEMENT_FAILURE"
    elif specification_failure:
        cause = "SPECIFICATION_FAILURE"
    elif all([control_executed_as_designed, control_present_and_enforceable, specified_control_sufficient]):
        cause = "NO_FAILURE_IDENTIFIED"
    else:
        cause = "NOT_ESTABLISHED"
    return {"control_failure_cause_class": cause, "binding_decision_made": False}


def evaluate_agency_justification(*, deterministic_alternative_assessed: bool,
                                  autonomy_necessary_for_purpose: bool,
                                  maximum_delegation_class: str,
                                  requested_delegation_class: str) -> dict:
    """Ask whether agentic autonomy was justified before evaluating an existing agent."""
    classes = ["NEVER_TOUCH", "PROPOSE_ONLY", "HUMAN_APPROVAL_REQUIRED", "BOUNDED_AUTONOMOUS"]
    if maximum_delegation_class not in classes or requested_delegation_class not in classes:
        raise ValueError("unknown delegation class")
    within_max = classes.index(requested_delegation_class) <= classes.index(maximum_delegation_class)
    ok = deterministic_alternative_assessed and autonomy_necessary_for_purpose and within_max
    return {
        "agency_justification_standing": "SUPPORTABLE" if ok else "NOT_ESTABLISHED",
        "maximum_delegation_class": maximum_delegation_class,
        "requested_delegation_class": requested_delegation_class,
        "binding_decision_made": False,
        "fail_closed": not ok,
    }


def evaluate_registry_resolution_standing(*, identifier_assigned: bool, publicly_resolvable: bool,
                                           evidence_available: bool, implementation_verified: bool) -> dict:
    """Identity, resolvability, evidence availability, and implementation proof are separate states."""
    return {
        "identifier_state": "ASSIGNED" if identifier_assigned else "NOT_ESTABLISHED",
        "publication_state": "PUBLICLY_RESOLVABLE" if publicly_resolvable else "NOT_PUBLICLY_RESOLVABLE",
        "evidence_availability_state": "AVAILABLE" if evidence_available else "NOT_AVAILABLE",
        "implementation_verification_state": "VERIFIED" if implementation_verified else "NOT_ESTABLISHED",
        "binding_decision_made": False,
    }


def evaluate_instance_bound_sufficiency(*, system_standing_supportable: bool,
                                        instance_evidence_supportable: bool,
                                        acceptance_basis_frozen_before_result: bool) -> dict:
    """System qualification/history does not automatically establish a specific consequential instance."""
    ok = all([system_standing_supportable, instance_evidence_supportable, acceptance_basis_frozen_before_result])
    return {
        "instance_assurance_standing": "SUPPORTABLE" if ok else "NOT_ESTABLISHED",
        "system_assurance_standing": "SUPPORTABLE" if system_standing_supportable else "NOT_ESTABLISHED",
        "binding_decision_made": False,
        "fail_closed": not ok,
    }


def evaluate_physical_digital_temporal_correspondence(*, clocks_synchronized: bool,
                                                       physical_event_time: datetime | None,
                                                       digital_event_time: datetime | None,
                                                       maximum_correspondence_error_seconds: float) -> dict:
    """Synchronized clocks do not establish that physical and digital events describe the same process phase."""
    if maximum_correspondence_error_seconds < 0:
        raise ValueError("maximum_correspondence_error_seconds must be non-negative")
    if physical_event_time is None or digital_event_time is None:
        delta = None
        ok = False
    else:
        delta = abs((digital_event_time - physical_event_time).total_seconds())
        ok = clocks_synchronized and delta <= maximum_correspondence_error_seconds
    return {
        "clock_synchronization_standing": "SUPPORTABLE" if clocks_synchronized else "NOT_ESTABLISHED",
        "physical_digital_temporal_correspondence": "ESTABLISHED" if ok else "NOT_ESTABLISHED",
        "correspondence_error_seconds": delta,
        "binding_decision_made": False,
        "fail_closed": not ok,
    }


def evaluate_institutional_independence(*, evidence_custodian: str, interpreter: str,
                                        decision_authority: str, executor: str,
                                        outcome_verifier: str,
                                        declared_conflicts: Iterable[tuple[str, str]]) -> dict:
    """Separate institutional functions and disclose conflicts rather than inferring independence from labels."""
    roles = [evidence_custodian, interpreter, decision_authority, executor, outcome_verifier]
    conflicts = {tuple(sorted(pair)) for pair in declared_conflicts}
    role_pairs = {tuple(sorted((roles[i], roles[j]))) for i in range(len(roles)) for j in range(i + 1, len(roles)) if roles[i] == roles[j]}
    unresolved = sorted(role_pairs - conflicts)
    return {
        "institutional_independence_standing": "SUPPORTABLE_WITH_DISCLOSED_DEPENDENCIES" if not unresolved else "NOT_ESTABLISHED",
        "unresolved_role_concentrations": unresolved,
        "binding_decision_made": False,
        "fail_closed": bool(unresolved),
    }
