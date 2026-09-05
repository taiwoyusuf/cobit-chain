"""Step 189 R1 hardening — explicit commit/execution/outcome event lineage.

SR-189-01 identified that the initial Step 189 candidate bound the exact Step 188
token to a commit receipt but could still accept execution and outcome records
that shared action/transaction/object identifiers without explicitly proving the
records belonged to the same commit-event lineage.

This hardened entrypoint composes the initial Step 189 evaluator and adds a
fail-closed commit-event -> execution-event -> outcome-observation chain. The
lineage evidence remains caller supplied: correspondence does not establish
external authenticity, causation, authority, or physical truth.
"""

from __future__ import annotations

from collections.abc import Mapping

from accountability_postcommit_correspondence_nonbypass import (
    NOT_ESTABLISHED,
    SUPPORTABLE,
    canonical_digest,
    evaluate_accountability_postcommit_correspondence_nonbypass,
)

HARDENING_REVISION = "STEP_189_R1_HARDENED"


def _nonempty(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _sequence(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def event_lineage_payload(
    *,
    commit_receipt: Mapping[str, object],
    execution_receipt: Mapping[str, object],
    outcome_evidence: Mapping[str, object],
) -> dict[str, object]:
    """Canonical bounded event-lineage payload for Step 189 hardening."""
    return {
        "commit_event_id": commit_receipt.get("commit_event_id"),
        "commit_event_sequence": commit_receipt.get("event_sequence"),
        "commit_token_id": commit_receipt.get("commit_token_id"),
        "execution_event_id": execution_receipt.get("execution_event_id"),
        "execution_source_commit_event_id": execution_receipt.get("source_commit_event_id"),
        "execution_commit_token_id": execution_receipt.get("commit_token_id"),
        "execution_event_sequence": execution_receipt.get("event_sequence"),
        "outcome_observation_id": outcome_evidence.get("outcome_observation_id"),
        "outcome_source_execution_event_id": outcome_evidence.get("source_execution_event_id"),
        "outcome_source_commit_event_id": outcome_evidence.get("source_commit_event_id"),
        "outcome_event_sequence": outcome_evidence.get("event_sequence"),
    }


def evaluate_accountability_postcommit_correspondence_nonbypass_hardened(
    *,
    step188_inputs: Mapping[str, object],
    step188_result: Mapping[str, object],
    step182_inputs: Mapping[str, object],
    step182_result: Mapping[str, object],
    postcommit_binding_record: Mapping[str, object],
    caller_requested_decision: str = "EVALUATE",
) -> dict[str, object]:
    """Require exact event lineage in addition to the initial Step 189 checks."""

    base = evaluate_accountability_postcommit_correspondence_nonbypass(
        step188_inputs=step188_inputs,
        step188_result=step188_result,
        step182_inputs=step182_inputs,
        step182_result=step182_result,
        postcommit_binding_record=postcommit_binding_record,
        caller_requested_decision=caller_requested_decision,
    )

    lineage_reasons: list[str] = []

    commit_receipt = (
        step182_inputs.get("commit_receipt")
        if isinstance(step182_inputs, Mapping)
        else None
    )
    execution_receipt = (
        step182_inputs.get("execution_receipt")
        if isinstance(step182_inputs, Mapping)
        else None
    )
    outcome_evidence = (
        step182_inputs.get("outcome_evidence")
        if isinstance(step182_inputs, Mapping)
        else None
    )
    token = (
        step188_inputs.get("step181_token")
        if isinstance(step188_inputs, Mapping)
        else None
    )

    if not isinstance(commit_receipt, Mapping):
        lineage_reasons.append("LINEAGE_COMMIT_RECEIPT_MISSING_OR_INVALID")
    if not isinstance(execution_receipt, Mapping):
        lineage_reasons.append("LINEAGE_EXECUTION_RECEIPT_MISSING_OR_INVALID")
    if not isinstance(outcome_evidence, Mapping):
        lineage_reasons.append("LINEAGE_OUTCOME_EVIDENCE_MISSING_OR_INVALID")

    if isinstance(commit_receipt, Mapping):
        if not _nonempty(commit_receipt.get("commit_event_id")):
            lineage_reasons.append("COMMIT_EVENT_ID_NOT_ESTABLISHED")
        if _sequence(commit_receipt.get("event_sequence")) is None:
            lineage_reasons.append("COMMIT_EVENT_SEQUENCE_INVALID")

    if isinstance(execution_receipt, Mapping):
        for field in ("execution_event_id", "source_commit_event_id", "commit_token_id"):
            if not _nonempty(execution_receipt.get(field)):
                lineage_reasons.append("EXECUTION_" + field.upper() + "_MISSING_OR_INVALID")
        if _sequence(execution_receipt.get("event_sequence")) is None:
            lineage_reasons.append("EXECUTION_EVENT_SEQUENCE_INVALID")

    if isinstance(outcome_evidence, Mapping):
        for field in (
            "outcome_observation_id",
            "source_execution_event_id",
            "source_commit_event_id",
        ):
            if not _nonempty(outcome_evidence.get(field)):
                lineage_reasons.append("OUTCOME_" + field.upper() + "_MISSING_OR_INVALID")
        if _sequence(outcome_evidence.get("event_sequence")) is None:
            lineage_reasons.append("OUTCOME_EVENT_SEQUENCE_INVALID")

    if isinstance(commit_receipt, Mapping) and isinstance(execution_receipt, Mapping):
        if execution_receipt.get("source_commit_event_id") != commit_receipt.get("commit_event_id"):
            lineage_reasons.append("EXECUTION_NOT_LINKED_TO_EXACT_COMMIT_EVENT")
        if execution_receipt.get("commit_token_id") != commit_receipt.get("commit_token_id"):
            lineage_reasons.append("EXECUTION_NOT_LINKED_TO_EXACT_COMMIT_TOKEN")

    if isinstance(token, Mapping) and isinstance(execution_receipt, Mapping):
        if execution_receipt.get("commit_token_id") != token.get("token_id"):
            lineage_reasons.append("EXECUTION_TOKEN_NOT_STEP_188_BOUND_TOKEN")

    if isinstance(commit_receipt, Mapping) and isinstance(outcome_evidence, Mapping):
        if outcome_evidence.get("source_commit_event_id") != commit_receipt.get("commit_event_id"):
            lineage_reasons.append("OUTCOME_NOT_LINKED_TO_EXACT_COMMIT_EVENT")

    if isinstance(execution_receipt, Mapping) and isinstance(outcome_evidence, Mapping):
        if outcome_evidence.get("source_execution_event_id") != execution_receipt.get("execution_event_id"):
            lineage_reasons.append("OUTCOME_NOT_LINKED_TO_EXACT_EXECUTION_EVENT")

    if (
        isinstance(commit_receipt, Mapping)
        and isinstance(execution_receipt, Mapping)
        and isinstance(outcome_evidence, Mapping)
    ):
        commit_seq = _sequence(commit_receipt.get("event_sequence"))
        execution_seq = _sequence(execution_receipt.get("event_sequence"))
        outcome_seq = _sequence(outcome_evidence.get("event_sequence"))
        if (
            commit_seq is not None
            and execution_seq is not None
            and outcome_seq is not None
            and not (commit_seq < execution_seq < outcome_seq)
        ):
            lineage_reasons.append("EVENT_LINEAGE_ORDERING_NOT_ESTABLISHED")

        lineage = event_lineage_payload(
            commit_receipt=commit_receipt,
            execution_receipt=execution_receipt,
            outcome_evidence=outcome_evidence,
        )
        lineage_digest = canonical_digest(lineage)
    else:
        lineage_digest = None

    if not isinstance(postcommit_binding_record, Mapping):
        lineage_reasons.append("LINEAGE_POSTCOMMIT_BINDING_RECORD_MISSING_OR_INVALID")
    else:
        for field in (
            "commit_event_id",
            "execution_event_id",
            "outcome_observation_id",
            "event_lineage_digest",
        ):
            if not _nonempty(postcommit_binding_record.get(field)):
                lineage_reasons.append("POSTCOMMIT_BINDING_" + field.upper() + "_MISSING_OR_INVALID")

        if isinstance(commit_receipt, Mapping):
            if postcommit_binding_record.get("commit_event_id") != commit_receipt.get("commit_event_id"):
                lineage_reasons.append("POSTCOMMIT_BINDING_COMMIT_EVENT_ID_MISMATCH")
        if isinstance(execution_receipt, Mapping):
            if postcommit_binding_record.get("execution_event_id") != execution_receipt.get("execution_event_id"):
                lineage_reasons.append("POSTCOMMIT_BINDING_EXECUTION_EVENT_ID_MISMATCH")
        if isinstance(outcome_evidence, Mapping):
            if postcommit_binding_record.get("outcome_observation_id") != outcome_evidence.get("outcome_observation_id"):
                lineage_reasons.append("POSTCOMMIT_BINDING_OUTCOME_OBSERVATION_ID_MISMATCH")
        if lineage_digest is None:
            lineage_reasons.append("EVENT_LINEAGE_DIGEST_NOT_COMPUTABLE")
        elif postcommit_binding_record.get("event_lineage_digest") != lineage_digest:
            lineage_reasons.append("POSTCOMMIT_BINDING_EVENT_LINEAGE_DIGEST_MISMATCH")

    combined_reasons = sorted(set(list(base.get("reasons", [])) + lineage_reasons))
    blocked = bool(combined_reasons)

    result = dict(base)
    result.update({
        "hardening_revision": HARDENING_REVISION,
        "accountability_postcommit_standing": NOT_ESTABLISHED if blocked else SUPPORTABLE,
        "accountability_postcommit_decision": (
            "NOT_SUPPORTABLE"
            if blocked
            else "ACCOUNTABILITY_COMMIT_EXECUTION_OUTCOME_CORRESPONDENCE_SUPPORTABLE"
        ),
        "no_bind_state": (
            "ACTIVE"
            if blocked
            else "SEPARATE_EXTERNAL_AUTHORITY_AUTHENTICITY_CAUSATION_AND_OPERATIONAL_VALIDATION_REQUIRED"
        ),
        "postcommit_reliance_held": blocked,
        "reasons": combined_reasons,
        "event_lineage_correspondence_checked": True,
        "event_lineage_correspondence_supportable": not bool(lineage_reasons),
        "event_lineage_temporal_ordering_checked": True,
        "event_lineage_digest_binding_checked": True,
        "sr_189_01_closed": not bool(lineage_reasons),
        "binding_provenance_manufactured": False,
        "binding_authority_granted": False,
        "action_admissibility_granted": False,
        "commit_authorized": False,
        "execution_authorized": False,
        "commit_token_consumed_by_evaluator": False,
        "physical_action_executed_by_evaluator": False,
        "causal_attribution_established": False,
        "regulated_release_or_disposition_authorized": False,
        "historical_facts_rewritten": False,
        "irlt_mag_state_changed": False,
    })
    return result
