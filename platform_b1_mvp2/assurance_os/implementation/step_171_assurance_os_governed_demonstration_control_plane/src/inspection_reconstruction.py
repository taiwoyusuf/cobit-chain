"""Inspection reconstruction packaging."""

from typing import Mapping, Sequence

from .canonical import deterministic_id


def build_reconstruction(
    session_manifest: Mapping[str, object],
    evidence_items: Sequence[Mapping[str, object]],
    audit_event_ids: Sequence[str],
) -> dict:
    payload = {
        "session_id": session_manifest["session_id"],
        "canonical_baseline_commit": (
            session_manifest["canonical_baseline_commit"]
        ),
        "evidence": sorted(
            [dict(item) for item in evidence_items],
            key=lambda item: str(item.get("evidence_type")),
        ),
        "audit_event_ids": sorted(
            str(item)
            for item in audit_event_ids
        ),
        "lineage_complete": (
            bool(evidence_items)
            and bool(audit_event_ids)
        ),
        "display_only": True,
    }

    payload["reconstruction_id"] = deterministic_id(
        "reconstruction",
        payload,
    )

    return payload
