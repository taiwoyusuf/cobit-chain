"""Deterministic governed session manifests."""

from typing import Iterable, Mapping

from .canonical import deterministic_id


def build_session_manifest(
    track: Mapping[str, object],
    scenario: Mapping[str, object],
    canonical_commit: str,
    step170_references: Iterable[Mapping[str, object]],
) -> dict:
    payload = {
        "track_code": track["code"],
        "scenario_id": scenario["scenario_id"],
        "canonical_baseline_commit": canonical_commit,
        "step170_references": sorted(
            [dict(item) for item in step170_references],
            key=lambda item: (
                str(item.get("evidence_class")),
                str(item.get("relative_path")),
            ),
        ),
        "logical_stage": "SESSION_CREATED",
        "synthetic": True,
    }

    payload["session_id"] = deterministic_id("session", payload)

    return payload
