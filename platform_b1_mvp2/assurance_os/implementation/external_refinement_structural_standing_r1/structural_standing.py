"""External-corpus refinements implemented as first-party COBIT-Chain challenge contracts.

These controls are difference-first refinements of existing COBIT-Chain capability families.
They do not create a new top-level capability number, execution authority, GxP validation,
or regulatory acceptance.
"""
from __future__ import annotations
from typing import Any, Dict, Mapping, Sequence

AUTHORITY = "NONE"
NO_BIND = True


def _result(control: str, standing: str, routing: str = "NONE", reasons=(), details=None) -> Dict[str, Any]:
    return {
        "control": control,
        "standing": standing,
        "routing": routing,
        "authority": AUTHORITY,
        "no_bind": NO_BIND,
        "reasons": list(reasons),
        "details": dict(details or {}),
        "executed": False,
    }


def evaluate_operating_envelope(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Evaluate whether the qualified operating regime itself remains supportable.

    This is intentionally stronger than checking whether individual monitored values
    remain within their limits. A structural/topological regime change invalidates
    silent inheritance from the previously qualified envelope.
    """
    control = "STRUCTURAL_OPERATING_ENVELOPE_STANDING"
    required = ("qualified_envelope_id", "current_envelope_id", "corridor_supported")
    missing = [k for k in required if record.get(k) in (None, "")]
    if missing:
        return _result(
            control,
            "NOT_ESTABLISHED",
            "REVIEW_REQUIRED",
            ["Operating-envelope evidence is incomplete."],
            {"missing_fields": missing},
        )

    if not bool(record.get("corridor_supported")):
        return _result(
            control,
            "NO_SUPPORTABLE_OPERATING_CORRIDOR",
            "HOLD_NO_BIND",
            ["No currently supportable operating corridor is established."],
        )

    if bool(record.get("bifurcation_detected")):
        return _result(
            control,
            "REGIME_BIFURCATED",
            "REQUALIFICATION_REQUIRED",
            ["A bifurcation changes the governing regime; prior standing cannot be inherited."],
        )

    structural_change = bool(record.get("structural_change_detected")) or bool(record.get("topology_changed"))
    envelope_changed = str(record.get("qualified_envelope_id")) != str(record.get("current_envelope_id"))
    if structural_change or envelope_changed:
        return _result(
            control,
            "ENVELOPE_CHANGED",
            "REQUALIFICATION_REQUIRED",
            [
                "CURRENT_VALUES_WITHIN_LIMITS != QUALIFIED_OPERATING_REGIME_PRESERVED",
                "Structural change requires positive requalification of the governing envelope.",
            ],
            {
                "qualified_envelope_id": record.get("qualified_envelope_id"),
                "current_envelope_id": record.get("current_envelope_id"),
                "current_values_within_limits": bool(record.get("current_values_within_limits")),
            },
        )

    if bool(record.get("boundary_approaching")):
        return _result(
            control,
            "ENVELOPE_BOUNDARY_APPROACHING",
            "REVIEW_REQUIRED",
            ["The operating state is approaching the qualified envelope boundary."],
        )

    if bool(record.get("parametric_drift_detected")):
        return _result(
            control,
            "PARAMETRIC_DRIFT_WITHIN_ENVELOPE",
            "MONITOR",
            ["Parametric drift is present, but the qualified structural envelope remains established."],
        )

    return _result(
        control,
        "ENVELOPE_STABLE",
        "NONE",
        ["The currently evidenced operating regime corresponds to the qualified envelope."],
    )


def evaluate_replay_legitimacy(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Separate deterministic replay/proof persistence from current legitimacy and promotion."""
    control = "REPLAY_LEGITIMACY_AND_PROMOTION_STANDING"
    replay = bool(record.get("replay_succeeded"))
    current_basis = bool(record.get("current_basis_established"))
    custody_complete = bool(record.get("custody_complete"))
    present = bool(record.get("record_present"))
    current = bool(record.get("record_current"))
    applicable = bool(record.get("record_applicable"))
    inference = bool(record.get("inference_supported"))
    reliance = bool(record.get("reliance_permitted"))
    admissible = bool(record.get("action_admissible"))

    if admissible and not all((present, current, applicable, inference, reliance, current_basis)):
        return _result(
            control,
            "ILLEGAL_PROMOTION_TO_CONSEQUENCE",
            "HOLD_NO_BIND",
            [
                "PERSISTENCE != PROMOTION_TO_CONSEQUENCE",
                "ACTION_ADMISSIBLE requires all upstream legitimacy conditions.",
            ],
        )

    if replay and not current_basis:
        return _result(
            control,
            "REPLAY_VALID_LEGITIMACY_NOT_ESTABLISHED",
            "REQUALIFICATION_REQUIRED",
            [
                "REPLAY_SUCCEEDED != CURRENT_LEGITIMACY_ESTABLISHED",
                "Deterministic reproducibility does not prove that the represented basis still governs reality.",
            ],
        )

    if present and not custody_complete:
        return _result(
            control,
            "PROOF_PRESENT_CUSTODY_INCOMPLETE",
            "REVIEW_REQUIRED",
            ["PROOF_PRESENT != CUSTODY_COMPLETE"],
        )

    chain = [
        ("record_present", present),
        ("record_current", current),
        ("record_applicable", applicable),
        ("inference_supported", inference),
        ("reliance_permitted", reliance),
        ("current_basis_established", current_basis),
    ]
    failed = [name for name, ok in chain if not ok]
    if failed:
        return _result(
            control,
            "LEGITIMACY_CHAIN_NOT_ESTABLISHED",
            "REVIEW_REQUIRED",
            ["RECORD_PRESENT != RECORD_CURRENT != RECORD_APPLICABLE != INFERENCE_SUPPORTED != RELIANCE_PERMITTED != ACTION_ADMISSIBLE"],
            {"failed_conditions": failed},
        )

    return _result(
        control,
        "LEGITIMACY_CHAIN_ESTABLISHED",
        "SEPARATE_ACTION_ADMISSIBILITY_REQUIRED",
        ["Replay/custody/legitimacy evidence is supportable but does not itself authorize action."],
    )


def evaluate_interacting_decisions(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Test whether individually valid decisions remain compatible in combination."""
    control = "INTERACTING_DECISION_CONDITION_STANDING"
    decisions = record.get("decisions")
    if not isinstance(decisions, Sequence) or isinstance(decisions, (str, bytes)) or not decisions:
        return _result(
            control,
            "NOT_ESTABLISHED",
            "REVIEW_REQUIRED",
            ["At least one governed decision is required."],
        )

    invalid = []
    for item in decisions:
        if not isinstance(item, Mapping) or not bool(item.get("individually_valid")):
            invalid.append(item.get("decision_id") if isinstance(item, Mapping) else None)
    if invalid:
        return _result(
            control,
            "CONSTITUENT_DECISION_NOT_VALID",
            "HOLD_NO_BIND",
            ["A constituent decision lacks individual standing."],
            {"invalid_decisions": invalid},
        )

    if not bool(record.get("interaction_assessed")):
        return _result(
            control,
            "INTERACTION_STANDING_NOT_ESTABLISHED",
            "REVIEW_REQUIRED",
            ["ALL_COMPONENT_DECISIONS_VALID != COMBINED_OPERATING_CONDITION_VALID"],
        )

    if not bool(record.get("interaction_basis_current", True)):
        return _result(
            control,
            "INTERACTION_BASIS_STALE",
            "REQUALIFICATION_REQUIRED",
            ["Current interaction validity must be positively established at the consequential crossing."],
        )

    if bool(record.get("emergent_exposure")) or not bool(record.get("intended_outcome_compatible")):
        return _result(
            control,
            "COMPOSITE_CONDITION_INCOMPATIBLE",
            "HOLD_NO_BIND",
            [
                "INDIVIDUALLY_VALID_DECISIONS != COMBINED_CONDITION_SAFE",
                "The interaction of valid decisions creates an incompatible or emergent consequence condition.",
            ],
        )

    return _result(
        control,
        "INTERACTING_DECISION_CONDITION_SUPPORTABLE",
        "SEPARATE_ACTION_ADMISSIBILITY_REQUIRED",
        ["Individual standing and interaction compatibility are both established without creating execution authority."],
    )
