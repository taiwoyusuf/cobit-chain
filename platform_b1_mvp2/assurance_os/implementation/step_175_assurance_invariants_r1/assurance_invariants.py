"""Executable assurance invariants for COBIT-Chain / Assurance Engineering.

This module is intentionally bounded. It does not grant regulatory authority,
release product, or overwrite historical evidence. Outputs are nonbinding
assurance determinations for downstream governed review.
"""

VSA_STATES = {
    "SUPPORTABLE",
    "CONDITIONALLY_SUPPORTABLE",
    "NOT_ESTABLISHED",
    "REASSESSMENT_REQUIRED",
    "NO_BIND",
}


def classify_absence(*, observed: bool, search_sufficient: bool) -> dict:
    """Distinguish missing evidence from established nonexistence.

    ABSENCE_UNRESOLVED means an item was not observed, but the examination was
    insufficient to establish that the item does not exist.
    """
    if observed:
        state = "PRESENT"
        established_absence = False
    elif search_sufficient:
        state = "ABSENT_ESTABLISHED"
        established_absence = True
    else:
        state = "ABSENCE_UNRESOLVED"
        established_absence = False

    return {
        "state": state,
        "observed": bool(observed),
        "search_sufficient": bool(search_sufficient),
        "established_absence": established_absence,
        "fail_closed": state == "ABSENCE_UNRESOLVED",
    }


def evaluate_control_basis(conditions: list[dict]) -> dict:
    """Evaluate whether the basis of a control remains supportable.

    This is distinct from whether the control code/process executed correctly.
    Each required condition is evaluated for presence, currency, integrity and
    agreement. Unresolved absence is preserved explicitly.
    """
    evaluated = []
    failures = []
    unresolved = []

    for condition in conditions:
        name = condition.get("name", "UNNAMED_CONDITION")
        required = bool(condition.get("required", True))
        observed = bool(condition.get("present", False))
        search_sufficient = bool(condition.get("search_sufficient", observed))
        absence = classify_absence(
            observed=observed,
            search_sufficient=search_sufficient,
        )
        checks = {
            "present": observed,
            "current": bool(condition.get("current", False)),
            "integrity": bool(condition.get("integrity", False)),
            "agrees": bool(condition.get("agrees", False)),
        }

        if not required:
            passed = True
        else:
            passed = all(checks.values())

        if required and absence["state"] == "ABSENCE_UNRESOLVED":
            unresolved.append(name)
        elif required and not passed:
            failures.append(name)

        evaluated.append({
            "name": name,
            "required": required,
            "absence_state": absence["state"],
            "checks": checks,
            "passed": passed,
        })

    if unresolved:
        standing = "NOT_ESTABLISHED"
        reason = "REQUIRED_CONTROL_BASIS_ABSENCE_UNRESOLVED"
    elif failures:
        standing = "REASSESSMENT_REQUIRED"
        reason = "CONTROL_BASIS_CONDITION_FAILED"
    else:
        standing = "SUPPORTABLE"
        reason = "CONTROL_BASIS_CURRENTLY_SUPPORTED"

    return {
        "standing": standing,
        "reason": reason,
        "unresolved": unresolved,
        "failures": failures,
        "evaluated": evaluated,
        "binding_decision_made": False,
        "fail_closed": standing != "SUPPORTABLE",
    }


def examine_partial_evidence(
    *,
    prior_state: str,
    required_dimensions: list[str],
    evidence: list[dict],
) -> dict:
    """Apply the Partial-Evidence Examination invariant.

    Added evidence can narrow, preserve or support a conclusion, but cannot
    expose certainty beyond the dimensions that are currently established.
    Conflicting evidence prevents SUPPORTABLE standing.
    """
    if prior_state not in VSA_STATES:
        raise ValueError("unknown prior_state")

    established = set()
    conflicts = set()
    unresolved = set()

    for item in evidence:
        dimension = item.get("dimension")
        if not dimension:
            continue
        state = item.get("state", "UNRESOLVED")
        if state == "ESTABLISHED":
            established.add(dimension)
        elif state == "CONFLICTING":
            conflicts.add(dimension)
        else:
            unresolved.add(dimension)

    required = set(required_dimensions)
    missing = required - established

    if conflicts & required:
        resulting_state = "NOT_ESTABLISHED"
        reason = "REQUIRED_EVIDENCE_CONFLICTING"
    elif missing:
        # Do not upgrade to SUPPORTABLE while required dimensions remain absent.
        if prior_state == "SUPPORTABLE":
            resulting_state = "REASSESSMENT_REQUIRED"
        elif prior_state == "CONDITIONALLY_SUPPORTABLE":
            resulting_state = "REASSESSMENT_REQUIRED"
        else:
            resulting_state = prior_state
        reason = "PARTIAL_EVIDENCE_INSUFFICIENT_FOR_FULL_SUPPORT"
    else:
        resulting_state = "SUPPORTABLE"
        reason = "ALL_REQUIRED_EVIDENCE_DIMENSIONS_ESTABLISHED"

    return {
        "prior_state": prior_state,
        "resulting_state": resulting_state,
        "required_dimensions": sorted(required),
        "established_dimensions": sorted(established),
        "conflicting_dimensions": sorted(conflicts),
        "unresolved_dimensions": sorted(unresolved),
        "missing_required_dimensions": sorted(missing),
        "reason": reason,
        "binding_decision_made": False,
    }


def evaluate_intervention_viability(
    *,
    authority_valid: bool,
    consequence_alterable: bool,
    intervention_window_open: bool,
) -> dict:
    """Separate authority from the physical/temporal ability to intervene."""
    if not authority_valid:
        state = "NO_BIND"
        reason = "AUTHORITY_NOT_ESTABLISHED"
    elif not consequence_alterable or not intervention_window_open:
        state = "INTERVENTION_NOT_VIABLE"
        reason = "CONSEQUENCE_NO_LONGER_ALTERABLE"
    else:
        state = "INTERVENTION_VIABLE"
        reason = "AUTHORITY_AND_INTERVENTION_WINDOW_ESTABLISHED"

    return {
        "state": state,
        "authority_valid": bool(authority_valid),
        "consequence_alterable": bool(consequence_alterable),
        "intervention_window_open": bool(intervention_window_open),
        "reason": reason,
        "binding_decision_made": False,
    }


def evaluate_restraint_claim(
    *,
    action_blocked: bool,
    alternate_paths_excluded: bool,
    consequence_observed_prevented: bool,
) -> dict:
    """Prevent an action-block event from being overstated as harm prevention."""
    if not action_blocked:
        state = "RESTRAINT_NOT_ESTABLISHED"
    elif not alternate_paths_excluded:
        state = "ACTION_BLOCKED_ONLY"
    elif not consequence_observed_prevented:
        state = "RESTRAINT_ESTABLISHED_CONSEQUENCE_UNRESOLVED"
    else:
        state = "VERIFIED_RESTRAINT"

    return {
        "state": state,
        "action_blocked": bool(action_blocked),
        "alternate_paths_excluded": bool(alternate_paths_excluded),
        "consequence_observed_prevented": bool(consequence_observed_prevented),
        "binding_decision_made": False,
    }
