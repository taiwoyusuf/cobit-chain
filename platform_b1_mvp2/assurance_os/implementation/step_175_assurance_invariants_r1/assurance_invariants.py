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
    """Distinguish missing evidence from established nonexistence."""
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
    """Evaluate whether the basis of a control remains supportable."""
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
    """Apply the Partial-Evidence Examination invariant."""
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


def evaluate_trust_anchor_succession(
    *,
    predecessor_anchor: str,
    successor_anchor: str,
    predecessor_authorized: bool,
    successor_cryptographically_capable: bool,
    succession_event_present: bool,
    succession_event_authenticated: bool,
    succession_scope_valid: bool,
    succession_current: bool,
) -> dict:
    """Require independently supportable predecessor-to-successor authority continuity.

    A historical checkpoint or valid predecessor does not automatically grant
    current standing to an unrelated replacement key. This extends Step 159's
    key-lifecycle/revocation design without replacing it.
    """
    same_anchor = predecessor_anchor == successor_anchor

    if same_anchor:
        succession_required = False
        succession_established = predecessor_authorized
    else:
        succession_required = True
        succession_established = all([
            predecessor_authorized,
            successor_cryptographically_capable,
            succession_event_present,
            succession_event_authenticated,
            succession_scope_valid,
            succession_current,
        ])

    if not predecessor_authorized:
        standing = "NOT_ESTABLISHED"
        reason = "PREDECESSOR_AUTHORITY_NOT_ESTABLISHED"
    elif not successor_cryptographically_capable:
        standing = "NOT_ESTABLISHED"
        reason = "SUCCESSOR_CRYPTOGRAPHIC_CAPABILITY_NOT_ESTABLISHED"
    elif succession_required and not succession_event_present:
        standing = "NOT_ESTABLISHED"
        reason = "SUCCESSION_EVENT_NOT_ESTABLISHED"
    elif succession_required and not succession_event_authenticated:
        standing = "NOT_ESTABLISHED"
        reason = "SUCCESSION_EVENT_NOT_AUTHENTICATED"
    elif succession_required and not succession_scope_valid:
        standing = "NOT_ESTABLISHED"
        reason = "SUCCESSION_SCOPE_NOT_VALID"
    elif succession_required and not succession_current:
        standing = "NOT_ESTABLISHED"
        reason = "SUCCESSION_NOT_CURRENT"
    else:
        standing = "SUPPORTABLE"
        reason = "AUTHORIZED_TRUST_ANCHOR_SUCCESSION_ESTABLISHED"

    return {
        "predecessor_anchor": predecessor_anchor,
        "successor_anchor": successor_anchor,
        "same_anchor": same_anchor,
        "succession_required": succession_required,
        "succession_established": succession_established,
        "successor_authority_standing": standing,
        "reason": reason,
        "binding_decision_made": False,
        "fail_closed": standing != "SUPPORTABLE",
    }
