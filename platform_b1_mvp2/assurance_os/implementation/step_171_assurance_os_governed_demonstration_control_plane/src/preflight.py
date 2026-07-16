"""Pre-execution assurance preflight."""

from typing import Mapping

from .authority_revalidation import evaluate_authority
from .dependency_assurance import evaluate_dependencies
from .evidence_integrity import evaluate_evidence
from .identity_accountability import evaluate_identity
from .source_state import evaluate_source_states


def perform_preflight(fixture: Mapping[str, object]) -> dict:
    evidence = evaluate_evidence(fixture["evidence"])
    dependencies = evaluate_dependencies(fixture["dependencies"])
    sources = evaluate_source_states(fixture["source_states"])
    identity = evaluate_identity(fixture["identity"])
    authority = evaluate_authority(fixture["authority"])

    checks = {
        "evidence": evidence,
        "dependencies": dependencies,
        "source_states": sources,
        "identity": identity,
        "authority": authority,
    }

    passed = all(item["passed"] for item in checks.values())

    return {
        "passed": passed,
        "checks": checks,
        "result": "PASS" if passed else "FAIL_CLOSED",
    }
