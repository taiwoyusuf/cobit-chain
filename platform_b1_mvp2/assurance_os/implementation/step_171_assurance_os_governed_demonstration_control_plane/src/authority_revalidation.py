"""Authority validity, availability, delegation, expiry, and timing evaluation."""

from typing import Mapping


REQUIRED_TRUE_FIELDS = (
    "present",
    "valid",
    "current",
    "delegated",
    "available",
    "not_expired",
    "timing_valid",
)


def evaluate_authority(authority: Mapping[str, object]) -> dict:
    dimensions = {
        field: authority.get(field) is True
        for field in REQUIRED_TRUE_FIELDS
    }

    silent = authority.get("silent") is True
    revoked = authority.get("revoked") is True

    passed = (
        all(dimensions.values())
        and not silent
        and not revoked
    )

    failure_reasons = [
        field.upper()
        for field, valid in dimensions.items()
        if not valid
    ]

    if silent:
        failure_reasons.append("SILENT")

    if revoked:
        failure_reasons.append("REVOKED")

    return {
        "passed": passed,
        "dimensions": dimensions,
        "silent": silent,
        "revoked": revoked,
        "failure_reasons": sorted(failure_reasons),
        "no_bind": not passed,
        "result": "PASS" if passed else "NO_BIND",
    }
