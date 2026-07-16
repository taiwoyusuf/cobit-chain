"""Identity, role, mapping, and accountability verification."""

from typing import Mapping


def evaluate_identity(identity: Mapping[str, object]) -> dict:
    identity_present = bool(identity.get("identity_id"))
    role_valid = identity.get("role_valid") is True
    mapping_valid = identity.get("mapping_valid") is True

    accountable_human = (
        identity.get("accountable_human_identified") is True
        and bool(identity.get("accountable_human_id"))
    )

    passed = (
        identity_present
        and role_valid
        and mapping_valid
        and accountable_human
    )

    return {
        "passed": passed,
        "identity_present": identity_present,
        "role_valid": role_valid,
        "mapping_valid": mapping_valid,
        "accountable_human_identified": accountable_human,
        "binding_authority": "IDENTIFIED_ACCOUNTABLE_HUMAN_ONLY",
        "result": "PASS" if passed else "FAIL_CLOSED",
    }
