"""Evidence-integrity and provenance evaluation."""

from typing import Mapping


def evaluate_evidence(evidence: Mapping[str, object]) -> dict:
    provenance_ok = evidence.get("provenance") == "SYNTHETIC"
    hash_ok = evidence.get("hash_matches") is True
    seal_ok = evidence.get("seal_valid") is True
    sufficient = evidence.get("sufficient") is True
    passed = provenance_ok and hash_ok and seal_ok and sufficient

    return {
        "passed": passed,
        "provenance_ok": provenance_ok,
        "hash_ok": hash_ok,
        "seal_ok": seal_ok,
        "sufficient": sufficient,
        "result": "PASS" if passed else "FAIL_CLOSED",
    }
