"""Read-only validation of immutable Step 170 references."""

from typing import Iterable, Mapping


REQUIRED_REFERENCE_CLASSES = {
    "ACTION_ADMISSIBILITY",
    "EVALUATION",
    "PASSPORT",
    "SEAL",
    "AUDIT_EVENT",
    "BACKUP",
    "RECONSTRUCTION",
}


def validate_reference(reference: Mapping[str, object], canonical_commit: str) -> dict:
    valid = (
        reference.get("canonical_commit") == canonical_commit
        and reference.get("read_only") is True
        and reference.get("evidence_class") in REQUIRED_REFERENCE_CLASSES
        and isinstance(reference.get("relative_path"), str)
        and bool(reference.get("relative_path"))
        and isinstance(reference.get("sha256"), str)
        and len(str(reference.get("sha256"))) == 64
    )

    return {
        "valid": valid,
        "canonical_commit": canonical_commit,
        "read_only": True,
        "evidence_class": reference.get("evidence_class"),
        "relative_path": reference.get("relative_path"),
    }


def validate_reference_set(
    references: Iterable[Mapping[str, object]],
    canonical_commit: str,
) -> dict:
    results = [
        validate_reference(reference, canonical_commit)
        for reference in references
    ]

    return {
        "passed": bool(results) and all(item["valid"] for item in results),
        "results": results,
        "canonical_commit": canonical_commit,
    }
