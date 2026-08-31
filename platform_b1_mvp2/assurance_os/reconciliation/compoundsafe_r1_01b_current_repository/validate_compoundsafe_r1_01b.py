"""Deterministic repository-scope validator for CompoundSafe R1-01B.

This validator establishes correspondence only for artifacts tracked in the
current Git repository and the preserved Step 148B repository baseline. It
cannot establish completeness of untracked local/external backup material.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent
RECORD = HERE / "compoundsafe_r1_01b_reconciliation.json"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def find_module(baseline: dict, module_id: str) -> dict:
    for item in baseline.get("Modules", []):
        if item.get("ModuleId") == module_id:
            return item
    raise AssertionError(f"module {module_id} not found in Step 148B baseline")


def validate() -> dict:
    record = load_json(RECORD)

    baseline_path = ROOT / record["current_repository_inventory"]["historical_repository_baseline"]
    summary_path = ROOT / record["current_productization_evidence"]["family_summary"]
    domain_map_path = ROOT / record["current_repository_inventory"]["shared_domain_mapping"]
    master_register_path = ROOT / record["current_repository_inventory"]["master_capability_register"]

    required_paths = [baseline_path, summary_path, domain_map_path, master_register_path]
    required_paths.extend(ROOT / p for p in record["preserved_legacy_retained_objects"])
    missing = [str(p.relative_to(ROOT)) for p in required_paths if not p.is_file()]
    if missing:
        raise AssertionError(f"required tracked artifacts missing: {missing}")

    baseline = load_json(baseline_path)
    compounding = find_module(baseline, "COMPOUNDING")
    expected = record["step_148b_compoundsafe_baseline"]
    comparisons = {
        "BaselineClassification": expected["baseline_classification"],
        "MatchedFileCount": expected["matched_file_count"],
        "ImplementationFileCount": expected["implementation_file_count"],
        "DeclaredActiveSourceCount": expected["declared_active_source_count"],
        "DeclaredAuthoritativeEvidenceCount": expected["declared_authoritative_evidence_count"],
        "RetainedEvidencePathCount": expected["retained_evidence_path_count"],
        "TestFileCount": expected["test_file_count"],
        "ManifestFileCount": expected["manifest_file_count"],
    }
    mismatches = {
        key: {"expected": value, "actual": compounding.get(key)}
        for key, value in comparisons.items()
        if compounding.get(key) != value
    }
    if mismatches:
        raise AssertionError(f"Step 148B CompoundSafe baseline mismatch: {mismatches}")

    retained = [x.strip() for x in compounding.get("RetainedEvidencePaths", "").split("|") if x.strip()]
    expected_retained = record["preserved_legacy_retained_objects"]
    if sorted(retained) != sorted(expected_retained):
        raise AssertionError("recorded retained-object set does not match Step 148B baseline")

    summary = load_json(summary_path)
    if summary.get("standing") != "SUPPORTED_BOUNDED_SYNTHETIC":
        raise AssertionError("CompoundSafe current summary lost bounded synthetic standing")
    if not summary.get("synthetic", False):
        raise AssertionError("CompoundSafe current summary must remain synthetic")

    domain_map = load_json(domain_map_path)
    domains = domain_map.get("domains", {})
    if "COMPOUNDSAFE" not in domains:
        raise AssertionError("CompoundSafe absent from shared domain map")
    if not domains["COMPOUNDSAFE"].get("apply_shared_updates"):
        raise AssertionError("CompoundSafe must consume shared updates")

    if record["external_artifact_boundary"]["untracked_local_backups_or_reference_materials_exhaustively_compared"]:
        raise AssertionError("validator may not claim exhaustive untracked/external artifact comparison")

    statuses = record["r1_01_status"]
    if statuses["R1-01B_current_first_party_repository_reconciliation"] != "COMPLETE_FOR_TRACKED_REPOSITORY_SCOPE":
        raise AssertionError("tracked-repository R1-01B status not sealed")

    return {
        "status": "PASS",
        "tracked_repository_inventory": "ESTABLISHED",
        "legacy_retained_objects_verified": len(expected_retained),
        "current_compoundsafe_productization": "SUPPORTED_BOUNDED_SYNTHETIC",
        "shared_domain_mapping": "ESTABLISHED",
        "R1-01B": "COMPLETE_FOR_TRACKED_REPOSITORY_SCOPE",
        "external_untracked_artifact_exhaustiveness": "NOT_ESTABLISHED",
        "binding_authority_created": False,
    }


if __name__ == "__main__":
    print(json.dumps(validate(), indent=2))
