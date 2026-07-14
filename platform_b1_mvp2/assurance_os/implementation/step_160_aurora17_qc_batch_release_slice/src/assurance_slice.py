from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

SCHEMA_VERSION = "1.0"
IMPLEMENTATION_VERSION = "160.1.0"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: Optional[datetime] = None) -> str:
    current = value or utc_now()
    return (
        current.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_utc(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        value = json.load(handle)

    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object in {path}")

    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def append_audit(
    project_root: Path,
    correlation_id: str,
    event_type: str,
    state: str,
    details: Dict[str, Any],
) -> Dict[str, Any]:
    event = {
        "event_id": str(uuid.uuid4()),
        "correlation_id": correlation_id,
        "event_type": event_type,
        "state": state,
        "recorded_at_utc": iso_utc(),
        "details": details,
    }

    audit_path = project_root / "runs" / "audit_events.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)

    with audit_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")

    return event


def load_paths(project_root: Path) -> Dict[str, Path]:
    return {
        "config": (
            project_root /
            "config" /
            "slice_config.json"
        ),
        "evidence": (
            project_root /
            "data" /
            "evidence" /
            "aurora17_qc_release_evidence.json"
        ),
        "source": (
            project_root /
            "data" /
            "source_state.json"
        ),
        "authority": (
            project_root /
            "data" /
            "authority.json"
        ),
        "seal": (
            project_root /
            "state" /
            "evidence_seal.json"
        ),
        "backup": (
            project_root /
            "backup" /
            "aurora17_qc_release_evidence.backup.json"
        ),
    }


def reset_runtime(project_root: Path) -> None:
    for relative in ("runs", "state", "backup"):
        target = project_root / relative

        if target.exists():
            shutil.rmtree(target)

        target.mkdir(parents=True, exist_ok=True)


def seal_evidence(
    project_root: Path,
    correlation_id: str,
) -> Dict[str, Any]:
    paths = load_paths(project_root)
    evidence = read_json(paths["evidence"])

    seal = {
        "seal_id": f"SEAL-{uuid.uuid4()}",
        "schema_version": SCHEMA_VERSION,
        "object_id": evidence["object_id"],
        "evidence_id": evidence["evidence_id"],
        "source_record_id": evidence["source_record_id"],
        "hash_algorithm": "SHA-256",
        "hash_value": sha256_file(paths["evidence"]),
        "canonical_content_hash": canonical_hash(evidence),
        "content_length_bytes": paths["evidence"].stat().st_size,
        "sealed_at_utc": iso_utc(),
        "sealed_by_actor_id": "ACTOR-QA-REVIEWER-001",
        "seal_status": "SEALED",
    }

    write_json(paths["seal"], seal)

    append_audit(
        project_root,
        correlation_id,
        "EVIDENCE_SEALED",
        "SEALED",
        {
            "evidence_id": seal["evidence_id"],
            "hash_algorithm": seal["hash_algorithm"],
            "hash_value": seal["hash_value"],
        },
    )

    return seal


def build_dependencies(
    evidence: Dict[str, Any],
    source: Dict[str, Any],
) -> List[Dict[str, Any]]:
    qc_results = evidence.get("qc_results", [])

    qc_results_pass = (
        bool(qc_results) and
        all(
            item.get("result") == "PASS"
            for item in qc_results
        )
    )

    results_complete = (
        source.get("qc_status") == "COMPLETE" and
        qc_results_pass
    )

    source_agreement = (
        evidence.get("source_record_id") ==
        source.get("source_record_id") and
        source.get("laboratory_result_state") ==
        "VERIFIED" and
        evidence.get("batch_id") ==
        source.get("batch_id")
    )

    deviation_disposition = (
        int(source.get("open_critical_deviations", 0)) == 0
    )

    sample_identity = (
        evidence.get("sample_id") ==
        source.get("sample_id")
    )

    raw = [
        (
            "DEP-QC-RESULTS",
            "QC_RESULTS_COMPLETE",
            results_complete,
            "COMPLETE",
        ),
        (
            "DEP-SOURCE-AGREEMENT",
            "SOURCE_SYSTEM_AGREEMENT",
            source_agreement,
            "AGREED",
        ),
        (
            "DEP-DEVIATION",
            "CRITICAL_DEVIATIONS_DISPOSITIONED",
            deviation_disposition,
            "ZERO_OPEN_CRITICAL",
        ),
        (
            "DEP-SAMPLE-IDENTITY",
            "SAMPLE_IDENTITY_MATCH",
            sample_identity,
            "MATCHED",
        ),
    ]

    return [
        {
            "dependency_id": dependency_id,
            "dependency_type": dependency_type,
            "required_state": required_state,
            "observed_state": (
                required_state
                if satisfied
                else "UNSATISFIED"
            ),
            "dependency_status": (
                "SATISFIED"
                if satisfied
                else "UNSATISFIED"
            ),
        }
        for (
            dependency_id,
            dependency_type,
            satisfied,
            required_state,
        ) in raw
    ]


def evaluate_authority(
    authority: Dict[str, Any],
    config: Dict[str, Any],
    now: datetime,
) -> Dict[str, Any]:
    present = bool(
        authority.get("authority_id") and
        authority.get("actor_id")
    )

    valid_from = (
        parse_utc(str(authority.get("valid_from_utc")))
        if present
        else now
    )

    valid_to = (
        parse_utc(str(authority.get("valid_to_utc")))
        if present
        else now
    )

    current = (
        present and
        valid_from <= now <= valid_to
    )

    status_valid = (
        authority.get("authority_status") ==
        "ACTIVE"
    )

    role_valid = (
        authority.get("role_id") in
        config["required_authority_roles"]
    )

    action_valid = (
        config["action_type"] in
        authority.get("allowed_action_types", [])
    )

    object_valid = (
        config["target_object_id"] in
        authority.get("object_scope", [])
    )

    consequence_valid = (
        config["action_consequence_level"] in
        authority.get("consequence_scope", [])
    )

    delegated = bool(
        authority.get("delegated", False)
    )

    valid = all(
        (
            present,
            current,
            status_valid,
            role_valid,
            action_valid,
            object_valid,
            consequence_valid,
        )
    )

    return {
        "authority_id": authority.get("authority_id"),
        "actor_id": authority.get("actor_id"),
        "role_id": authority.get("role_id"),
        "authority_present": present,
        "authority_valid": valid,
        "authority_current": current,
        "authority_in_scope": (
            role_valid and
            action_valid and
            object_valid and
            consequence_valid
        ),
        "authority_delegated": delegated,
        "authority_status": (
            "VALID"
            if valid
            else "INVALID"
        ),
        "valid_from_utc": authority.get("valid_from_utc"),
        "valid_to_utc": authority.get("valid_to_utc"),
    }


def build_display_states(
    result: Dict[str, Any],
) -> List[str]:
    states: List[str] = []

    if (
        result["integrity_state"] ==
        "REHASH_MISMATCH" or
        not result["evidence_sufficient"]
    ):
        states.append("EVIDENCE INSUFFICIENT")

    if not result["identity_verified"]:
        states.append("IDENTITY CONFLICT")

    if not result["dependencies_satisfied"]:
        states.append("DEPENDENCY UNSATISFIED")

    if not result["authority"]["authority_present"]:
        states.append("AUTHORITY ABSENT")
    elif not result["authority"]["authority_valid"]:
        states.append("AUTHORITY INVALID")

    if not result["human_accountability_identified"]:
        states.append(
            "HUMAN ACCOUNTABILITY MISSING"
        )

    if result["no_bind_state"] == "ACTIVE":
        states.extend(
            [
                "NO-BIND STATE ACTIVE",
                "ACTION HELD",
            ]
        )
    else:
        states.extend(
            [
                "ACTION ADMISSIBLE",
                "SOURCE-SYSTEM EXECUTION REQUIRED",
            ]
        )

    return list(dict.fromkeys(states))


def evaluate(
    project_root: Path,
    scenario_name: str,
) -> Dict[str, Any]:
    paths = load_paths(project_root)

    config = read_json(paths["config"])
    evidence = read_json(paths["evidence"])
    source = read_json(paths["source"])
    authority_record = read_json(paths["authority"])
    seal = read_json(paths["seal"])

    now = utc_now()
    correlation_id = str(uuid.uuid4())

    current_hash = sha256_file(paths["evidence"])
    canonical_current_hash = canonical_hash(evidence)

    integrity_verified = (
        seal.get("hash_algorithm") == "SHA-256" and
        current_hash == seal.get("hash_value") and
        canonical_current_hash ==
        seal.get("canonical_content_hash")
    )

    integrity_state = (
        "REHASH_VERIFIED"
        if integrity_verified
        else "REHASH_MISMATCH"
    )

    identity_verified = all(
        (
            evidence.get("object_id") ==
            config.get("target_object_id"),

            evidence.get("batch_id") ==
            source.get("batch_id"),

            evidence.get("sample_id") ==
            source.get("sample_id"),

            evidence.get("source_record_id") ==
            source.get("source_record_id"),
        )
    )

    dependencies = build_dependencies(
        evidence,
        source,
    )

    dependencies_satisfied = all(
        item["dependency_status"] ==
        "SATISFIED"
        for item in dependencies
    )

    authority = evaluate_authority(
        authority_record,
        config,
        now,
    )

    timing_valid = (
        parse_utc(
            source["release_window_start_utc"]
        ) <= now <=
        parse_utc(
            source["release_window_end_utc"]
        )
    )

    human_accountability_identified = bool(
        authority.get("actor_id") and
        authority.get("role_id")
    )

    evidence_sufficient = all(
        (
            integrity_verified,
            identity_verified,
            dependencies_satisfied,
            bool(
                evidence.get(
                    "reviewed_by_actor_id"
                )
            ),
            evidence.get("review_status") ==
            "REVIEWED",
        )
    )

    reasons: List[str] = []

    if not integrity_verified:
        reasons.append(
            "EVIDENCE_REHASH_MISMATCH"
        )

    if not identity_verified:
        reasons.append(
            "IDENTITY_CONFLICT"
        )

    if not dependencies_satisfied:
        reasons.append(
            "DEPENDENCY_UNSATISFIED"
        )

    if not authority["authority_present"]:
        reasons.append(
            "AUTHORITY_ABSENT"
        )
    elif not authority["authority_valid"]:
        reasons.append(
            "AUTHORITY_INVALID"
        )

    if not timing_valid:
        reasons.append(
            "TIMING_INVALID"
        )

    if not human_accountability_identified:
        reasons.append(
            "HUMAN_ACCOUNTABILITY_NOT_IDENTIFIED"
        )

    if (
        not evidence_sufficient and
        "EVIDENCE_REHASH_MISMATCH" not in reasons
    ):
        reasons.append(
            "EVIDENCE_INSUFFICIENT"
        )

    no_bind_active = bool(reasons)

    evaluation_id = (
        f"EVAL-{uuid.uuid4()}"
    )

    action_id = config["action_id"]

    result: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "implementation_version": (
            IMPLEMENTATION_VERSION
        ),
        "scenario_name": scenario_name,
        "correlation_id": correlation_id,
        "evaluation_id": evaluation_id,
        "evaluated_at_utc": iso_utc(now),
        "object_id": config["target_object_id"],
        "action_id": action_id,
        "action_type": config["action_type"],
        "action_consequence_level": (
            config["action_consequence_level"]
        ),
        "identity_verified": identity_verified,
        "integrity_state": integrity_state,
        "sealed_hash": seal.get("hash_value"),
        "current_hash": current_hash,
        "evidence_sufficient": evidence_sufficient,
        "dependencies": dependencies,
        "dependencies_satisfied": (
            dependencies_satisfied
        ),
        "authority": authority,
        "timing_valid": timing_valid,
        "human_accountability_identified": (
            human_accountability_identified
        ),
        "security_trust_state": "NORMAL",
        "no_bind_state": (
            "ACTIVE"
            if no_bind_active
            else "INACTIVE"
        ),
        "no_bind_reasons": reasons,
        "action_admissibility_state": (
            "HELD"
            if no_bind_active
            else "ADMISSIBLE"
        ),
        "source_system_execution_required": True,
        "execution_performed": False,
        "human_binding_decision_performed": False,
        "official_source_system": (
            source.get("source_system_name")
        ),
        "official_source_record_id": (
            source.get("source_record_id")
        ),
    }

    result["display_states"] = (
        build_display_states(result)
    )

    run_dir = (
        project_root /
        "runs" /
        scenario_name
    )

    run_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    no_bind_record = {
        "no_bind_id": f"NB-{uuid.uuid4()}",
        "action_id": action_id,
        "object_id": config["target_object_id"],
        "activated": no_bind_active,
        "no_bind_state": (
            "NO-BIND STATE ACTIVE"
            if no_bind_active
            else "INACTIVE"
        ),
        "reason_codes": reasons,
        "activated_at_utc": (
            iso_utc(now)
            if no_bind_active
            else None
        ),
        "resolution_required": no_bind_active,
        "silence_is_not_consent": True,
    }

    admissibility = {
        "admissibility_id": (
            f"ADM-{uuid.uuid4()}"
        ),
        "action_id": action_id,
        "object_id": config["target_object_id"],
        "evaluation_id": evaluation_id,
        "decision_state": (
            "ACTION_HELD"
            if no_bind_active
            else "ACTION_ADMISSIBLE"
        ),
        "rationale": (
            reasons
            if reasons
            else [
                "ALL_REQUIRED_ASSURANCE_CONDITIONS_POSITIVELY_SATISFIED"
            ]
        ),
        "decided_at_utc": iso_utc(now),
        "source_execution_required": True,
        "execution_performed": False,
        "decision_boundary": (
            "ASSURANCE EVALUATION ONLY - NOT EXECUTION"
        ),
    }

    display_contract = {
        "display_contract_id": (
            f"DISPLAY-{uuid.uuid4()}"
        ),
        "correlation_id": correlation_id,
        "object_id": config["target_object_id"],
        "action_id": action_id,
        "generated_at_utc": iso_utc(now),
        "expires_at_utc": iso_utc(
            now +
            timedelta(
                minutes=int(
                    config[
                        "display_contract_ttl_minutes"
                    ]
                )
            )
        ),
        "display_authority": (
            "DISPLAY / WITNESS ONLY"
        ),
        "display_states": (
            result["display_states"]
        ),
        "allowed_fields": (
            config["display_allowed_fields"]
        ),
        "prohibited_controls": (
            config["display_prohibited_controls"]
        ),
        "human_prompt": (
            "STOP: GOVERNANCE HOLD ACTIVE. "
            "AUTHORIZED HUMAN REVIEW AND "
            "GOVERNED RESOLUTION ARE REQUIRED."
            if no_bind_active
            else
            "ASSURANCE CONDITIONS ARE SATISFIED. "
            "AUTHORIZED HUMAN DECISION AND "
            "SOURCE-SYSTEM EXECUTION ARE STILL REQUIRED."
        ),
        "source_of_truth": {
            "system": (
                source.get("source_system_name")
            ),
            "record_id": (
                source.get("source_record_id")
            ),
        },
        "can_approve": False,
        "can_release": False,
        "can_override": False,
        "can_resolve_no_bind": False,
        "can_execute": False,
    }

    reconstruction = {
        "reconstruction_id": (
            f"RECON-{uuid.uuid4()}"
        ),
        "scenario_name": scenario_name,
        "correlation_id": correlation_id,
        "object_id": config["target_object_id"],
        "action_id": action_id,
        "generated_at_utc": iso_utc(now),
        "chronology": [
            {
                "event": "EVIDENCE_SEALED",
                "time": seal.get("sealed_at_utc"),
            },
            {
                "event": "REHASH_EVALUATED",
                "time": iso_utc(now),
                "state": integrity_state,
            },
            {
                "event": "DEPENDENCIES_EVALUATED",
                "time": iso_utc(now),
                "state": dependencies_satisfied,
            },
            {
                "event": "AUTHORITY_EVALUATED",
                "time": iso_utc(now),
                "state": (
                    authority["authority_status"]
                ),
            },
            {
                "event": "NO_BIND_EVALUATED",
                "time": iso_utc(now),
                "state": (
                    no_bind_record[
                        "no_bind_state"
                    ]
                ),
            },
            {
                "event": "ADMISSIBILITY_RECORDED",
                "time": iso_utc(now),
                "state": (
                    admissibility[
                        "decision_state"
                    ]
                ),
            },
        ],
        "evidence_seal_reference": (
            seal["seal_id"]
        ),
        "current_evidence_hash": current_hash,
        "source_system_reference": (
            source.get("source_record_id")
        ),
        "authority_reference": (
            authority.get("authority_id")
        ),
        "no_bind_reference": (
            no_bind_record["no_bind_id"]
        ),
        "admissibility_reference": (
            admissibility["admissibility_id"]
        ),
        "unresolved_gaps": reasons,
        "official_execution_record": None,
        "execution_performed": False,
    }

    write_json(
        run_dir / "evaluation.json",
        result,
    )

    write_json(
        run_dir / "no_bind_state.json",
        no_bind_record,
    )

    write_json(
        run_dir / "action_admissibility.json",
        admissibility,
    )

    write_json(
        run_dir / "display_contract.json",
        display_contract,
    )

    write_json(
        run_dir / "reconstruction.json",
        reconstruction,
    )

    append_audit(
        project_root,
        correlation_id,
        "ASSURANCE_EVALUATED",
        result["action_admissibility_state"],
        {
            "scenario_name": scenario_name,
            "integrity_state": integrity_state,
            "no_bind_state": (
                result["no_bind_state"]
            ),
            "reasons": reasons,
        },
    )

    return result


def tamper_evidence(
    project_root: Path,
) -> None:
    evidence_path = (
        load_paths(project_root)["evidence"]
    )

    evidence = read_json(evidence_path)

    evidence["assay_percent"] = 88.4
    evidence["tampered_for_demo"] = True
    evidence["tamper_note"] = (
        "Synthetic post-seal change used to "
        "prove fail-closed rehash behavior."
    )

    write_json(
        evidence_path,
        evidence,
    )


def backup_and_verify(
    project_root: Path,
    expected_hash: str,
) -> Dict[str, Any]:
    paths = load_paths(project_root)

    paths["backup"].parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    shutil.copy2(
        paths["evidence"],
        paths["backup"],
    )

    backup_hash = sha256_file(
        paths["backup"]
    )

    verified = (
        backup_hash == expected_hash
    )

    result = {
        "backup_path": str(
            paths["backup"].relative_to(
                project_root
            )
        ),
        "backup_hash": backup_hash,
        "expected_hash": expected_hash,
        "backup_integrity_verified": verified,
        "verified_at_utc": iso_utc(),
    }

    write_json(
        project_root /
        "backup" /
        "backup_verification.json",
        result,
    )

    if not verified:
        raise RuntimeError(
            "Backup integrity verification failed."
        )

    return result


def restore_from_backup(
    project_root: Path,
    expected_hash: str,
) -> Dict[str, Any]:
    paths = load_paths(project_root)

    backup_hash = sha256_file(
        paths["backup"]
    )

    if backup_hash != expected_hash:
        raise RuntimeError(
            "Backup hash does not match the "
            "sealed evidence hash."
        )

    shutil.copy2(
        paths["backup"],
        paths["evidence"],
    )

    restored_hash = sha256_file(
        paths["evidence"]
    )

    verified = (
        restored_hash == expected_hash
    )

    result = {
        "restored_hash": restored_hash,
        "expected_hash": expected_hash,
        "restore_integrity_verified": verified,
        "restored_at_utc": iso_utc(),
    }

    write_json(
        project_root /
        "backup" /
        "restore_verification.json",
        result,
    )

    if not verified:
        raise RuntimeError(
            "Restored evidence integrity "
            "verification failed."
        )

    return result


def write_scenario_csv(
    path: Path,
    scenarios: Iterable[Dict[str, Any]],
) -> None:
    rows = list(scenarios)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "Scenario",
        "IntegrityState",
        "IdentityVerified",
        "DependenciesSatisfied",
        "EvidenceSufficient",
        "AuthorityValid",
        "TimingValid",
        "HumanAccountabilityIdentified",
        "NoBindState",
        "ActionAdmissibilityState",
        "DisplayStates",
        "SourceExecutionRequired",
        "ExecutionPerformed",
    ]

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for item in rows:
            writer.writerow(
                {
                    "Scenario": (
                        item["scenario_name"]
                    ),
                    "IntegrityState": (
                        item["integrity_state"]
                    ),
                    "IdentityVerified": (
                        item["identity_verified"]
                    ),
                    "DependenciesSatisfied": (
                        item[
                            "dependencies_satisfied"
                        ]
                    ),
                    "EvidenceSufficient": (
                        item["evidence_sufficient"]
                    ),
                    "AuthorityValid": (
                        item["authority"][
                            "authority_valid"
                        ]
                    ),
                    "TimingValid": (
                        item["timing_valid"]
                    ),
                    "HumanAccountabilityIdentified": (
                        item[
                            "human_accountability_identified"
                        ]
                    ),
                    "NoBindState": (
                        item["no_bind_state"]
                    ),
                    "ActionAdmissibilityState": (
                        item[
                            "action_admissibility_state"
                        ]
                    ),
                    "DisplayStates": "; ".join(
                        item["display_states"]
                    ),
                    "SourceExecutionRequired": (
                        item[
                            "source_system_execution_required"
                        ]
                    ),
                    "ExecutionPerformed": (
                        item["execution_performed"]
                    ),
                }
            )


def report_markdown(
    summary: Dict[str, Any],
) -> str:
    scenario_rows = []

    for scenario in summary["scenarios"]:
        scenario_rows.append(
            "| {name} | {integrity} | {evidence} | "
            "{no_bind} | {admissibility} | {execution} |".format(
                name=scenario["scenario_name"],
                integrity=scenario["integrity_state"],
                evidence=scenario["evidence_sufficient"],
                no_bind=scenario["no_bind_state"],
                admissibility=scenario[
                    "action_admissibility_state"
                ],
                execution=scenario[
                    "execution_performed"
                ],
            )
        )

    return "\n".join(
        [
            "# Step 160 - AURORA-17 QC and Human Batch-Release Implementation Slice",
            "",
            "**Local non-production implementation only. No PHI, company production data, production connector, autonomous release, or regulatory-validation claim.**",
            "",
            "## Implemented vertical slice",
            "",
            "- Canonical synthetic AURORA-17 batch identity",
            "- Mock laboratory source-system record",
            "- SHA-256 evidence seal and rehash verification",
            "- QC workflow dependency evaluation",
            "- Mock authorized batch-releaser evaluation",
            "- Fail-closed No-Bind activation",
            "- Action-admissibility record",
            "- Expiring RAMAT display-only contract",
            "- Audit events and governance reconstruction package",
            "- Local backup, restore, and integrity verification",
            "",
            "## Demonstration results",
            "",
            "| Scenario | Integrity | Evidence sufficient | No-Bind | Admissibility | Execution performed |",
            "|---|---|---:|---|---|---:|",
            *scenario_rows,
            "",
            "## Required proof",
            "",
            f"- Baseline success: **{summary['checks']['baseline_success']}**",
            f"- Tamper detection: **{summary['checks']['tamper_detection']}**",
            f"- Fail-closed No-Bind: **{summary['checks']['fail_closed_no_bind']}**",
            f"- Recovery integrity: **{summary['checks']['recovery_integrity']}**",
            f"- Recovery success: **{summary['checks']['recovery_success']}**",
            f"- Display-only boundary: **{summary['checks']['display_only_boundary']}**",
            f"- No execution performed: **{summary['checks']['no_execution_performed']}**",
            "",
            "## Locked boundaries",
            "",
            "- Platform B v1 was not modified.",
            "- Thread D v1 was not modified.",
            "- Platform B1 performed local assurance evaluation only.",
            "- RAMAT output remained DISPLAY / WITNESS ONLY.",
            "- Qualified human authority remains required for release.",
            "- Official execution remains in the governed source system.",
            "- Action admissibility is not execution.",
            "",
            "**STEP 160 AURORA-17 QC AND HUMAN BATCH-RELEASE IMPLEMENTATION SLICE COMPLETE**",
            "",
            "**FURTHER IMPLEMENTATION REQUIRES A NEW GOVERNED SCOPE REVIEW**",
            "",
        ]
    )


def validate_result_contract(
    project_root: Path,
    result: Dict[str, Any],
    expected: str,
) -> None:
    run_dir = (
        project_root /
        "runs" /
        result["scenario_name"]
    )

    display = read_json(
        run_dir /
        "display_contract.json"
    )

    prohibited = set(
        display["prohibited_controls"]
    )

    required_prohibited = {
        "approve",
        "release",
        "override",
        "resolve_no_bind",
        "execute_action",
    }

    if (
        display["display_authority"] !=
        "DISPLAY / WITNESS ONLY"
    ):
        raise AssertionError(
            "Display authority boundary failed."
        )

    if not required_prohibited.issubset(
        prohibited
    ):
        raise AssertionError(
            "Display contract omitted "
            "prohibited controls."
        )

    if any(
        display.get(field) is not False
        for field in (
            "can_approve",
            "can_release",
            "can_override",
            "can_resolve_no_bind",
            "can_execute",
        )
    ):
        raise AssertionError(
            "Display contract exposes "
            "binding capability."
        )

    if (
        result["action_admissibility_state"] !=
        expected
    ):
        raise AssertionError(
            f"Scenario {result['scenario_name']} "
            f"expected {expected} but produced "
            f"{result['action_admissibility_state']}"
        )

    if result["execution_performed"]:
        raise AssertionError(
            "Assurance slice must not execute "
            "the regulated action."
        )


def run_demo(
    project_root: Path,
) -> Dict[str, Any]:
    reset_runtime(project_root)

    correlation_id = str(uuid.uuid4())

    seal = seal_evidence(
        project_root,
        correlation_id,
    )

    backup_result = backup_and_verify(
        project_root,
        seal["hash_value"],
    )

    success_before = evaluate(
        project_root,
        "01_success_before_tamper",
    )

    validate_result_contract(
        project_root,
        success_before,
        "ADMISSIBLE",
    )

    tamper_evidence(project_root)

    tamper_failure = evaluate(
        project_root,
        "02_tamper_failure",
    )

    validate_result_contract(
        project_root,
        tamper_failure,
        "HELD",
    )

    restore_result = restore_from_backup(
        project_root,
        seal["hash_value"],
    )

    recovery_success = evaluate(
        project_root,
        "03_recovery_success",
    )

    validate_result_contract(
        project_root,
        recovery_success,
        "ADMISSIBLE",
    )

    scenarios = [
        success_before,
        tamper_failure,
        recovery_success,
    ]

    checks = {
        "baseline_success": (
            success_before[
                "action_admissibility_state"
            ] == "ADMISSIBLE"
        ),
        "tamper_detection": (
            tamper_failure["integrity_state"] ==
            "REHASH_MISMATCH"
        ),
        "fail_closed_no_bind": (
            tamper_failure["no_bind_state"] ==
            "ACTIVE" and
            tamper_failure[
                "action_admissibility_state"
            ] == "HELD" and
            "EVIDENCE INSUFFICIENT" in
            tamper_failure["display_states"] and
            "NO-BIND STATE ACTIVE" in
            tamper_failure["display_states"] and
            "ACTION HELD" in
            tamper_failure["display_states"]
        ),
        "backup_integrity": (
            backup_result[
                "backup_integrity_verified"
            ]
        ),
        "recovery_integrity": (
            restore_result[
                "restore_integrity_verified"
            ]
        ),
        "recovery_success": (
            recovery_success[
                "action_admissibility_state"
            ] == "ADMISSIBLE"
        ),
        "display_only_boundary": all(
            read_json(
                project_root /
                "runs" /
                item["scenario_name"] /
                "display_contract.json"
            )["display_authority"] ==
            "DISPLAY / WITNESS ONLY"
            for item in scenarios
        ),
        "no_execution_performed": all(
            not item["execution_performed"]
            for item in scenarios
        ),
        "platform_b_v1_modified": False,
        "thread_d_v1_modified": False,
        "production_integration_performed": False,
        "phi_used": False,
    }

    positive_check_keys = (
        "baseline_success",
        "tamper_detection",
        "fail_closed_no_bind",
        "backup_integrity",
        "recovery_integrity",
        "recovery_success",
        "display_only_boundary",
        "no_execution_performed",
    )

    negative_check_keys = (
        "platform_b_v1_modified",
        "thread_d_v1_modified",
        "production_integration_performed",
        "phi_used",
    )

    overall_status = (
        "PASS"
        if (
            all(
                checks[key]
                for key in positive_check_keys
            ) and
            not any(
                checks[key]
                for key in negative_check_keys
            )
        )
        else "FAIL"
    )

    summary = {
        "step": "160",
        "title": (
            "AURORA-17 QC and Human "
            "Batch-Release Implementation Slice"
        ),
        "implementation_version": (
            IMPLEMENTATION_VERSION
        ),
        "generated_at_utc": iso_utc(),
        "overall_status": overall_status,
        "implementation_boundary": (
            "LOCAL NON-PRODUCTION "
            "IMPLEMENTATION SLICE ONLY"
        ),
        "scenario_count": len(scenarios),
        "checks": checks,
        "sealed_evidence_hash": (
            seal["hash_value"]
        ),
        "backup_verification": backup_result,
        "restore_verification": restore_result,
        "scenarios": scenarios,
        "architecture_boundaries": {
            "platform_b_v1": (
                "ARCHITECTURE LOCKED - NOT MODIFIED"
            ),
            "thread_d_v1": (
                "ARCHITECTURE LOCKED - NOT MODIFIED"
            ),
            "platform_b1": (
                "LOCAL ASSURANCE EVALUATION ONLY"
            ),
            "ramat_vision": (
                "DISPLAY / WITNESS ONLY"
            ),
            "human_authority": (
                "REQUIRED FOR BINDING RELEASE DECISION"
            ),
            "source_system": (
                "OFFICIAL EXECUTION REQUIRED"
            ),
        },
    }

    report_json_path = (
        project_root /
        "STEP_160_AURORA_17_QC_BATCH_RELEASE_IMPLEMENTATION_SLICE.json"
    )

    report_csv_path = (
        project_root /
        "STEP_160_AURORA_17_QC_BATCH_RELEASE_IMPLEMENTATION_SLICE.csv"
    )

    report_md_path = (
        project_root /
        "STEP_160_AURORA_17_QC_BATCH_RELEASE_IMPLEMENTATION_SLICE.md"
    )

    write_json(
        report_json_path,
        summary,
    )

    write_scenario_csv(
        report_csv_path,
        scenarios,
    )

    write_text(
        report_md_path,
        report_markdown(summary),
    )

    if overall_status != "PASS":
        raise RuntimeError(
            "Step 160 implementation "
            "validation failed."
        )

    return summary


def verify_existing(
    project_root: Path,
) -> Dict[str, Any]:
    summary_path = (
        project_root /
        "STEP_160_AURORA_17_QC_BATCH_RELEASE_IMPLEMENTATION_SLICE.json"
    )

    summary = read_json(summary_path)

    if summary.get("overall_status") != "PASS":
        raise RuntimeError(
            "Existing Step 160 summary is not PASS."
        )

    if int(summary.get("scenario_count", 0)) != 3:
        raise RuntimeError(
            "Existing Step 160 summary does not "
            "contain three scenarios."
        )

    return summary


def main(
    argv: Optional[List[str]] = None,
) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "AURORA-17 local assurance "
            "implementation slice"
        )
    )

    parser.add_argument(
        "--project-root",
        required=True,
        help="Step 160 implementation root",
    )

    parser.add_argument(
        "command",
        choices=(
            "run-demo",
            "verify",
        ),
    )

    args = parser.parse_args(argv)

    project_root = Path(
        args.project_root
    ).resolve()

    if args.command == "run-demo":
        summary = run_demo(project_root)
    else:
        summary = verify_existing(
            project_root
        )

    print(
        json.dumps(
            {
                "status": (
                    summary["overall_status"]
                ),
                "scenario_count": (
                    summary["scenario_count"]
                ),
            }
        )
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())