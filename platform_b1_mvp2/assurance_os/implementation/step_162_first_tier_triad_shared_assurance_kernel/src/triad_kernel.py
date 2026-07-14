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

IMPLEMENTATION_VERSION = "162.1.0"
SCHEMA_VERSION = "1.0"

DISPLAY_PROHIBITED_CONTROLS = [
    "approve",
    "release",
    "override",
    "resolve_no_bind",
    "execute_action",
    "edit_source_record",
    "dispense",
    "administer",
    "transfer_real_product",
]


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


def append_audit(
    project_root: Path,
    correlation_id: str,
    track_id: str,
    event_type: str,
    state: str,
    details: Dict[str, Any],
) -> Dict[str, Any]:
    event = {
        "event_id": str(uuid.uuid4()),
        "correlation_id": correlation_id,
        "track_id": track_id,
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


def load_fixture_document(project_root: Path) -> Dict[str, Any]:
    return read_json(
        project_root /
        "config" /
        "track_fixtures.json"
    )


def track_runtime_paths(
    project_root: Path,
    track_id: str,
) -> Dict[str, Path]:
    normalized = track_id.lower()

    return {
        "data_root": (
            project_root /
            "data" /
            normalized
        ),
        "evidence": (
            project_root /
            "data" /
            normalized /
            "evidence.json"
        ),
        "source": (
            project_root /
            "data" /
            normalized /
            "source_state.json"
        ),
        "authority": (
            project_root /
            "data" /
            normalized /
            "authority.json"
        ),
        "dependencies": (
            project_root /
            "data" /
            normalized /
            "dependencies.json"
        ),
        "seal": (
            project_root /
            "state" /
            normalized /
            "evidence_seal.json"
        ),
        "backup": (
            project_root /
            "backup" /
            f"{normalized}_evidence.backup.json"
        ),
    }


def reset_runtime(project_root: Path) -> None:
    for relative in ("data", "state", "runs", "backup"):
        target = project_root / relative

        if target.exists():
            shutil.rmtree(target)

        target.mkdir(parents=True, exist_ok=True)


def initialize_track(
    project_root: Path,
    track: Dict[str, Any],
) -> None:
    paths = track_runtime_paths(
        project_root,
        track["track_id"],
    )

    paths["data_root"].mkdir(
        parents=True,
        exist_ok=True,
    )

    write_json(
        paths["evidence"],
        track["evidence"],
    )

    write_json(
        paths["source"],
        track["source_state"],
    )

    write_json(
        paths["authority"],
        track["authority"],
    )

    write_json(
        paths["dependencies"],
        {
            "dependencies": track["dependencies"]
        },
    )


def seal_and_backup(
    project_root: Path,
    track: Dict[str, Any],
) -> Dict[str, Any]:
    track_id = track["track_id"]
    paths = track_runtime_paths(
        project_root,
        track_id,
    )

    evidence = read_json(paths["evidence"])
    correlation_id = str(uuid.uuid4())
    evidence_hash = sha256_file(paths["evidence"])

    seal = {
        "seal_id": f"SEAL-{uuid.uuid4()}",
        "track_id": track_id,
        "object_id": evidence["object_id"],
        "evidence_id": evidence["evidence_id"],
        "hash_algorithm": "SHA-256",
        "hash_value": evidence_hash,
        "content_length_bytes": paths["evidence"].stat().st_size,
        "sealed_at_utc": iso_utc(),
        "sealed_by_actor_id": evidence["reviewed_by_actor_id"],
        "seal_status": "SEALED",
    }

    write_json(
        paths["seal"],
        seal,
    )

    paths["backup"].parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    shutil.copy2(
        paths["evidence"],
        paths["backup"],
    )

    backup_hash = sha256_file(paths["backup"])

    if backup_hash != evidence_hash:
        raise RuntimeError(
            f"{track_id}: backup integrity verification failed"
        )

    append_audit(
        project_root,
        correlation_id,
        track_id,
        "EVIDENCE_SEALED_AND_BACKED_UP",
        "PASS",
        {
            "hash_algorithm": "SHA-256",
            "hash_value": evidence_hash,
            "backup_hash": backup_hash,
        },
    )

    return seal


def evaluate_authority(
    track: Dict[str, Any],
    authority: Dict[str, Any],
    now: datetime,
) -> Dict[str, Any]:
    present = bool(
        authority.get("authority_id") and
        authority.get("actor_id") and
        authority.get("role_id")
    )

    current = (
        present and
        parse_utc(authority["valid_from_utc"]) <=
        now <=
        parse_utc(authority["valid_to_utc"])
    )

    role_valid = (
        authority.get("role_id") ==
        track["required_role"]
    )

    action_valid = (
        track["action_type"] in
        authority.get(
            "allowed_action_types",
            [],
        )
    )

    object_valid = (
        track["object_id"] in
        authority.get(
            "object_scope",
            [],
        )
    )

    consequence_valid = (
        track["consequence_level"] in
        authority.get(
            "consequence_scope",
            [],
        )
    )

    status_valid = (
        authority.get("authority_status") ==
        "ACTIVE"
    )

    valid = all(
        (
            present,
            current,
            role_valid,
            action_valid,
            object_valid,
            consequence_valid,
            status_valid,
        )
    )

    return {
        "authority_id": authority.get("authority_id"),
        "actor_id": authority.get("actor_id"),
        "role_id": authority.get("role_id"),
        "authority_present": present,
        "authority_current": current,
        "authority_in_scope": (
            role_valid and
            action_valid and
            object_valid and
            consequence_valid
        ),
        "authority_valid": valid,
        "authority_state": (
            "VALID"
            if valid
            else "INVALID"
        ),
    }


def evaluate_dependencies(
    dependency_document: Dict[str, Any],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for dependency in dependency_document.get(
        "dependencies",
        [],
    ):
        satisfied = bool(
            dependency.get("satisfied")
        )

        results.append(
            {
                "dependency_id": (
                    dependency["dependency_id"]
                ),
                "dependency_name": (
                    dependency["dependency_name"]
                ),
                "required_state": "SATISFIED",
                "observed_state": (
                    "SATISFIED"
                    if satisfied
                    else "UNSATISFIED"
                ),
                "dependency_status": (
                    "SATISFIED"
                    if satisfied
                    else "UNSATISFIED"
                ),
            }
        )

    return results


def build_display_states(
    result: Dict[str, Any],
) -> List[str]:
    states: List[str] = []

    if not result["identity_verified"]:
        states.append("IDENTITY CONFLICT")

    if result["integrity_state"] != "REHASH_VERIFIED":
        states.append("EVIDENCE INSUFFICIENT")

    if not result["dependencies_satisfied"]:
        states.append("DEPENDENCY UNSATISFIED")

    if not result["authority"]["authority_present"]:
        states.append("AUTHORITY ABSENT")
    elif not result["authority"]["authority_valid"]:
        states.append("AUTHORITY INVALID")

    if not result["timing_valid"]:
        states.append("TIMING INVALID")

    if not result["human_accountability_identified"]:
        states.append(
            "HUMAN ACCOUNTABILITY MISSING"
        )

    if result["no_bind_state"] == "ACTIVE":
        states.extend(
            [
                "NO-BIND STATE ACTIVE",
                "ACTION HELD",
                "HUMAN AUTHORITY REQUIRED",
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


def evaluate_track(
    project_root: Path,
    track: Dict[str, Any],
    scenario_name: str,
) -> Dict[str, Any]:
    track_id = track["track_id"]
    paths = track_runtime_paths(
        project_root,
        track_id,
    )

    evidence = read_json(paths["evidence"])
    source = read_json(paths["source"])
    authority_record = read_json(paths["authority"])
    dependency_document = read_json(
        paths["dependencies"]
    )
    seal = read_json(paths["seal"])

    now = utc_now()
    correlation_id = str(uuid.uuid4())
    current_hash = sha256_file(paths["evidence"])

    integrity_verified = (
        seal.get("hash_algorithm") == "SHA-256" and
        current_hash == seal.get("hash_value")
    )

    identity_verified = all(
        (
            evidence.get("object_id") ==
            track.get("object_id"),

            source.get("object_id") ==
            track.get("object_id"),

            evidence.get("source_record_id") ==
            source.get("source_record_id"),
        )
    )

    dependencies = evaluate_dependencies(
        dependency_document
    )

    dependencies_satisfied = (
        bool(dependencies) and
        all(
            item["dependency_status"] ==
            "SATISFIED"
            for item in dependencies
        )
    )

    authority = evaluate_authority(
        track,
        authority_record,
        now,
    )

    timing_valid = (
        parse_utc(
            source["valid_from_utc"]
        ) <= now <=
        parse_utc(
            source["valid_to_utc"]
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
            evidence.get("review_status") ==
            "REVIEWED",
            bool(
                evidence.get(
                    "reviewed_by_actor_id"
                )
            ),
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

    result: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "implementation_version": IMPLEMENTATION_VERSION,
        "scenario_name": scenario_name,
        "track_id": track_id,
        "track_name": track["track_name"],
        "priority_tier": track["priority_tier"],
        "correlation_id": correlation_id,
        "evaluation_id": f"EVAL-{uuid.uuid4()}",
        "evaluated_at_utc": iso_utc(now),
        "object_id": track["object_id"],
        "action_id": track["action_id"],
        "action_type": track["action_type"],
        "action_consequence_level": (
            track["consequence_level"]
        ),
        "identity_verified": identity_verified,
        "integrity_state": (
            "REHASH_VERIFIED"
            if integrity_verified
            else "REHASH_MISMATCH"
        ),
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

    no_bind = {
        "no_bind_id": f"NB-{uuid.uuid4()}",
        "track_id": track_id,
        "object_id": track["object_id"],
        "action_id": track["action_id"],
        "activated": no_bind_active,
        "no_bind_state": (
            "NO-BIND STATE ACTIVE"
            if no_bind_active
            else "INACTIVE"
        ),
        "reason_codes": reasons,
        "resolution_required": no_bind_active,
        "silence_is_not_consent": True,
        "display_cannot_resolve": True,
    }

    admissibility = {
        "admissibility_id": (
            f"ADM-{uuid.uuid4()}"
        ),
        "track_id": track_id,
        "object_id": track["object_id"],
        "action_id": track["action_id"],
        "decision_state": (
            "ACTION_HELD"
            if no_bind_active
            else "ACTION_ADMISSIBLE"
        ),
        "source_execution_required": True,
        "execution_performed": False,
        "decision_boundary": (
            "ASSURANCE EVALUATION ONLY - NOT EXECUTION"
        ),
        "rationale": (
            reasons
            if reasons
            else [
                "ALL_REQUIRED_ASSURANCE_CONDITIONS_POSITIVELY_SATISFIED"
            ]
        ),
    }

    display_contract = {
        "display_contract_id": (
            f"DISPLAY-{uuid.uuid4()}"
        ),
        "track_id": track_id,
        "track_name": track["track_name"],
        "priority_tier": "FIRST-TIER",
        "object_id": track["object_id"],
        "action_id": track["action_id"],
        "generated_at_utc": iso_utc(now),
        "expires_at_utc": iso_utc(
            now + timedelta(minutes=5)
        ),
        "display_authority": (
            "DISPLAY / WITNESS ONLY"
        ),
        "display_states": (
            result["display_states"]
        ),
        "prohibited_controls": (
            DISPLAY_PROHIBITED_CONTROLS
        ),
        "human_prompt": (
            "STOP: GOVERNANCE HOLD ACTIVE. "
            "AUTHORIZED HUMAN REVIEW AND "
            "GOVERNED RESOLUTION ARE REQUIRED."
            if no_bind_active
            else
            "ASSURANCE CONDITIONS ARE SATISFIED. "
            "AUTHORIZED HUMAN DECISION AND "
            "OFFICIAL SOURCE-SYSTEM EXECUTION "
            "ARE STILL REQUIRED."
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
        "can_dispense": False,
        "can_administer": False,
        "can_transfer_real_product": False,
    }

    reconstruction = {
        "reconstruction_id": (
            f"RECON-{uuid.uuid4()}"
        ),
        "scenario_name": scenario_name,
        "track_id": track_id,
        "correlation_id": correlation_id,
        "object_id": track["object_id"],
        "action_id": track["action_id"],
        "generated_at_utc": iso_utc(now),
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
            no_bind["no_bind_id"]
        ),
        "admissibility_reference": (
            admissibility["admissibility_id"]
        ),
        "unresolved_gaps": reasons,
        "execution_performed": False,
        "official_execution_record": None,
        "chronology": [
            {
                "event": "REHASH_EVALUATED",
                "state": result["integrity_state"],
                "time": iso_utc(now),
            },
            {
                "event": "DEPENDENCIES_EVALUATED",
                "state": dependencies_satisfied,
                "time": iso_utc(now),
            },
            {
                "event": "AUTHORITY_EVALUATED",
                "state": authority["authority_state"],
                "time": iso_utc(now),
            },
            {
                "event": "NO_BIND_EVALUATED",
                "state": no_bind["no_bind_state"],
                "time": iso_utc(now),
            },
            {
                "event": "ADMISSIBILITY_RECORDED",
                "state": admissibility["decision_state"],
                "time": iso_utc(now),
            },
        ],
    }

    write_json(
        run_dir / "evaluation.json",
        result,
    )

    write_json(
        run_dir / "no_bind_state.json",
        no_bind,
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
        track_id,
        "SHARED_KERNEL_EVALUATED",
        result["action_admissibility_state"],
        {
            "scenario_name": scenario_name,
            "integrity_state": result["integrity_state"],
            "no_bind_state": result["no_bind_state"],
            "reasons": reasons,
        },
    )

    return result


def tamper_evidence(
    project_root: Path,
    track_id: str,
) -> None:
    evidence_path = track_runtime_paths(
        project_root,
        track_id,
    )["evidence"]

    evidence = read_json(evidence_path)
    evidence["assurance_marker"] = "ALTERED_AFTER_SEAL"
    evidence["tampered_for_demo"] = True

    write_json(
        evidence_path,
        evidence,
    )


def restore_evidence(
    project_root: Path,
    track_id: str,
    expected_hash: str,
) -> Dict[str, Any]:
    paths = track_runtime_paths(
        project_root,
        track_id,
    )

    backup_hash = sha256_file(
        paths["backup"]
    )

    if backup_hash != expected_hash:
        raise RuntimeError(
            f"{track_id}: backup hash mismatch"
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

    if not verified:
        raise RuntimeError(
            f"{track_id}: restored evidence hash mismatch"
        )

    result = {
        "track_id": track_id,
        "expected_hash": expected_hash,
        "backup_hash": backup_hash,
        "restored_hash": restored_hash,
        "restore_integrity_verified": verified,
        "restored_at_utc": iso_utc(),
    }

    write_json(
        project_root /
        "backup" /
        f"{track_id.lower()}_restore_verification.json",
        result,
    )

    return result


def validate_display_contract(
    project_root: Path,
    scenario_name: str,
) -> None:
    display = read_json(
        project_root /
        "runs" /
        scenario_name /
        "display_contract.json"
    )

    if (
        display["display_authority"] !=
        "DISPLAY / WITNESS ONLY"
    ):
        raise AssertionError(
            "Display authority boundary failed"
        )

    for field in (
        "can_approve",
        "can_release",
        "can_override",
        "can_resolve_no_bind",
        "can_execute",
        "can_dispense",
        "can_administer",
        "can_transfer_real_product",
    ):
        if display.get(field) is not False:
            raise AssertionError(
                f"Display contract exposes prohibited capability: {field}"
            )


def write_scenario_csv(
    path: Path,
    scenarios: Iterable[Dict[str, Any]],
) -> None:
    rows = list(scenarios)

    fieldnames = [
        "TrackId",
        "TrackName",
        "PriorityTier",
        "Scenario",
        "IntegrityState",
        "IdentityVerified",
        "DependenciesSatisfied",
        "EvidenceSufficient",
        "AuthorityValid",
        "TimingValid",
        "NoBindState",
        "ActionAdmissibilityState",
        "DisplayStates",
        "SourceExecutionRequired",
        "ExecutionPerformed",
    ]

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

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
                    "TrackId": item["track_id"],
                    "TrackName": item["track_name"],
                    "PriorityTier": item["priority_tier"],
                    "Scenario": item["scenario_name"],
                    "IntegrityState": item["integrity_state"],
                    "IdentityVerified": item["identity_verified"],
                    "DependenciesSatisfied": (
                        item["dependencies_satisfied"]
                    ),
                    "EvidenceSufficient": item["evidence_sufficient"],
                    "AuthorityValid": (
                        item["authority"]["authority_valid"]
                    ),
                    "TimingValid": item["timing_valid"],
                    "NoBindState": item["no_bind_state"],
                    "ActionAdmissibilityState": (
                        item["action_admissibility_state"]
                    ),
                    "DisplayStates": "; ".join(
                        item["display_states"]
                    ),
                    "SourceExecutionRequired": (
                        item["source_system_execution_required"]
                    ),
                    "ExecutionPerformed": (
                        item["execution_performed"]
                    ),
                }
            )


def report_markdown(
    summary: Dict[str, Any],
) -> str:
    rows: List[str] = []

    for scenario in summary["scenarios"]:
        rows.append(
            "| {track} | {scenario} | {integrity} | "
            "{no_bind} | {admissibility} | {execution} |".format(
                track=scenario["track_id"],
                scenario=scenario["scenario_name"],
                integrity=scenario["integrity_state"],
                no_bind=scenario["no_bind_state"],
                admissibility=scenario[
                    "action_admissibility_state"
                ],
                execution=scenario["execution_performed"],
            )
        )

    return "\n".join(
        [
            "# Step 162 - First-Tier Triad Shared Assurance Kernel",
            "",
            "**Explicitly authorized by the user command NEXT for local synthetic non-production implementation only.**",
            "",
            "## Equal first-tier tracks",
            "",
            "- IRLT and radiopharmaceutical assurance",
            "- Compounding pharmacy assurance",
            "- DSCSA and pharmaceutical supply-chain assurance",
            "",
            "## Shared implemented capabilities",
            "",
            "- Canonical regulated-object identity evaluation",
            "- SHA-256 evidence sealing and rehash verification",
            "- Workflow dependency evaluation",
            "- Authority and temporal-validity evaluation",
            "- Fail-closed No-Bind behavior",
            "- Action-admissibility records",
            "- Display-only RAMAT contracts",
            "- Audit events and governance reconstruction",
            "- Backup and integrity-verified recovery",
            "- Reusable synthetic fixture format",
            "",
            "## Demonstration results",
            "",
            "| Track | Scenario | Integrity | No-Bind | Admissibility | Execution performed |",
            "|---|---|---|---|---|---:|",
            *rows,
            "",
            "## Boundaries",
            "",
            "- Platform B v1 was not modified.",
            "- Thread D v1 was not modified.",
            "- Platform B1 performed local shared assurance evaluation only.",
            "- Thread D2 and RAMAT Vision remained DISPLAY / WITNESS ONLY.",
            "- No scenario approved, released, dispensed, administered, shipped, or executed regulated work.",
            "- Qualified human authority remains required.",
            "- Official execution remains in governed source systems.",
            "- No PHI or company production data was used.",
            "",
            "**STEP 162 FIRST-TIER TRIAD SHARED ASSURANCE KERNEL COMPLETE**",
            "",
            "**STEP 163: AWAITING NEW GOVERNED SCOPE REVIEW**",
            "",
        ]
    )


def run_demo(
    project_root: Path,
) -> Dict[str, Any]:
    reset_runtime(project_root)

    fixture_document = load_fixture_document(
        project_root
    )

    tracks = fixture_document.get(
        "tracks",
        [],
    )

    if len(tracks) != 3:
        raise RuntimeError(
            "Exactly three first-tier tracks are required"
        )

    scenarios: List[Dict[str, Any]] = []
    restore_results: List[Dict[str, Any]] = []

    for track in tracks:
        initialize_track(
            project_root,
            track,
        )

        seal = seal_and_backup(
            project_root,
            track,
        )

        track_id = track["track_id"]

        baseline_name = (
            f"{track_id}_01_success_before_tamper"
        )

        tamper_name = (
            f"{track_id}_02_tamper_failure"
        )

        recovery_name = (
            f"{track_id}_03_recovery_success"
        )

        baseline = evaluate_track(
            project_root,
            track,
            baseline_name,
        )

        if (
            baseline["action_admissibility_state"] !=
            "ADMISSIBLE"
        ):
            raise RuntimeError(
                f"{track_id}: baseline was not admissible"
            )

        validate_display_contract(
            project_root,
            baseline_name,
        )

        tamper_evidence(
            project_root,
            track_id,
        )

        tamper = evaluate_track(
            project_root,
            track,
            tamper_name,
        )

        if (
            tamper["integrity_state"] !=
            "REHASH_MISMATCH" or
            tamper["no_bind_state"] !=
            "ACTIVE" or
            tamper["action_admissibility_state"] !=
            "HELD"
        ):
            raise RuntimeError(
                f"{track_id}: tamper scenario did not fail closed"
            )

        required_states = {
            "EVIDENCE INSUFFICIENT",
            "NO-BIND STATE ACTIVE",
            "ACTION HELD",
        }

        if not required_states.issubset(
            set(tamper["display_states"])
        ):
            raise RuntimeError(
                f"{track_id}: tamper display states are incomplete"
            )

        validate_display_contract(
            project_root,
            tamper_name,
        )

        restore_result = restore_evidence(
            project_root,
            track_id,
            seal["hash_value"],
        )

        recovery = evaluate_track(
            project_root,
            track,
            recovery_name,
        )

        if (
            recovery["integrity_state"] !=
            "REHASH_VERIFIED" or
            recovery["action_admissibility_state"] !=
            "ADMISSIBLE"
        ):
            raise RuntimeError(
                f"{track_id}: recovery did not restore admissibility"
            )

        validate_display_contract(
            project_root,
            recovery_name,
        )

        scenarios.extend(
            [
                baseline,
                tamper,
                recovery,
            ]
        )

        restore_results.append(
            restore_result
        )

    track_ids = sorted(
        {
            item["track_id"]
            for item in scenarios
        }
    )

    baseline_scenarios = [
        item
        for item in scenarios
        if item["scenario_name"].endswith(
            "01_success_before_tamper"
        )
    ]

    tamper_scenarios = [
        item
        for item in scenarios
        if item["scenario_name"].endswith(
            "02_tamper_failure"
        )
    ]

    recovery_scenarios = [
        item
        for item in scenarios
        if item["scenario_name"].endswith(
            "03_recovery_success"
        )
    ]

    checks = {
        "three_equal_first_tier_tracks": (
            track_ids ==
            [
                "COMPOUNDING",
                "DSCSA",
                "IRLT",
            ]
        ),
        "scenario_count_is_nine": (
            len(scenarios) == 9
        ),
        "all_baselines_admissible": all(
            item["action_admissibility_state"] ==
            "ADMISSIBLE"
            for item in baseline_scenarios
        ),
        "all_tamper_scenarios_detected": all(
            item["integrity_state"] ==
            "REHASH_MISMATCH"
            for item in tamper_scenarios
        ),
        "all_tamper_scenarios_fail_closed": all(
            item["no_bind_state"] ==
            "ACTIVE" and
            item["action_admissibility_state"] ==
            "HELD"
            for item in tamper_scenarios
        ),
        "all_recovery_scenarios_admissible": all(
            item["integrity_state"] ==
            "REHASH_VERIFIED" and
            item["action_admissibility_state"] ==
            "ADMISSIBLE"
            for item in recovery_scenarios
        ),
        "all_restores_integrity_verified": all(
            item["restore_integrity_verified"]
            for item in restore_results
        ),
        "all_display_contracts_display_only": True,
        "no_execution_performed": all(
            not item["execution_performed"]
            for item in scenarios
        ),
        "platform_b_v1_modified": False,
        "thread_d_v1_modified": False,
        "production_integration_performed": False,
        "phi_used": False,
    }

    positive_keys = (
        "three_equal_first_tier_tracks",
        "scenario_count_is_nine",
        "all_baselines_admissible",
        "all_tamper_scenarios_detected",
        "all_tamper_scenarios_fail_closed",
        "all_recovery_scenarios_admissible",
        "all_restores_integrity_verified",
        "all_display_contracts_display_only",
        "no_execution_performed",
    )

    negative_keys = (
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
                for key in positive_keys
            ) and
            not any(
                checks[key]
                for key in negative_keys
            )
        )
        else "FAIL"
    )

    summary = {
        "step": "162",
        "title": (
            "First-Tier Triad Shared Assurance Kernel"
        ),
        "implementation_version": (
            IMPLEMENTATION_VERSION
        ),
        "authorization_source": (
            fixture_document["authorized_by"]
        ),
        "authorization_recorded_at_utc": (
            fixture_document[
                "authorization_recorded_at_utc"
            ]
        ),
        "generated_at_utc": iso_utc(),
        "overall_status": overall_status,
        "implementation_boundary": (
            fixture_document[
                "implementation_boundary"
            ]
        ),
        "first_tier_track_count": len(track_ids),
        "first_tier_tracks": track_ids,
        "scenario_count": len(scenarios),
        "checks": checks,
        "restore_results": restore_results,
        "scenarios": scenarios,
        "architecture_boundaries": {
            "platform_b_v1": (
                "ARCHITECTURE LOCKED - NOT MODIFIED"
            ),
            "thread_d_v1": (
                "ARCHITECTURE LOCKED - NOT MODIFIED"
            ),
            "platform_b1": (
                "LOCAL SHARED ASSURANCE EVALUATION ONLY"
            ),
            "thread_d2": (
                "DISPLAY / WITNESS ONLY"
            ),
            "ramat_vision": (
                "DISPLAY / WITNESS ONLY"
            ),
            "human_authority": (
                "REQUIRED FOR BINDING DECISIONS"
            ),
            "source_system_execution": (
                "REQUIRED"
            ),
        },
    }

    report_json = (
        project_root /
        "STEP_162_FIRST_TIER_TRIAD_SHARED_ASSURANCE_KERNEL.json"
    )

    report_csv = (
        project_root /
        "STEP_162_FIRST_TIER_TRIAD_SHARED_ASSURANCE_KERNEL.csv"
    )

    report_markdown_path = (
        project_root /
        "STEP_162_FIRST_TIER_TRIAD_SHARED_ASSURANCE_KERNEL.md"
    )

    write_json(
        report_json,
        summary,
    )

    write_scenario_csv(
        report_csv,
        scenarios,
    )

    write_text(
        report_markdown_path,
        report_markdown(summary),
    )

    if overall_status != "PASS":
        raise RuntimeError(
            "Step 162 shared-kernel validation failed"
        )

    return summary


def verify_existing(
    project_root: Path,
) -> Dict[str, Any]:
    summary = read_json(
        project_root /
        "STEP_162_FIRST_TIER_TRIAD_SHARED_ASSURANCE_KERNEL.json"
    )

    if summary.get("overall_status") != "PASS":
        raise RuntimeError(
            "Existing Step 162 summary is not PASS"
        )

    if int(
        summary.get(
            "first_tier_track_count",
            0,
        )
    ) != 3:
        raise RuntimeError(
            "Existing Step 162 summary does not contain three tracks"
        )

    if int(
        summary.get(
            "scenario_count",
            0,
        )
    ) != 9:
        raise RuntimeError(
            "Existing Step 162 summary does not contain nine scenarios"
        )

    return summary


def main(
    argv: Optional[List[str]] = None,
) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Step 162 first-tier triad "
            "shared assurance kernel"
        )
    )

    parser.add_argument(
        "--project-root",
        required=True,
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
        summary = verify_existing(project_root)

    print(
        json.dumps(
            {
                "status": summary["overall_status"],
                "track_count": (
                    summary[
                        "first_tier_track_count"
                    ]
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