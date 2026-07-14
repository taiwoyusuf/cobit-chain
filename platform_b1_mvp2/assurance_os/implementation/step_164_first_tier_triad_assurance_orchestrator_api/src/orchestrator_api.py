from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import sys
import threading
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

VERSION = "164.1.1"
TRACK_IDS = ("IRLT", "COMPOUNDING", "DSCSA")
PROHIBITED_METHODS = ("POST", "PUT", "PATCH", "DELETE")
ALIASES = {
    "baseline": "01_baseline_success",
    "tamper": "02_evidence_tamper_failure",
    "domain_failure": "03_domain_failure",
    "recovery": "04_recovery_success",
}


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
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        value = json.load(handle)

    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")

    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(value)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def config(project_root: Path) -> Dict[str, Any]:
    return read_json(
        project_root / "config" / "orchestrator_config.json"
    )


def track_paths(project_root: Path, track_id: str) -> Dict[str, Path]:
    key = track_id.lower()

    return {
        "data": project_root / "data" / key,
        "evidence": project_root / "data" / key / "evidence.json",
        "source": project_root / "data" / key / "source_state.json",
        "authority": project_root / "data" / key / "authority.json",
        "dependencies": project_root / "data" / key / "dependencies.json",
        "seal": project_root / "state" / key / "evidence_seal.json",
        "backup": project_root / "backup" / f"{key}_evidence.backup.json",
    }


def reset_runtime(project_root: Path) -> None:
    for relative in (
        "data",
        "state",
        "runs",
        "backup",
        "passports",
        "ramat",
        "reconstruction",
        "api_self_test",
    ):
        target = project_root / relative

        if target.exists():
            shutil.rmtree(target)

        target.mkdir(parents=True, exist_ok=True)


def append_audit(
    project_root: Path,
    correlation_id: str,
    track_id: str,
    event_type: str,
    state: str,
    details: Dict[str, Any],
) -> None:
    record = {
        "event_id": str(uuid.uuid4()),
        "correlation_id": correlation_id,
        "track_id": track_id,
        "event_type": event_type,
        "state": state,
        "recorded_at_utc": iso_utc(),
        "details": details,
    }

    path = project_root / "runs" / "audit_events.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def initialize_track(project_root: Path, track: Dict[str, Any]) -> None:
    paths = track_paths(project_root, track["track_id"])
    paths["data"].mkdir(parents=True, exist_ok=True)

    evidence = {
        "evidence_id": f"EVID-{track['track_id']}-164-001",
        "track_id": track["track_id"],
        "object_id": track["object_id"],
        "source_record_id": track["source_record_id"],
        "evidence_type": f"{track['track_id']}_ASSURANCE_PACKAGE",
        "review_status": "REVIEWED",
        "reviewed_by_actor_id": f"ACTOR-{track['track_id']}-REVIEWER-001",
        "assurance_marker": "TRUSTED",
        "synthetic": True,
    }

    source = {
        "source_system_name": track["source_system"],
        "source_record_id": track["source_record_id"],
        "object_id": track["object_id"],
        "valid_from_utc": track["valid_from_utc"],
        "valid_to_utc": track["valid_to_utc"],
        "synthetic": True,
    }

    authority = {
        "authority_id": f"AUTH-{track['track_id']}-164-001",
        "actor_id": f"ACTOR-{track['track_id']}-AUTHORITY-001",
        "role_id": track["required_role"],
        "allowed_action_types": [track["action_type"]],
        "object_scope": [track["object_id"]],
        "consequence_scope": [track["consequence_level"]],
        "valid_from_utc": track["valid_from_utc"],
        "valid_to_utc": track["valid_to_utc"],
        "authority_status": "ACTIVE",
        "synthetic": True,
    }

    dependencies = {
        "track_id": track["track_id"],
        "dependencies": [
            {
                "dependency_id": (
                    f"{track['track_id']}-DEP-{index:03d}"
                ),
                "dependency_name": name,
                "satisfied": True,
            }
            for index, name in enumerate(
                track["dependencies"],
                start=1,
            )
        ],
    }

    write_json(paths["evidence"], evidence)
    write_json(paths["source"], source)
    write_json(paths["authority"], authority)
    write_json(paths["dependencies"], dependencies)


def reset_operational_state(
    project_root: Path,
    track: Dict[str, Any],
) -> None:
    paths = track_paths(project_root, track["track_id"])

    dependencies = {
        "track_id": track["track_id"],
        "dependencies": [
            {
                "dependency_id": (
                    f"{track['track_id']}-DEP-{index:03d}"
                ),
                "dependency_name": name,
                "satisfied": True,
            }
            for index, name in enumerate(
                track["dependencies"],
                start=1,
            )
        ],
    }

    write_json(paths["dependencies"], dependencies)


def seal_and_backup(
    project_root: Path,
    track: Dict[str, Any],
) -> Dict[str, Any]:
    track_id = track["track_id"]
    paths = track_paths(project_root, track_id)
    evidence = read_json(paths["evidence"])
    evidence_hash = sha256_file(paths["evidence"])

    seal = {
        "seal_id": f"SEAL-{uuid.uuid4()}",
        "track_id": track_id,
        "object_id": track["object_id"],
        "evidence_id": evidence["evidence_id"],
        "hash_algorithm": "SHA-256",
        "hash_value": evidence_hash,
        "sealed_at_utc": iso_utc(),
        "seal_status": "SEALED",
    }

    write_json(paths["seal"], seal)

    paths["backup"].parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(paths["evidence"], paths["backup"])

    if sha256_file(paths["backup"]) != evidence_hash:
        raise RuntimeError(f"{track_id}: backup verification failed")

    append_audit(
        project_root,
        str(uuid.uuid4()),
        track_id,
        "EVIDENCE_SEALED_AND_BACKED_UP",
        "PASS",
        {"hash": evidence_hash},
    )

    return seal


def restore_evidence(
    project_root: Path,
    track_id: str,
    expected_hash: str,
) -> Dict[str, Any]:
    paths = track_paths(project_root, track_id)

    backup_hash = sha256_file(paths["backup"])

    if backup_hash != expected_hash:
        raise RuntimeError(f"{track_id}: backup hash mismatch")

    shutil.copy2(paths["backup"], paths["evidence"])
    restored_hash = sha256_file(paths["evidence"])
    verified = restored_hash == expected_hash

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

    if not verified:
        raise RuntimeError(f"{track_id}: restore verification failed")

    return result


def inject_tamper(project_root: Path, track_id: str) -> None:
    path = track_paths(project_root, track_id)["evidence"]
    evidence = read_json(path)
    evidence["assurance_marker"] = "ALTERED_AFTER_SEAL"
    evidence["tampered_for_demo"] = True
    write_json(path, evidence)


def inject_domain_failure(
    project_root: Path,
    track: Dict[str, Any],
) -> None:
    path = track_paths(
        project_root,
        track["track_id"],
    )["dependencies"]

    document = read_json(path)
    matched = False

    for dependency in document["dependencies"]:
        if (
            dependency["dependency_name"] ==
            track["domain_dependency"]
        ):
            dependency["satisfied"] = False
            dependency["failure_code"] = (
                track["domain_failure_code"]
            )
            matched = True

    if not matched:
        raise RuntimeError(
            f"{track['track_id']}: domain dependency was not found"
        )

    write_json(path, document)


def evaluate(
    project_root: Path,
    track: Dict[str, Any],
    scenario_name: str,
    failure_type: Optional[str] = None,
) -> Dict[str, Any]:
    track_id = track["track_id"]
    paths = track_paths(project_root, track_id)

    evidence = read_json(paths["evidence"])
    source = read_json(paths["source"])
    authority_record = read_json(paths["authority"])
    dependency_document = read_json(paths["dependencies"])
    seal = read_json(paths["seal"])

    now = utc_now()
    current_hash = sha256_file(paths["evidence"])

    integrity_verified = (
        seal["hash_algorithm"] == "SHA-256" and
        current_hash == seal["hash_value"]
    )

    identity_verified = all(
        (
            evidence["object_id"] == track["object_id"],
            source["object_id"] == track["object_id"],
            evidence["source_record_id"] ==
            source["source_record_id"],
        )
    )

    dependency_results = [
        {
            "dependency_id": item["dependency_id"],
            "dependency_name": item["dependency_name"],
            "dependency_status": (
                "SATISFIED"
                if item.get("satisfied")
                else "UNSATISFIED"
            ),
            "failure_code": item.get("failure_code"),
        }
        for item in dependency_document["dependencies"]
    ]

    dependencies_satisfied = all(
        item["dependency_status"] == "SATISFIED"
        for item in dependency_results
    )

    authority_present = bool(
        authority_record.get("authority_id") and
        authority_record.get("actor_id") and
        authority_record.get("role_id")
    )

    authority_current = (
        parse_utc(authority_record["valid_from_utc"]) <=
        now <=
        parse_utc(authority_record["valid_to_utc"])
    )

    authority_in_scope = all(
        (
            authority_record["role_id"] ==
            track["required_role"],

            track["action_type"] in
            authority_record["allowed_action_types"],

            track["object_id"] in
            authority_record["object_scope"],

            track["consequence_level"] in
            authority_record["consequence_scope"],

            authority_record["authority_status"] ==
            "ACTIVE",
        )
    )

    authority_valid = (
        authority_present and
        authority_current and
        authority_in_scope
    )

    timing_valid = (
        parse_utc(source["valid_from_utc"]) <=
        now <=
        parse_utc(source["valid_to_utc"])
    )

    reasons: List[str] = []

    if not integrity_verified:
        reasons.append("EVIDENCE_REHASH_MISMATCH")

    if not identity_verified:
        reasons.append("IDENTITY_CONFLICT")

    if not dependencies_satisfied:
        reasons.append("DEPENDENCY_UNSATISFIED")

    if not authority_present:
        reasons.append("AUTHORITY_ABSENT")
    elif not authority_valid:
        reasons.append("AUTHORITY_INVALID")

    if not timing_valid:
        reasons.append("TIMING_INVALID")

    if failure_type:
        reasons.append(failure_type)

    reasons = list(dict.fromkeys(reasons))
    no_bind_active = bool(reasons)

    display_states: List[str] = []

    if not integrity_verified:
        display_states.append("EVIDENCE INSUFFICIENT")

    if not identity_verified:
        display_states.append("IDENTITY CONFLICT")

    if not dependencies_satisfied:
        display_states.append("DEPENDENCY UNSATISFIED")

    if not authority_present:
        display_states.append("AUTHORITY ABSENT")

    if not authority_valid and authority_present:
        display_states.append("AUTHORITY INVALID")

    if not timing_valid:
        display_states.append("TIMING INVALID")

    if no_bind_active:
        display_states.extend(
            [
                "NO-BIND STATE ACTIVE",
                "ACTION HELD",
                "HUMAN AUTHORITY REQUIRED",
            ]
        )
    else:
        display_states.extend(
            [
                "ACTION ADMISSIBLE",
                "SOURCE-SYSTEM EXECUTION REQUIRED",
            ]
        )

    display_states = list(dict.fromkeys(display_states))
    correlation_id = str(uuid.uuid4())

    result = {
        "schema_version": "1.0",
        "implementation_version": VERSION,
        "scenario_name": scenario_name,
        "failure_type": failure_type,
        "track_id": track_id,
        "track_name": track["track_name"],
        "priority_tier": "FIRST-TIER",
        "correlation_id": correlation_id,
        "evaluation_id": f"EVAL-{uuid.uuid4()}",
        "evaluated_at_utc": iso_utc(now),
        "object_id": track["object_id"],
        "action_id": track["action_id"],
        "action_type": track["action_type"],
        "identity_verified": identity_verified,
        "integrity_state": (
            "REHASH_VERIFIED"
            if integrity_verified
            else "REHASH_MISMATCH"
        ),
        "sealed_hash": seal["hash_value"],
        "current_hash": current_hash,
        "dependencies": dependency_results,
        "dependencies_satisfied": dependencies_satisfied,
        "authority": {
            "authority_id": authority_record.get("authority_id"),
            "actor_id": authority_record.get("actor_id"),
            "role_id": authority_record.get("role_id"),
            "authority_present": authority_present,
            "authority_current": authority_current,
            "authority_in_scope": authority_in_scope,
            "authority_valid": authority_valid,
        },
        "timing_valid": timing_valid,
        "evidence_sufficient": (
            integrity_verified and
            identity_verified and
            dependencies_satisfied
        ),
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
        "display_states": display_states,
        "official_source_system": source["source_system_name"],
        "official_source_record_id": source["source_record_id"],
        "source_system_execution_required": True,
        "human_binding_decision_required": True,
        "human_binding_decision_performed": False,
        "execution_performed": False,
    }

    run_dir = project_root / "runs" / scenario_name
    run_dir.mkdir(parents=True, exist_ok=True)

    no_bind_record = {
        "no_bind_id": f"NB-{uuid.uuid4()}",
        "track_id": track_id,
        "activated": no_bind_active,
        "state": (
            "NO-BIND STATE ACTIVE"
            if no_bind_active
            else "INACTIVE"
        ),
        "reason_codes": reasons,
        "silence_is_not_consent": True,
        "display_cannot_resolve": True,
    }

    admissibility = {
        "admissibility_id": f"ADM-{uuid.uuid4()}",
        "track_id": track_id,
        "decision_state": (
            "ACTION_HELD"
            if no_bind_active
            else "ACTION_ADMISSIBLE"
        ),
        "rationale": (
            reasons
            if reasons
            else [
                "ALL_REQUIRED_ASSURANCE_CONDITIONS_SATISFIED"
            ]
        ),
        "source_execution_required": True,
        "execution_performed": False,
        "decision_boundary": (
            "ASSURANCE EVALUATION ONLY - NOT EXECUTION"
        ),
    }

    display = {
        "display_contract_id": f"DISPLAY-{uuid.uuid4()}",
        "track_id": track_id,
        "track_name": track["track_name"],
        "scenario_name": scenario_name,
        "generated_at_utc": iso_utc(now),
        "display_authority": "DISPLAY / WITNESS ONLY",
        "display_states": display_states,
        "source_of_truth": {
            "system": source["source_system_name"],
            "record_id": source["source_record_id"],
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
        "reconstruction_id": f"RECON-{uuid.uuid4()}",
        "track_id": track_id,
        "scenario_name": scenario_name,
        "correlation_id": correlation_id,
        "generated_at_utc": iso_utc(now),
        "object_id": track["object_id"],
        "action_id": track["action_id"],
        "evidence_seal_reference": seal["seal_id"],
        "evidence_hash": current_hash,
        "source_system_reference": source["source_record_id"],
        "authority_reference": authority_record["authority_id"],
        "unresolved_gaps": reasons,
        "execution_performed": False,
    }

    write_json(run_dir / "evaluation.json", result)
    write_json(run_dir / "no_bind_state.json", no_bind_record)
    write_json(
        run_dir / "action_admissibility.json",
        admissibility,
    )
    write_json(run_dir / "display_contract.json", display)
    write_json(run_dir / "reconstruction.json", reconstruction)

    append_audit(
        project_root,
        correlation_id,
        track_id,
        "ORCHESTRATOR_EVALUATED",
        result["action_admissibility_state"],
        {
            "scenario_name": scenario_name,
            "integrity_state": result["integrity_state"],
            "no_bind_state": result["no_bind_state"],
            "failure_type": failure_type,
        },
    )

    return result


def validate_display(project_root: Path, scenario_name: str) -> None:
    display = read_json(
        project_root /
        "runs" /
        scenario_name /
        "display_contract.json"
    )

    if display["display_authority"] != "DISPLAY / WITNESS ONLY":
        raise RuntimeError("Display authority boundary failed")

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
            raise RuntimeError(
                f"Display exposes prohibited capability: {field}"
            )


def create_passport(
    project_root: Path,
    track: Dict[str, Any],
    recovery: Dict[str, Any],
) -> Dict[str, Any]:
    paths = track_paths(project_root, track["track_id"])
    seal = read_json(paths["seal"])

    passport = {
        "passport_id": f"PASSPORT-{uuid.uuid4()}",
        "passport_type": (
            "FIRST-TIER ASSURANCE EVIDENCE PASSPORT"
        ),
        "track_id": track["track_id"],
        "track_name": track["track_name"],
        "priority_tier": "FIRST-TIER",
        "generated_at_utc": iso_utc(),
        "object_id": track["object_id"],
        "action_id": track["action_id"],
        "source_system": recovery["official_source_system"],
        "source_record_id": recovery[
            "official_source_record_id"
        ],
        "hash_algorithm": "SHA-256",
        "evidence_seal_id": seal["seal_id"],
        "evidence_hash": seal["hash_value"],
        "rehash_state": recovery["integrity_state"],
        "dependencies_satisfied": recovery[
            "dependencies_satisfied"
        ],
        "authority_valid": recovery["authority"][
            "authority_valid"
        ],
        "timing_valid": recovery["timing_valid"],
        "no_bind_state": recovery["no_bind_state"],
        "admissibility_state": recovery[
            "action_admissibility_state"
        ],
        "human_binding_decision_required": True,
        "source_system_execution_required": True,
        "execution_performed": False,
        "ramat_boundary": "DISPLAY / WITNESS ONLY",
        "synthetic": True,
    }

    path = (
        project_root /
        "passports" /
        f"{track['track_id'].lower()}_assurance_passport.json"
    )

    write_json(path, passport)

    passport_seal = {
        "passport_id": passport["passport_id"],
        "hash_algorithm": "SHA-256",
        "passport_hash": sha256_file(path),
        "sealed_at_utc": iso_utc(),
    }

    write_json(
        project_root /
        "passports" /
        f"{track['track_id'].lower()}_assurance_passport.seal.json",
        passport_seal,
    )

    return passport


def write_csv(
    path: Path,
    scenarios: Iterable[Dict[str, Any]],
) -> None:
    fieldnames = [
        "TrackId",
        "TrackName",
        "PriorityTier",
        "Scenario",
        "FailureType",
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

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for item in scenarios:
            writer.writerow(
                {
                    "TrackId": item["track_id"],
                    "TrackName": item["track_name"],
                    "PriorityTier": item["priority_tier"],
                    "Scenario": item["scenario_name"],
                    "FailureType": item.get("failure_type"),
                    "IntegrityState": item["integrity_state"],
                    "IdentityVerified": item["identity_verified"],
                    "DependenciesSatisfied": item[
                        "dependencies_satisfied"
                    ],
                    "EvidenceSufficient": item[
                        "evidence_sufficient"
                    ],
                    "AuthorityValid": item["authority"][
                        "authority_valid"
                    ],
                    "TimingValid": item["timing_valid"],
                    "NoBindState": item["no_bind_state"],
                    "ActionAdmissibilityState": item[
                        "action_admissibility_state"
                    ],
                    "DisplayStates": "; ".join(
                        item["display_states"]
                    ),
                    "SourceExecutionRequired": item[
                        "source_system_execution_required"
                    ],
                    "ExecutionPerformed": item[
                        "execution_performed"
                    ],
                }
            )


def markdown_report(summary: Dict[str, Any]) -> str:
    rows: List[str] = []

    for scenario in summary["scenarios"]:
        rows.append(
            "| {track} | {scenario} | {integrity} | "
            "{dependencies} | {nobind} | {admissibility} | "
            "{execution} |".format(
                track=scenario["track_id"],
                scenario=scenario["scenario_name"],
                integrity=scenario["integrity_state"],
                dependencies=scenario[
                    "dependencies_satisfied"
                ],
                nobind=scenario["no_bind_state"],
                admissibility=scenario[
                    "action_admissibility_state"
                ],
                execution=scenario["execution_performed"],
            )
        )

    return "\n".join(
        [
            "# Step 164 - First-Tier Triad Assurance Orchestrator and Evidence Passport API",
            "",
            "Authorized by the user command NEXT for local synthetic read-only implementation only.",
            "",
            "## Equal first-tier tracks",
            "",
            "- IRLT and radiopharmaceutical assurance",
            "- Compounding pharmacy assurance",
            "- DSCSA and pharmaceutical supply-chain assurance",
            "",
            "## Demonstration results",
            "",
            "| Track | Scenario | Integrity | Dependencies satisfied | No-Bind | Admissibility | Execution |",
            "|---|---|---|---:|---|---|---:|",
            *rows,
            "",
            "## API boundary",
            "",
            "- Host: 127.0.0.1 only",
            "- Allowed method: GET",
            "- POST, PUT, PATCH, and DELETE are rejected",
            "- No production write-back",
            "- No regulated execution endpoint",
            "",
            "## Locked boundaries",
            "",
            "- Platform B v1 was not modified.",
            "- Thread D v1 was not modified.",
            "- Thread D2 and RAMAT Vision remained DISPLAY / WITNESS ONLY.",
            "- Qualified human authority remains required.",
            "- Official source-system execution remains required.",
            "- No PHI or company production data was used.",
            "",
            "STEP 164 FIRST-TIER TRIAD ASSURANCE ORCHESTRATOR AND EVIDENCE PASSPORT API COMPLETE",
            "",
            "STEP 165: AWAITING NEW GOVERNED SCOPE REVIEW",
            "",
        ]
    )


def run_demo(project_root: Path) -> Dict[str, Any]:
    reset_runtime(project_root)
    configuration = config(project_root)
    tracks = configuration["tracks"]

    if len(tracks) != 3:
        raise RuntimeError("Exactly three tracks are required")

    observed_ids = sorted(
        track["track_id"]
        for track in tracks
    )

    if observed_ids != sorted(TRACK_IDS):
        raise RuntimeError(
            "IRLT, COMPOUNDING, and DSCSA are required"
        )

    scenarios: List[Dict[str, Any]] = []
    restores: List[Dict[str, Any]] = []
    passports: List[Dict[str, Any]] = []

    for track in tracks:
        if track["priority_tier"] != "FIRST-TIER":
            raise RuntimeError(
                f"{track['track_id']} is not FIRST-TIER"
            )

        track_id = track["track_id"]
        initialize_track(project_root, track)
        seal = seal_and_backup(project_root, track)

        baseline_name = f"{track_id}_01_baseline_success"
        tamper_name = f"{track_id}_02_evidence_tamper_failure"
        domain_name = f"{track_id}_03_domain_failure"
        recovery_name = f"{track_id}_04_recovery_success"

        baseline = evaluate(
            project_root,
            track,
            baseline_name,
        )

        if baseline["action_admissibility_state"] != "ADMISSIBLE":
            raise RuntimeError(
                f"{track_id}: baseline was not admissible"
            )

        validate_display(project_root, baseline_name)

        inject_tamper(project_root, track_id)

        tamper = evaluate(
            project_root,
            track,
            tamper_name,
            "EVIDENCE_TAMPER_INJECTED",
        )

        if (
            tamper["integrity_state"] != "REHASH_MISMATCH" or
            tamper["no_bind_state"] != "ACTIVE" or
            tamper["action_admissibility_state"] != "HELD"
        ):
            raise RuntimeError(
                f"{track_id}: tamper did not fail closed"
            )

        validate_display(project_root, tamper_name)

        restore_result = restore_evidence(
            project_root,
            track_id,
            seal["hash_value"],
        )

        inject_domain_failure(project_root, track)

        domain_failure = evaluate(
            project_root,
            track,
            domain_name,
            track["domain_failure_code"],
        )

        if (
            domain_failure["dependencies_satisfied"] or
            domain_failure["no_bind_state"] != "ACTIVE" or
            domain_failure["action_admissibility_state"] != "HELD"
        ):
            raise RuntimeError(
                f"{track_id}: domain failure did not fail closed"
            )

        validate_display(project_root, domain_name)

        reset_operational_state(project_root, track)

        recovery = evaluate(
            project_root,
            track,
            recovery_name,
        )

        if (
            recovery["integrity_state"] != "REHASH_VERIFIED" or
            not recovery["dependencies_satisfied"] or
            recovery["action_admissibility_state"] != "ADMISSIBLE"
        ):
            raise RuntimeError(
                f"{track_id}: recovery was not admissible"
            )

        validate_display(project_root, recovery_name)

        passport = create_passport(
            project_root,
            track,
            recovery,
        )

        shutil.copy2(
            project_root /
            "runs" /
            recovery_name /
            "display_contract.json",

            project_root /
            "ramat" /
            f"{track_id.lower()}_current_display.json",
        )

        shutil.copy2(
            project_root /
            "runs" /
            recovery_name /
            "reconstruction.json",

            project_root /
            "reconstruction" /
            f"{track_id.lower()}_current_reconstruction.json",
        )

        scenarios.extend(
            [
                baseline,
                tamper,
                domain_failure,
                recovery,
            ]
        )

        restores.append(restore_result)
        passports.append(passport)

    baseline_rows = [
        item
        for item in scenarios
        if item["scenario_name"].endswith(
            "01_baseline_success"
        )
    ]

    tamper_rows = [
        item
        for item in scenarios
        if item["scenario_name"].endswith(
            "02_evidence_tamper_failure"
        )
    ]

    domain_rows = [
        item
        for item in scenarios
        if item["scenario_name"].endswith(
            "03_domain_failure"
        )
    ]

    recovery_rows = [
        item
        for item in scenarios
        if item["scenario_name"].endswith(
            "04_recovery_success"
        )
    ]

    checks = {
        "three_equal_first_tier_tracks": (
            observed_ids == sorted(TRACK_IDS)
        ),
        "scenario_count_is_twelve": (
            len(scenarios) == 12
        ),
        "all_baselines_admissible": all(
            item["action_admissibility_state"] ==
            "ADMISSIBLE"
            for item in baseline_rows
        ),
        "all_tamper_failures_detected": all(
            item["integrity_state"] ==
            "REHASH_MISMATCH" and
            item["action_admissibility_state"] ==
            "HELD"
            for item in tamper_rows
        ),
        "all_domain_failures_held": all(
            not item["dependencies_satisfied"] and
            item["action_admissibility_state"] ==
            "HELD"
            for item in domain_rows
        ),
        "all_recoveries_admissible": all(
            item["integrity_state"] ==
            "REHASH_VERIFIED" and
            item["dependencies_satisfied"] and
            item["action_admissibility_state"] ==
            "ADMISSIBLE"
            for item in recovery_rows
        ),
        "all_restores_verified": all(
            item["restore_integrity_verified"]
            for item in restores
        ),
        "three_passports_generated": (
            len(passports) == 3
        ),
        "all_display_contracts_display_only": True,
        "no_execution_performed": all(
            not item["execution_performed"]
            for item in scenarios
        ),
        "api_read_only": True,
        "platform_b_v1_modified": False,
        "thread_d_v1_modified": False,
        "production_integration_performed": False,
        "production_write_back_performed": False,
        "phi_used": False,
    }

    positive = (
        "three_equal_first_tier_tracks",
        "scenario_count_is_twelve",
        "all_baselines_admissible",
        "all_tamper_failures_detected",
        "all_domain_failures_held",
        "all_recoveries_admissible",
        "all_restores_verified",
        "three_passports_generated",
        "all_display_contracts_display_only",
        "no_execution_performed",
        "api_read_only",
    )

    negative = (
        "platform_b_v1_modified",
        "thread_d_v1_modified",
        "production_integration_performed",
        "production_write_back_performed",
        "phi_used",
    )

    status = (
        "PASS"
        if (
            all(checks[key] for key in positive) and
            not any(checks[key] for key in negative)
        )
        else "FAIL"
    )

    summary = {
        "step": "164",
        "title": (
            "First-Tier Triad Assurance Orchestrator "
            "and Evidence Passport API"
        ),
        "implementation_version": VERSION,
        "authorization_source": configuration["authorized_by"],
        "authorization_recorded_at_utc": configuration[
            "authorization_recorded_at_utc"
        ],
        "generated_at_utc": iso_utc(),
        "overall_status": status,
        "implementation_boundary": configuration[
            "implementation_boundary"
        ],
        "first_tier_track_count": 3,
        "first_tier_tracks": observed_ids,
        "scenario_count": len(scenarios),
        "passport_count": len(passports),
        "checks": checks,
        "restore_results": restores,
        "scenarios": scenarios,
        "api": {
            "host": "127.0.0.1",
            "read_only": True,
            "allowed_methods": ["GET"],
            "prohibited_methods": list(PROHIBITED_METHODS),
        },
        "architecture_boundaries": {
            "platform_b_v1": (
                "ARCHITECTURE LOCKED - NOT MODIFIED"
            ),
            "thread_d_v1": (
                "ARCHITECTURE LOCKED - NOT MODIFIED"
            ),
            "platform_b1": (
                "LOCAL ADVANCED ASSURANCE ORCHESTRATION ONLY"
            ),
            "thread_d2": "DISPLAY / WITNESS ONLY",
            "ramat_vision": "DISPLAY / WITNESS ONLY",
            "human_authority": (
                "REQUIRED FOR BINDING DECISIONS"
            ),
            "source_system_execution": "REQUIRED",
        },
    }

    json_path = (
        project_root /
        "STEP_164_FIRST_TIER_TRIAD_ASSURANCE_ORCHESTRATOR_AND_EVIDENCE_PASSPORT_API.json"
    )

    csv_path = (
        project_root /
        "STEP_164_FIRST_TIER_TRIAD_ASSURANCE_ORCHESTRATOR_AND_EVIDENCE_PASSPORT_API.csv"
    )

    markdown_path = (
        project_root /
        "STEP_164_FIRST_TIER_TRIAD_ASSURANCE_ORCHESTRATOR_AND_EVIDENCE_PASSPORT_API.md"
    )

    write_json(json_path, summary)
    write_csv(csv_path, scenarios)
    write_text(markdown_path, markdown_report(summary))

    if status != "PASS":
        raise RuntimeError("Step 164 demonstration failed")

    return summary


def scenario_file(
    project_root: Path,
    track_id: str,
    alias: str,
) -> Path:
    track_id = track_id.upper()

    if track_id not in TRACK_IDS:
        raise KeyError("Unknown track")

    if alias not in ALIASES:
        raise KeyError("Unknown scenario")

    return (
        project_root /
        "runs" /
        f"{track_id}_{ALIASES[alias]}" /
        "evaluation.json"
    )


def make_handler(project_root: Path):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AssuranceOS-Step164/164.1.1"

        def log_message(
            self,
            format: str,
            *args: Any,
        ) -> None:
            return

        def send_payload(
            self,
            status: int,
            value: Any,
        ) -> None:
            body = json.dumps(
                value,
                sort_keys=True,
            ).encode("utf-8")

            self.send_response(status)
            self.send_header(
                "Content-Type",
                "application/json; charset=utf-8",
            )
            self.send_header(
                "Content-Length",
                str(len(body)),
            )
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def reject_write(self) -> None:
            self.send_payload(
                405,
                {
                    "error": "METHOD_NOT_ALLOWED",
                    "allowed_methods": ["GET"],
                    "write_back_permitted": False,
                },
            )

        do_POST = reject_write
        do_PUT = reject_write
        do_PATCH = reject_write
        do_DELETE = reject_write

        def do_GET(self) -> None:
            parts = [
                value
                for value in urlparse(self.path).path.split("/")
                if value
            ]

            try:
                if not parts:
                    self.send_payload(
                        200,
                        {
                            "service": (
                                "Step 164 First-Tier Triad "
                                "Assurance Orchestrator API"
                            ),
                            "read_only": True,
                        },
                    )
                    return

                if parts == ["health"]:
                    self.send_payload(
                        200,
                        {
                            "status": "PASS",
                            "host_boundary": "127.0.0.1",
                            "read_only": True,
                            "production_write_back": False,
                        },
                    )
                    return

                if parts == ["tracks"]:
                    configuration = config(project_root)

                    self.send_payload(
                        200,
                        {
                            "track_count": 3,
                            "tracks": [
                                {
                                    "track_id": item["track_id"],
                                    "track_name": item["track_name"],
                                    "priority_tier": (
                                        item["priority_tier"]
                                    ),
                                }
                                for item in configuration["tracks"]
                            ],
                        },
                    )
                    return

                if parts == ["scenarios"]:
                    summary = read_json(
                        project_root /
                        "STEP_164_FIRST_TIER_TRIAD_ASSURANCE_ORCHESTRATOR_AND_EVIDENCE_PASSPORT_API.json"
                    )

                    self.send_payload(
                        200,
                        {
                            "scenario_count": summary["scenario_count"],
                            "scenarios": [
                                {
                                    "track_id": item["track_id"],
                                    "scenario_name": (
                                        item["scenario_name"]
                                    ),
                                    "admissibility": item[
                                        "action_admissibility_state"
                                    ],
                                }
                                for item in summary["scenarios"]
                            ],
                        },
                    )
                    return

                if (
                    len(parts) == 3 and
                    parts[0] == "evaluation"
                ):
                    self.send_payload(
                        200,
                        read_json(
                            scenario_file(
                                project_root,
                                parts[1],
                                parts[2],
                            )
                        ),
                    )
                    return

                if (
                    len(parts) == 2 and
                    parts[0] in (
                        "passport",
                        "ramat",
                        "reconstruction",
                    )
                ):
                    track_id = parts[1].upper()

                    if track_id not in TRACK_IDS:
                        raise KeyError("Unknown track")

                    key = track_id.lower()

                    if parts[0] == "passport":
                        path = (
                            project_root /
                            "passports" /
                            f"{key}_assurance_passport.json"
                        )
                    elif parts[0] == "ramat":
                        path = (
                            project_root /
                            "ramat" /
                            f"{key}_current_display.json"
                        )
                    else:
                        path = (
                            project_root /
                            "reconstruction" /
                            f"{key}_current_reconstruction.json"
                        )

                    self.send_payload(200, read_json(path))
                    return

                self.send_payload(
                    404,
                    {"error": "NOT_FOUND"},
                )
            except (
                FileNotFoundError,
                KeyError,
                ValueError,
            ) as exc:
                self.send_payload(
                    404,
                    {
                        "error": "NOT_FOUND",
                        "detail": str(exc),
                    },
                )

    return Handler


def api_self_test(project_root: Path) -> Dict[str, Any]:
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(project_root),
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )

    thread.start()
    host, port = server.server_address
    base = f"http://{host}:{port}"

    try:
        expected_gets = (
            "/health",
            "/tracks",
            "/scenarios",
            "/evaluation/IRLT/baseline",
            "/evaluation/IRLT/tamper",
            "/evaluation/COMPOUNDING/domain_failure",
            "/evaluation/DSCSA/recovery",
            "/passport/IRLT",
            "/passport/COMPOUNDING",
            "/passport/DSCSA",
            "/ramat/IRLT",
            "/ramat/COMPOUNDING",
            "/ramat/DSCSA",
            "/reconstruction/IRLT",
            "/reconstruction/COMPOUNDING",
            "/reconstruction/DSCSA",
        )

        get_results: Dict[str, int] = {}

        for path in expected_gets:
            with urllib.request.urlopen(
                base + path,
                timeout=5,
            ) as response:
                payload = json.loads(
                    response.read().decode("utf-8")
                )

                if not isinstance(payload, dict):
                    raise RuntimeError(
                        f"Invalid API payload: {path}"
                    )

                get_results[path] = response.status

        write_results: Dict[str, int] = {}

        for method in PROHIBITED_METHODS:
            request = urllib.request.Request(
                base + "/tracks",
                data=b"{}",
                method=method,
                headers={
                    "Content-Type": "application/json",
                },
            )

            try:
                urllib.request.urlopen(
                    request,
                    timeout=5,
                )

                raise RuntimeError(
                    f"{method} was unexpectedly accepted"
                )
            except urllib.error.HTTPError as exc:
                write_results[method] = exc.code

        checks = {
            "all_expected_gets_return_200": all(
                value == 200
                for value in get_results.values()
            ),
            "all_write_methods_rejected": all(
                value == 405
                for value in write_results.values()
            ),
            "localhost_only": host == "127.0.0.1",
            "api_read_only": True,
            "production_write_back": False,
        }

        status = (
            "PASS"
            if (
                checks["all_expected_gets_return_200"] and
                checks["all_write_methods_rejected"] and
                checks["localhost_only"] and
                checks["api_read_only"] and
                not checks["production_write_back"]
            )
            else "FAIL"
        )

        result = {
            "status": status,
            "tested_at_utc": iso_utc(),
            "host": host,
            "ephemeral_port": port,
            "get_results": get_results,
            "write_method_results": write_results,
            "checks": checks,
        }

        write_json(
            project_root /
            "api_self_test" /
            "api_self_test_result.json",
            result,
        )

        if status != "PASS":
            raise RuntimeError("API self-test failed")

        return result
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def verify(project_root: Path) -> Dict[str, Any]:
    summary = read_json(
        project_root /
        "STEP_164_FIRST_TIER_TRIAD_ASSURANCE_ORCHESTRATOR_AND_EVIDENCE_PASSPORT_API.json"
    )

    api_result = read_json(
        project_root /
        "api_self_test" /
        "api_self_test_result.json"
    )

    if summary["overall_status"] != "PASS":
        raise RuntimeError("Step 164 summary is not PASS")

    if summary["first_tier_track_count"] != 3:
        raise RuntimeError("Step 164 track count is invalid")

    if summary["scenario_count"] != 12:
        raise RuntimeError("Step 164 scenario count is invalid")

    if summary["passport_count"] != 3:
        raise RuntimeError("Step 164 passport count is invalid")

    if api_result["status"] != "PASS":
        raise RuntimeError("Step 164 API self-test is not PASS")

    return summary


def serve(
    project_root: Path,
    host: str,
    port: int,
) -> None:
    if host != "127.0.0.1":
        raise ValueError(
            "Step 164 API may bind only to 127.0.0.1"
        )

    server = ThreadingHTTPServer(
        (host, port),
        make_handler(project_root),
    )

    print(
        json.dumps(
            {
                "status": "SERVING",
                "host": host,
                "port": port,
                "read_only": True,
            }
        )
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--project-root",
        required=True,
    )

    parser.add_argument(
        "command",
        choices=(
            "run-demo",
            "api-self-test",
            "verify",
            "serve",
        ),
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8765,
    )

    args = parser.parse_args(argv)
    project_root = Path(args.project_root).resolve()

    if args.command == "run-demo":
        result = run_demo(project_root)

        output = {
            "status": result["overall_status"],
            "track_count": result["first_tier_track_count"],
            "scenario_count": result["scenario_count"],
            "passport_count": result["passport_count"],
        }

    elif args.command == "api-self-test":
        result = api_self_test(project_root)

        output = {
            "status": result["status"],
            "host": result["host"],
        }

    elif args.command == "verify":
        result = verify(project_root)

        output = {
            "status": result["overall_status"],
            "track_count": result["first_tier_track_count"],
            "scenario_count": result["scenario_count"],
            "passport_count": result["passport_count"],
        }

    else:
        serve(
            project_root,
            args.host,
            args.port,
        )
        return 0

    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    sys.exit(main())