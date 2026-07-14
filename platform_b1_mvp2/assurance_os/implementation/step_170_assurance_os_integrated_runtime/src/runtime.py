import copy
from pathlib import Path

from .admissibility import determine_admissibility
from .audit_log import (
    append_event,
    verify_chain,
    write_jsonl,
)
from .authority_no_bind import evaluate_authority
from .backup_restore import (
    create_backup,
    verify_restore,
)
from .canonicalization import (
    read_json,
    write_json,
)
from .dependency_lens import evaluate_dependencies
from .display_contracts import build_display_contract
from .evidence_integrity import (
    create_seal,
    verify_payload,
)
from .inspection_bundle import build_bundle
from .passport_builder import build_passport
from .reconstruction import build_reconstruction
from .source_adapters import (
    load_fixture,
    load_scenario_catalog,
)


def _apply_mode(fixture, mode):
    working = copy.deepcopy(fixture)
    original_evidence = copy.deepcopy(
        working["evidence"]
    )

    if mode == "evidence_tamper":
        working["evidence"]["value"] = (
            working["evidence"]["value"] +
            " [TAMPERED]"
        )

    elif mode == "dependency_failure":
        working["dependencies"][0][
            "agrees"
        ] = False

    elif mode == "authority_failure":
        working["authority"][
            "authority_present"
        ] = False

        working["authority"][
            "approver_available"
        ] = False

    elif mode == "recovery":
        working["recovery"] = {
            "prior_failure_preserved": True,
            "restoration_verified": True,
        }

    return working, original_evidence


def evaluate_scenario(
    track,
    scenario,
    fixture,
    timestamp,
):
    working, original_evidence = (
        _apply_mode(
            fixture,
            scenario["mode"],
        )
    )

    object_id = working[
        "regulated_object"
    ]["object_id"]

    original_seal = create_seal(
        original_evidence,
        object_id,
        timestamp,
    )

    evidence_result = verify_payload(
        working["evidence"],
        original_seal,
    )

    dependency_result = (
        evaluate_dependencies(
            working["dependencies"]
        )
    )

    authority_result = (
        evaluate_authority(
            working["authority"]
        )
    )

    admissibility_result = (
        determine_admissibility(
            evidence_result,
            dependency_result,
            authority_result,
        )
    )

    expected_decision = scenario[
        "expected_decision"
    ]

    if (
        admissibility_result["decision"] !=
        expected_decision
    ):
        raise RuntimeError(
            "Scenario decision mismatch for " +
            track["code"] +
            "_" +
            scenario["id"]
        )

    scenario_id = (
        track["code"] +
        "_" +
        scenario["id"]
    )

    passport = build_passport(
        track["id"],
        scenario_id,
        working["regulated_object"],
        working["source_state"],
        evidence_result,
        dependency_result,
        authority_result,
        admissibility_result,
        timestamp,
    )

    passport_seal = create_seal(
        passport,
        scenario_id,
        timestamp,
    )

    reconstruction = build_reconstruction(
        track["id"],
        scenario_id,
        evidence_result,
        dependency_result,
        authority_result,
        admissibility_result,
        timestamp,
        working.get("recovery"),
    )

    display_contract = (
        build_display_contract(
            track["id"],
            scenario_id,
            authority_result,
            admissibility_result,
        )
    )

    evaluation = {
        "schema_version": "1.0",
        "track_id": track["id"],
        "scenario_id": scenario_id,
        "mode": scenario["mode"],
        "evidence_integrity": (
            evidence_result
        ),
        "workflow_dependencies": (
            dependency_result
        ),
        "authority": authority_result,
        "governance_no_bind": {
            "state": (
                admissibility_result[
                    "no_bind_state"
                ]
            ),
            "action_held": (
                admissibility_result[
                    "action_held"
                ]
            ),
            "escalation_required": (
                admissibility_result[
                    "escalation_required"
                ]
            ),
        },
        "action_admissibility": (
            admissibility_result
        ),
        "source_state": (
            working["source_state"]
        ),
        "regulated_object": (
            working["regulated_object"]
        ),
    }

    no_bind_state = {
        "schema_version": "1.0",
        "track_id": track["id"],
        "scenario_id": scenario_id,
        "no_bind_state": (
            admissibility_result[
                "no_bind_state"
            ]
        ),
        "action_held": (
            admissibility_result[
                "action_held"
            ]
        ),
        "escalation_required": (
            admissibility_result[
                "escalation_required"
            ]
        ),
        "documented_pause_created": (
            admissibility_result[
                "documented_pause_created"
            ]
        ),
        "reasons": sorted(
            set(
                authority_result["reasons"] +
                admissibility_result["reasons"]
            )
        ),
        "silence_is_not_consent": True,
    }

    return {
        "scenario_id": scenario_id,
        "evaluation": evaluation,
        "action_admissibility": (
            admissibility_result
        ),
        "no_bind_state": no_bind_state,
        "evidence_passport": passport,
        "evidence_passport_seal": (
            passport_seal
        ),
        "reconstruction": reconstruction,
        "display_contract": display_contract,
    }


def _write_scenario_outputs(
    runtime_root,
    result,
):
    run_root = (
        Path(runtime_root) /
        "runs" /
        result["scenario_id"]
    )

    write_json(
        run_root / "evaluation.json",
        result["evaluation"],
    )

    write_json(
        run_root /
        "action_admissibility.json",
        result["action_admissibility"],
    )

    write_json(
        run_root / "no_bind_state.json",
        result["no_bind_state"],
    )

    write_json(
        run_root / "evidence_passport.json",
        result["evidence_passport"],
    )

    write_json(
        run_root /
        "evidence_passport.seal.json",
        result["evidence_passport_seal"],
    )

    write_json(
        run_root / "reconstruction.json",
        result["reconstruction"],
    )

    write_json(
        run_root / "display_contract.json",
        result["display_contract"],
    )


def run_all(runtime_root):
    root = Path(runtime_root)
    catalog = load_scenario_catalog(root)
    timestamp = catalog[
        "deterministic_timestamp"
    ]

    audit_events = []
    scenario_results = []
    current_passports = []

    for track in catalog["tracks"]:
        fixture = load_fixture(
            root,
            track["id"],
        )

        track_results = []

        for scenario in track["scenarios"]:
            result = evaluate_scenario(
                track,
                scenario,
                fixture,
                timestamp,
            )

            _write_scenario_outputs(
                root,
                result,
            )

            track_results.append(result)
            scenario_results.append(result)

            append_event(
                audit_events,
                {
                    "timestamp": timestamp,
                    "track_id": track["id"],
                    "scenario_id": (
                        result["scenario_id"]
                    ),
                    "decision": (
                        result[
                            "action_admissibility"
                        ]["decision"]
                    ),
                    "no_bind_state": (
                        result[
                            "no_bind_state"
                        ]["no_bind_state"]
                    ),
                },
            )

        current = track_results[-1]
        current_passports.append(
            current["evidence_passport"]
        )

        write_json(
            root /
            "passports" /
            (
                track["id"] +
                "_current_assurance_passport.json"
            ),
            current["evidence_passport"],
        )

        write_json(
            root /
            "passports" /
            (
                track["id"] +
                "_current_assurance_passport.seal.json"
            ),
            current[
                "evidence_passport_seal"
            ],
        )

        write_json(
            root /
            "ramat" /
            (
                track["id"] +
                "_current_display.json"
            ),
            current["display_contract"],
        )

        write_json(
            root /
            "reconstruction" /
            (
                track["id"] +
                "_current_reconstruction.json"
            ),
            current["reconstruction"],
        )

        backup_path = (
            root /
            "backup" /
            (
                track["id"] +
                "_evidence.backup.json"
            )
        )

        verification_path = (
            root /
            "backup" /
            (
                track["id"] +
                "_restore_verification.json"
            )
        )

        create_backup(
            current["evidence_passport"],
            backup_path,
        )

        restore_result = verify_restore(
            backup_path,
            verification_path,
        )

        if not restore_result[
            "restore_verified"
        ]:
            raise RuntimeError(
                "Restore verification failed for " +
                track["id"]
            )

    if not verify_chain(audit_events):
        raise RuntimeError(
            "Hash-linked audit-event chain failed."
        )

    write_jsonl(
        root /
        "runs" /
        "audit_events.jsonl",
        audit_events,
    )

    admissible_count = sum(
        1
        for result in scenario_results
        if (
            result["action_admissibility"][
                "decision"
            ] == "ADMISSIBLE"
        )
    )

    not_admissible_count = (
        len(scenario_results) -
        admissible_count
    )

    runtime_summary = {
        "schema_version": "1.0",
        "scenario_count": (
            len(scenario_results)
        ),
        "admissible_count": (
            admissible_count
        ),
        "not_admissible_count": (
            not_admissible_count
        ),
        "audit_chain_verified": True,
        "generated_at": timestamp,
        "local_only": True,
        "production_connections": False,
        "deployment_performed": False,
    }

    write_json(
        root /
        "runs" /
        "runtime_summary.json",
        runtime_summary,
    )

    bundle, bundle_manifest = build_bundle(
        current_passports,
        runtime_summary,
        timestamp,
    )

    write_json(
        root /
        "bundle" /
        "inspection_passport_bundle.json",
        bundle,
    )

    write_json(
        root /
        "bundle" /
        "inspection_passport_bundle_manifest.json",
        bundle_manifest,
    )

    self_test_result = {
        "schema_version": "1.0",
        "passed": (
            len(scenario_results) == 16 and
            admissible_count == 8 and
            not_admissible_count == 8
        ),
        "scenario_count": (
            len(scenario_results)
        ),
        "admissible_count": (
            admissible_count
        ),
        "not_admissible_count": (
            not_admissible_count
        ),
        "audit_chain_verified": True,
        "generated_at": timestamp,
    }

    write_json(
        root /
        "self_test" /
        "self_test_result.json",
        self_test_result,
    )

    return runtime_summary


def verify_outputs(runtime_root):
    root = Path(runtime_root)

    manifest = read_json(
        root /
        "manifests" /
        "generated_output_manifest.json"
    )

    repository_root = (
        root.parent.parent.parent.parent
    )

    missing = []

    for relative_path in manifest[
        "generated_paths"
    ]:
        target = (
            repository_root /
            relative_path
        )

        if not target.exists():
            missing.append(relative_path)

    seal_failures = []

    for passport_path in root.glob(
        "runs/*/evidence_passport.json"
    ):
        seal_path = passport_path.with_name(
            "evidence_passport.seal.json"
        )

        if not seal_path.exists():
            seal_failures.append(
                str(passport_path)
            )
            continue

        passport = read_json(passport_path)
        seal = read_json(seal_path)

        if not verify_payload(
            passport,
            seal,
        )["valid"]:
            seal_failures.append(
                str(passport_path)
            )

    return {
        "valid": (
            not missing and
            not seal_failures
        ),
        "missing": missing,
        "seal_failures": seal_failures,
    }


def reconstruct_all(runtime_root):
    root = Path(runtime_root)

    paths = sorted(
        root.glob(
            "runs/*/reconstruction.json"
        )
    )

    return {
        "reconstruction_count": len(paths),
        "paths": [
            str(path)
            for path in paths
        ],
    }
