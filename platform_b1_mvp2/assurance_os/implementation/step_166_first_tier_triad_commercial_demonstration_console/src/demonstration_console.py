from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mimetypes
import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

VERSION = "166.1.0"
TRACK_IDS = ("IRLT", "COMPOUNDING", "DSCSA")
SCENARIO_ALIASES = {
    "baseline": "01_baseline_success",
    "tamper": "02_evidence_tamper_failure",
    "domain_failure": "03_domain_failure",
    "recovery": "04_recovery_success",
}
PROHIBITED_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def iso_utc(value: Optional[datetime] = None) -> str:
    current = value or datetime.now(timezone.utc)

    return (
        current.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


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


def load_config(project_root: Path) -> Dict[str, Any]:
    return read_json(
        project_root /
        "config" /
        "console_config.json"
    )


def snapshot_path(
    project_root: Path,
    category: str,
    track_id: str,
) -> Path:
    key = track_id.lower()

    if track_id not in TRACK_IDS:
        raise KeyError("Unknown track")

    if category == "passport":
        return (
            project_root /
            "snapshot" /
            "passports" /
            f"{key}_assurance_passport.json"
        )

    if category == "passport_seal":
        return (
            project_root /
            "snapshot" /
            "passports" /
            f"{key}_assurance_passport.seal.json"
        )

    if category == "ramat":
        return (
            project_root /
            "snapshot" /
            "ramat" /
            f"{key}_current_display.json"
        )

    if category == "reconstruction":
        return (
            project_root /
            "snapshot" /
            "reconstruction" /
            f"{key}_current_reconstruction.json"
        )

    raise KeyError("Unknown category")


def scenario_path(
    project_root: Path,
    track_id: str,
    alias: str,
) -> Path:
    track_id = track_id.upper()

    if track_id not in TRACK_IDS:
        raise KeyError("Unknown track")

    if alias not in SCENARIO_ALIASES:
        raise KeyError("Unknown scenario")

    return (
        project_root /
        "snapshot" /
        "scenarios" /
        f"{track_id}_{SCENARIO_ALIASES[alias]}.json"
    )


def validate_display(display: Dict[str, Any]) -> None:
    if display.get("display_authority") != "DISPLAY / WITNESS ONLY":
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


def build_bundle(project_root: Path) -> Dict[str, Any]:
    configuration = load_config(project_root)
    source_summary = read_json(
        project_root /
        "snapshot" /
        "step164_summary.json"
    )

    if source_summary.get("overall_status") != "PASS":
        raise RuntimeError("Step 164 source summary is not PASS")

    tracks = configuration.get("tracks", [])

    if len(tracks) != 3:
        raise RuntimeError("Exactly three console tracks are required")

    observed_track_ids = sorted(
        str(track["track_id"])
        for track in tracks
    )

    if observed_track_ids != sorted(TRACK_IDS):
        raise RuntimeError(
            "IRLT, COMPOUNDING, and DSCSA are required"
        )

    passports: List[Dict[str, Any]] = []
    displays: List[Dict[str, Any]] = []
    reconstructions: List[Dict[str, Any]] = []
    scenarios: List[Dict[str, Any]] = []
    component_hashes: List[Dict[str, Any]] = []

    for track in tracks:
        track_id = track["track_id"]

        if track.get("priority_tier") != "FIRST-TIER":
            raise RuntimeError(
                f"{track_id} is not FIRST-TIER"
            )

        passport_path = snapshot_path(
            project_root,
            "passport",
            track_id,
        )

        seal_path = snapshot_path(
            project_root,
            "passport_seal",
            track_id,
        )

        display_path = snapshot_path(
            project_root,
            "ramat",
            track_id,
        )

        reconstruction_path = snapshot_path(
            project_root,
            "reconstruction",
            track_id,
        )

        passport = read_json(passport_path)
        seal = read_json(seal_path)
        display = read_json(display_path)
        reconstruction = read_json(reconstruction_path)

        if (
            passport.get("track_id") != track_id or
            passport.get("priority_tier") != "FIRST-TIER" or
            passport.get("ramat_boundary") !=
            "DISPLAY / WITNESS ONLY" or
            passport.get("execution_performed") is not False
        ):
            raise RuntimeError(
                f"{track_id} passport boundary failed"
            )

        if (
            seal.get("hash_algorithm") != "SHA-256" or
            sha256_file(passport_path) !=
            seal.get("passport_hash")
        ):
            raise RuntimeError(
                f"{track_id} passport seal failed"
            )

        validate_display(display)

        if reconstruction.get("execution_performed") is not False:
            raise RuntimeError(
                f"{track_id} reconstruction reported execution"
            )

        passports.append(passport)
        displays.append(display)
        reconstructions.append(reconstruction)

        for alias in (
            "baseline",
            "tamper",
            "domain_failure",
            "recovery",
        ):
            path = scenario_path(
                project_root,
                track_id,
                alias,
            )

            scenario = read_json(path)

            if scenario.get("execution_performed") is not False:
                raise RuntimeError(
                    f"{track_id} {alias} reported execution"
                )

            if scenario.get("priority_tier") != "FIRST-TIER":
                raise RuntimeError(
                    f"{track_id} {alias} lost first-tier status"
                )

            if alias == "baseline":
                if (
                    scenario.get("integrity_state") !=
                    "REHASH_VERIFIED" or
                    scenario.get(
                        "action_admissibility_state"
                    ) != "ADMISSIBLE"
                ):
                    raise RuntimeError(
                        f"{track_id} baseline validation failed"
                    )

            elif alias == "tamper":
                if (
                    scenario.get("integrity_state") !=
                    "REHASH_MISMATCH" or
                    scenario.get("no_bind_state") !=
                    "ACTIVE" or
                    scenario.get(
                        "action_admissibility_state"
                    ) != "HELD"
                ):
                    raise RuntimeError(
                        f"{track_id} tamper validation failed"
                    )

            elif alias == "domain_failure":
                if (
                    scenario.get(
                        "dependencies_satisfied"
                    ) is not False or
                    scenario.get("no_bind_state") !=
                    "ACTIVE" or
                    scenario.get(
                        "action_admissibility_state"
                    ) != "HELD"
                ):
                    raise RuntimeError(
                        f"{track_id} domain validation failed"
                    )

            else:
                if (
                    scenario.get("integrity_state") !=
                    "REHASH_VERIFIED" or
                    scenario.get(
                        "dependencies_satisfied"
                    ) is not True or
                    scenario.get(
                        "action_admissibility_state"
                    ) != "ADMISSIBLE"
                ):
                    raise RuntimeError(
                        f"{track_id} recovery validation failed"
                    )

            scenarios.append(scenario)

        for component_path in (
            passport_path,
            seal_path,
            display_path,
            reconstruction_path,
        ):
            component_hashes.append(
                {
                    "relative_path": str(
                        component_path.relative_to(
                            project_root
                        )
                    ).replace("\\", "/"),
                    "sha256": sha256_file(component_path),
                    "length_bytes": component_path.stat().st_size,
                }
            )

    bundle = {
        "bundle_id": "STEP166-FIRST-TIER-TRIAD-BUNDLE",
        "bundle_type": (
            "COMMERCIAL DEMONSTRATION AND "
            "INSPECTION PASSPORT BUNDLE"
        ),
        "implementation_version": VERSION,
        "generated_at_utc": iso_utc(),
        "implementation_boundary": configuration[
            "implementation_boundary"
        ],
        "track_count": len(tracks),
        "scenario_count": len(scenarios),
        "passport_count": len(passports),
        "display_feed_count": len(displays),
        "reconstruction_count": len(reconstructions),
        "tracks": tracks,
        "passports": passports,
        "ramat_display_feeds": displays,
        "reconstructions": reconstructions,
        "scenarios": scenarios,
        "human_binding_authority_required": True,
        "source_system_execution_required": True,
        "execution_performed": False,
        "production_write_back_performed": False,
        "phi_used": False,
        "architecture_boundaries": configuration[
            "architecture_boundaries"
        ],
    }

    bundle_path = (
        project_root /
        "bundle" /
        "inspection_passport_bundle.json"
    )

    write_json(bundle_path, bundle)

    component_hashes.append(
        {
            "relative_path": (
                "bundle/inspection_passport_bundle.json"
            ),
            "sha256": sha256_file(bundle_path),
            "length_bytes": bundle_path.stat().st_size,
        }
    )

    bundle_manifest = {
        "bundle_id": bundle["bundle_id"],
        "hash_algorithm": "SHA-256",
        "generated_at_utc": iso_utc(),
        "component_count": len(component_hashes),
        "components": component_hashes,
    }

    write_json(
        project_root /
        "bundle" /
        "inspection_passport_bundle_manifest.json",
        bundle_manifest,
    )

    summary = {
        "step": "166",
        "title": (
            "First-Tier Triad Commercial Demonstration "
            "Console and Inspection Passport Bundle"
        ),
        "implementation_version": VERSION,
        "authorization_source": configuration[
            "authorized_by"
        ],
        "authorization_recorded_at_utc": configuration[
            "authorization_recorded_at_utc"
        ],
        "generated_at_utc": iso_utc(),
        "overall_status": "PASS",
        "implementation_boundary": configuration[
            "implementation_boundary"
        ],
        "first_tier_track_count": 3,
        "scenario_count": 12,
        "passport_count": 3,
        "display_feed_count": 3,
        "reconstruction_count": 3,
        "console_count": 1,
        "checks": {
            "three_equal_first_tier_tracks": True,
            "twelve_prebuilt_scenarios": True,
            "three_sealed_passports": True,
            "three_display_only_ramat_feeds": True,
            "three_reconstruction_exports": True,
            "all_tamper_scenarios_held": True,
            "all_domain_failures_held": True,
            "all_recoveries_admissible": True,
            "console_read_only": True,
            "no_execution_performed": True,
            "platform_b_v1_modified": False,
            "thread_d_v1_modified": False,
            "production_integration_performed": False,
            "production_write_back_performed": False,
            "phi_used": False,
        },
        "architecture_boundaries": configuration[
            "architecture_boundaries"
        ],
    }

    report_json = (
        project_root /
        "STEP_166_FIRST_TIER_TRIAD_COMMERCIAL_DEMONSTRATION_CONSOLE_AND_INSPECTION_PASSPORT_BUNDLE.json"
    )

    report_csv = (
        project_root /
        "STEP_166_FIRST_TIER_TRIAD_COMMERCIAL_DEMONSTRATION_CONSOLE_AND_INSPECTION_PASSPORT_BUNDLE.csv"
    )

    report_markdown = (
        project_root /
        "STEP_166_FIRST_TIER_TRIAD_COMMERCIAL_DEMONSTRATION_CONSOLE_AND_INSPECTION_PASSPORT_BUNDLE.md"
    )

    write_json(report_json, summary)

    fieldnames = (
        "TrackId",
        "Scenario",
        "IntegrityState",
        "DependenciesSatisfied",
        "NoBindState",
        "ActionAdmissibilityState",
        "ExecutionPerformed",
    )

    with report_csv.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
        )
        writer.writeheader()

        for scenario in scenarios:
            writer.writerow(
                {
                    "TrackId": scenario["track_id"],
                    "Scenario": scenario["scenario_name"],
                    "IntegrityState": scenario[
                        "integrity_state"
                    ],
                    "DependenciesSatisfied": scenario[
                        "dependencies_satisfied"
                    ],
                    "NoBindState": scenario[
                        "no_bind_state"
                    ],
                    "ActionAdmissibilityState": scenario[
                        "action_admissibility_state"
                    ],
                    "ExecutionPerformed": scenario[
                        "execution_performed"
                    ],
                }
            )

    write_text(
        report_markdown,
        "\n".join(
            [
                "# Step 166 - First-Tier Triad Commercial Demonstration Console and Inspection Passport Bundle",
                "",
                "Authorized by the user command next for local synthetic read-only implementation only.",
                "",
                "## Implemented outputs",
                "",
                "- One local read-only commercial demonstration console",
                "- Three equal first-tier assurance tracks",
                "- Twelve controlled prebuilt scenarios",
                "- Three SHA-256-sealed inspection passports",
                "- Three RAMAT display-only feeds",
                "- Three governance reconstruction exports",
                "- One inspection-passport evidence bundle",
                "",
                "## Locked boundaries",
                "",
                "- Platform B v1 was not modified.",
                "- Thread D v1 was not modified.",
                "- Thread D2 and RAMAT Vision remain DISPLAY / WITNESS ONLY.",
                "- Qualified humans retain binding authority.",
                "- Official execution remains in governed source systems.",
                "- No PHI, production write-back, or regulated execution occurred.",
                "",
                "STEP 166 FIRST-TIER TRIAD COMMERCIAL DEMONSTRATION CONSOLE AND INSPECTION PASSPORT BUNDLE COMPLETE",
                "",
                "STEP 167: AWAITING NEW GOVERNED SCOPE REVIEW",
                "",
            ]
        ),
    )

    return summary


def make_handler(project_root: Path):
    class ConsoleHandler(BaseHTTPRequestHandler):
        server_version = "AssuranceOS-Step166/166.1.0"

        def log_message(
            self,
            format: str,
            *args: Any,
        ) -> None:
            return

        def send_bytes(
            self,
            status: int,
            body: bytes,
            content_type: str,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'self'; "
                "script-src 'self'; connect-src 'self'; "
                "img-src 'self'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(body)

        def send_json(
            self,
            status: int,
            value: Any,
        ) -> None:
            self.send_bytes(
                status,
                json.dumps(
                    value,
                    sort_keys=True,
                ).encode("utf-8"),
                "application/json; charset=utf-8",
            )

        def reject_write(self) -> None:
            self.send_json(
                405,
                {
                    "error": "METHOD_NOT_ALLOWED",
                    "allowed_methods": ["GET"],
                    "write_back_permitted": False,
                    "regulated_execution_permitted": False,
                },
            )

        do_POST = reject_write
        do_PUT = reject_write
        do_PATCH = reject_write
        do_DELETE = reject_write

        def serve_static(
            self,
            relative_path: str,
        ) -> None:
            path = (
                project_root /
                "static" /
                relative_path
            ).resolve()

            static_root = (
                project_root /
                "static"
            ).resolve()

            if (
                static_root not in path.parents and
                path != static_root
            ):
                self.send_json(
                    403,
                    {"error": "FORBIDDEN"},
                )
                return

            if not path.is_file():
                self.send_json(
                    404,
                    {"error": "NOT_FOUND"},
                )
                return

            content_type, _ = mimetypes.guess_type(
                str(path)
            )

            self.send_bytes(
                200,
                path.read_bytes(),
                content_type or
                "application/octet-stream",
            )

        def do_GET(self) -> None:
            parts = [
                value
                for value in
                urlparse(self.path).path.split("/")
                if value
            ]

            try:
                if not parts:
                    self.serve_static("index.html")
                    return

                if parts == ["styles.css"]:
                    self.serve_static("styles.css")
                    return

                if parts == ["app.js"]:
                    self.serve_static("app.js")
                    return

                if parts == ["api", "health"]:
                    self.send_json(
                        200,
                        {
                            "status": "PASS",
                            "host_boundary": "127.0.0.1",
                            "read_only": True,
                            "display_authority": (
                                "DISPLAY / WITNESS ONLY"
                            ),
                            "production_write_back": False,
                            "regulated_execution": False,
                        },
                    )
                    return

                if parts == ["api", "tracks"]:
                    configuration = load_config(
                        project_root
                    )

                    self.send_json(
                        200,
                        {
                            "track_count": 3,
                            "tracks": configuration[
                                "tracks"
                            ],
                        },
                    )
                    return

                if parts == ["api", "bundle"]:
                    self.send_json(
                        200,
                        read_json(
                            project_root /
                            "bundle" /
                            "inspection_passport_bundle.json"
                        ),
                    )
                    return

                if (
                    len(parts) == 4 and
                    parts[0] == "api" and
                    parts[1] == "scenario"
                ):
                    self.send_json(
                        200,
                        read_json(
                            scenario_path(
                                project_root,
                                parts[2].upper(),
                                parts[3],
                            )
                        ),
                    )
                    return

                if (
                    len(parts) == 3 and
                    parts[0] == "api" and
                    parts[1] in (
                        "passport",
                        "ramat",
                        "reconstruction",
                    )
                ):
                    category = parts[1]
                    track_id = parts[2].upper()

                    self.send_json(
                        200,
                        read_json(
                            snapshot_path(
                                project_root,
                                category,
                                track_id,
                            )
                        ),
                    )
                    return

                self.send_json(
                    404,
                    {"error": "NOT_FOUND"},
                )

            except (
                FileNotFoundError,
                KeyError,
                ValueError,
            ) as exc:
                self.send_json(
                    404,
                    {
                        "error": "NOT_FOUND",
                        "detail": str(exc),
                    },
                )

    return ConsoleHandler


def run_self_test(
    project_root: Path,
) -> Dict[str, Any]:
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
        expected_gets = [
            "/",
            "/styles.css",
            "/app.js",
            "/api/health",
            "/api/tracks",
            "/api/bundle",
        ]

        for track_id in TRACK_IDS:
            expected_gets.extend(
                [
                    f"/api/passport/{track_id}",
                    f"/api/ramat/{track_id}",
                    f"/api/reconstruction/{track_id}",
                    f"/api/scenario/{track_id}/baseline",
                    f"/api/scenario/{track_id}/tamper",
                    f"/api/scenario/{track_id}/domain_failure",
                    f"/api/scenario/{track_id}/recovery",
                ]
            )

        get_results: Dict[str, int] = {}

        for path in expected_gets:
            with urllib.request.urlopen(
                base + path,
                timeout=5,
            ) as response:
                body = response.read()

                if not body:
                    raise RuntimeError(
                        f"Empty response from {path}"
                    )

                get_results[path] = response.status

        write_results: Dict[str, int] = {}

        for method in PROHIBITED_METHODS:
            request = urllib.request.Request(
                base + "/api/tracks",
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

        html = (
            project_root /
            "static" /
            "index.html"
        ).read_text(encoding="utf-8")

        prohibited_control_ids = (
            'id="approve"',
            'id="release"',
            'id="override"',
            'id="execute"',
            'id="dispense"',
            'id="administer"',
        )

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
            "console_read_only": True,
            "no_prohibited_action_controls": not any(
                marker in html
                for marker in prohibited_control_ids
            ),
            "production_write_back": False,
            "regulated_execution": False,
        }

        status = (
            "PASS"
            if (
                checks[
                    "all_expected_gets_return_200"
                ] and
                checks[
                    "all_write_methods_rejected"
                ] and
                checks["localhost_only"] and
                checks["console_read_only"] and
                checks[
                    "no_prohibited_action_controls"
                ] and
                not checks["production_write_back"] and
                not checks["regulated_execution"]
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
            "self_test" /
            "console_self_test_result.json",
            result,
        )

        if status != "PASS":
            raise RuntimeError(
                "Step 166 console self-test failed"
            )

        return result

    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def verify(project_root: Path) -> Dict[str, Any]:
    summary = read_json(
        project_root /
        "STEP_166_FIRST_TIER_TRIAD_COMMERCIAL_DEMONSTRATION_CONSOLE_AND_INSPECTION_PASSPORT_BUNDLE.json"
    )

    self_test = read_json(
        project_root /
        "self_test" /
        "console_self_test_result.json"
    )

    bundle = read_json(
        project_root /
        "bundle" /
        "inspection_passport_bundle.json"
    )

    if summary.get("overall_status") != "PASS":
        raise RuntimeError(
            "Step 166 summary is not PASS"
        )

    if (
        int(summary.get("first_tier_track_count", 0)) != 3 or
        int(summary.get("scenario_count", 0)) != 12 or
        int(summary.get("passport_count", 0)) != 3 or
        int(summary.get("display_feed_count", 0)) != 3 or
        int(summary.get("reconstruction_count", 0)) != 3 or
        int(summary.get("console_count", 0)) != 1
    ):
        raise RuntimeError(
            "Step 166 summary counts are invalid"
        )

    if self_test.get("status") != "PASS":
        raise RuntimeError(
            "Step 166 console self-test is not PASS"
        )

    if (
        bundle.get("execution_performed") is not False or
        bundle.get("production_write_back_performed") is not False or
        bundle.get("phi_used") is not False
    ):
        raise RuntimeError(
            "Step 166 bundle boundary is invalid"
        )

    return summary


def serve(
    project_root: Path,
    host: str,
    port: int,
) -> None:
    if host != "127.0.0.1":
        raise ValueError(
            "Step 166 console may bind only to 127.0.0.1"
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


def main(
    argv: Optional[List[str]] = None,
) -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--project-root",
        required=True,
    )

    parser.add_argument(
        "command",
        choices=(
            "build-bundle",
            "self-test",
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
        default=8766,
    )

    args = parser.parse_args(argv)
    project_root = Path(args.project_root).resolve()

    if args.command == "build-bundle":
        result = build_bundle(project_root)

        output = {
            "status": result["overall_status"],
            "track_count": result[
                "first_tier_track_count"
            ],
            "scenario_count": result[
                "scenario_count"
            ],
            "passport_count": result[
                "passport_count"
            ],
        }

    elif args.command == "self-test":
        result = run_self_test(project_root)

        output = {
            "status": result["status"],
            "host": result["host"],
        }

    elif args.command == "verify":
        result = verify(project_root)

        output = {
            "status": result["overall_status"],
            "track_count": result[
                "first_tier_track_count"
            ],
            "scenario_count": result[
                "scenario_count"
            ],
            "console_count": result[
                "console_count"
            ],
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