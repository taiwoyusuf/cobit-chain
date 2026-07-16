"""Read-only static verifier for the Step 171 control plane."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def verify_static_baseline() -> dict:
    runtime = load_json(
        ROOT / "config" / "runtime_config.json"
    )

    tracks = load_json(
        ROOT / "config" / "track_registry.json"
    )

    scenarios = load_json(
        ROOT / "config" / "scenario_registry.json"
    )

    passed = (
        runtime["local_only"] is True
        and runtime["synthetic_only"] is True
        and runtime["network_enabled"] is False
        and runtime["production_connections_enabled"] is False
        and runtime["deployment_enabled"] is False
        and runtime["hardware_enabled"] is False
        and len(tracks["tracks"]) == 4
        and len(scenarios["scenarios"]) == 20
    )

    return {
        "passed": passed,
        "track_count": len(tracks["tracks"]),
        "scenario_count": len(scenarios["scenarios"]),
        "generated_outputs_created": False,
    }


def main() -> int:
    result = verify_static_baseline()

    print(
        json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":"),
        )
    )

    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
