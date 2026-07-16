"""Local dry-run CLI for the Step 171 control plane."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.control_plane import evaluate_session


CANONICAL_BASELINE_COMMIT = "ea22f14a84f7beeea3f446123059fc65660c38e6"


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate one synthetic Step 171 session "
            "without writing output."
        )
    )

    parser.add_argument("--track", required=True)
    parser.add_argument("--scenario", required=True)

    arguments = parser.parse_args()

    track_registry = load_json(
        ROOT / "config" / "track_registry.json"
    )

    scenario_registry = load_json(
        ROOT / "config" / "scenario_registry.json"
    )

    tracks = {
        item["code"]: item
        for item in track_registry["tracks"]
    }

    scenarios = {
        item["scenario_id"]: item
        for item in scenario_registry["scenarios"]
    }

    if arguments.track not in tracks:
        raise SystemExit("Unauthorized track")

    if arguments.scenario not in scenarios:
        raise SystemExit("Unauthorized scenario")

    scenario_metadata = scenarios[arguments.scenario]

    if scenario_metadata["track_code"] != arguments.track:
        raise SystemExit(
            "Scenario does not belong to the selected track"
        )

    fixture = load_json(
        ROOT / scenario_metadata["fixture_path"]
    )

    result = evaluate_session(
        tracks[arguments.track],
        scenario_metadata,
        fixture,
        CANONICAL_BASELINE_COMMIT,
        fixture["step170_references"],
    )

    print(
        json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":"),
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
