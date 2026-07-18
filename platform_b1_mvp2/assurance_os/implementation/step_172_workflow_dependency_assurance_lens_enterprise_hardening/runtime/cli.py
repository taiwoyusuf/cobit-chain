"""Synthetic deterministic Step 172C runtime component.

Platform B1 evaluates assurance state. Source systems remain authoritative.
Only an accountable human may bind regulated action.
RAMAT Vision and Thread D2 are display-only.
"""

import argparse
import json
from pathlib import Path
from typing import Sequence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read a synthetic Step 172 input document. "
            "Step 172D execution is not performed by Step 172C."
        )
    )

    parser.add_argument(
        "input_path",
        type=Path,
    )

    return parser


def main(argv: Sequence[str] = ()) -> int:
    parser = build_parser()
    args = parser.parse_args(
        list(argv) if argv else None
    )

    payload = json.loads(
        args.input_path.read_text(
            encoding="utf-8"
        )
    )

    print(
        json.dumps(
            {
                "input_loaded": True,
                "keys": sorted(payload),
                "step_172d_executed": False,
            },
            sort_keys=True,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
