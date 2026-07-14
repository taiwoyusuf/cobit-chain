import argparse
import json
from pathlib import Path

from .canonicalization import read_json
from .runtime import (
    reconstruct_all,
    run_all,
    verify_outputs,
)


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Local-only Assurance OS "
            "Step 170 runtime."
        )
    )

    parser.add_argument(
        "--root",
        default=str(
            Path(__file__).resolve().parents[1]
        ),
        help="Step 170 implementation root.",
    )

    subcommands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subcommands.add_parser("self-test")
    subcommands.add_parser("run-all")
    subcommands.add_parser("verify")

    reconstruct = subcommands.add_parser(
        "reconstruct"
    )

    reconstruct.add_argument(
        "--all",
        action="store_true",
        dest="all_records",
    )

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    root = Path(args.root).resolve()

    if args.command == "self-test":
        run_all(root)

        result = read_json(
            root /
            "self_test" /
            "self_test_result.json"
        )

    elif args.command == "run-all":
        result = run_all(root)

    elif args.command == "verify":
        result = verify_outputs(root)

    elif args.command == "reconstruct":
        result = reconstruct_all(root)

    else:
        raise RuntimeError(
            "Unsupported command."
        )

    print(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
    )

    passed = result.get(
        "valid",
        result.get(
            "passed",
            True,
        ),
    )

    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
