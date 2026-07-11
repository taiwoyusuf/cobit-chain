"""
Platform B1 / MVP2 evaluator registry.

Purpose:
Connect each MVP2 evaluator to its mock data, schema, and Thread D2 display fixture.

Boundary:
- Local registry only.
- No Azure deployment.
- No Platform B v1 modification.
- No Thread D v1 modification.
- No real source-system integration.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


REGISTRY_PATH = Path(__file__).with_name("evaluator_registry.json")


def load_registry(path: Path | None = None) -> Dict[str, Any]:
    registry_path = path or REGISTRY_PATH
    with registry_path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def list_evaluators(registry: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    active_registry = registry or load_registry()
    return active_registry.get("evaluators", [])


def get_evaluator(feature_id: str, registry: Dict[str, Any] | None = None) -> Dict[str, Any]:
    active_registry = registry or load_registry()

    for evaluator in active_registry.get("evaluators", []):
        if evaluator.get("feature_id") == feature_id:
            return evaluator

    raise KeyError(f"Evaluator feature_id not found: {feature_id}")


def get_workflow_dependency_evaluator(registry: Dict[str, Any] | None = None) -> Dict[str, Any]:
    return get_evaluator("workflow_dependency_assurance_lens", registry=registry)


def main() -> int:
    registry = load_registry()
    print(json.dumps(registry, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
