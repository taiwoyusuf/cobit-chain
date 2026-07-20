"""
Local deterministic source-only validator for patterns.

This file is created during Step 173C but is not executed until a
separately authorized Step 173D.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


VALIDATOR_ID = "patterns"
NETWORK_ALLOWED = False
PRODUCTION_DATA_ALLOWED = False
HARDWARE_ALLOWED = False


def load_json(path: Path) -> Any:
    """Load a local UTF-8 JSON document."""
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate(root: Path) -> list[str]:
    """Return deterministic validation findings without external side effects."""
    findings: list[str] = []

    if not root.exists():
        findings.append("root_missing")

    return findings


def validator_metadata() -> dict[str, object]:
    """Return immutable validator boundary metadata."""
    return {
        "validator_id": VALIDATOR_ID,
        "network_allowed": NETWORK_ALLOWED,
        "production_data_allowed": PRODUCTION_DATA_ALLOWED,
        "hardware_allowed": HARDWARE_ALLOWED,
    }
