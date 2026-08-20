from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any


LOGGER = logging.getLogger("azure_mcp_gateway.evidence")
SENSITIVE_KEYS = {
    "authorization",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "secret",
    "key",
    "connection_string",
    "cookie",
    "set-cookie",
}


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key.lower() in SENSITIVE_KEYS else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def emit_event(
    *,
    event_type: str,
    session_id: str | None,
    tool_name: str | None,
    decision: str,
    detail: dict[str, Any] | None = None,
) -> None:
    event = {
        "schema": "cobit-chain.azure-mcp-gateway.evidence.r1",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "session_ref": hashlib.sha256((session_id or "anonymous").encode()).hexdigest()[:16],
        "tool_name": tool_name,
        "decision": decision,
        "detail": _redact(detail or {}),
    }
    LOGGER.info(json.dumps(event, separators=(",", ":"), sort_keys=True))
