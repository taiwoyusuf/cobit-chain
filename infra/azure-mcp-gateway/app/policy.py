from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable


PROHIBITED_TERMS = {
    "create",
    "update",
    "delete",
    "write",
    "patch",
    "put",
    "post",
    "restart",
    "redeploy",
    "action",
    "assign",
    "grant",
    "rbac",
    "role_assignment",
    "role_definition",
    "permission",
    "secret",
    "key",
    "credential",
    "connection_string",
    "listkeys",
    "listsecrets",
}


class PolicyDenied(ValueError):
    pass


def load_allowlist(path: Path) -> set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("default") != "deny":
        raise RuntimeError("R1 requires default=deny")
    tools = data.get("tools")
    if not isinstance(tools, list) or not all(isinstance(item, str) for item in tools):
        raise RuntimeError("R1 allow-list must be an explicit string list")
    if any("*" in item for item in tools):
        raise RuntimeError("R1 forbids wildcard allow-list entries")
    return set(tools)


def _normalized_tokens(name: str) -> Iterable[str]:
    normalized = name.lower().replace("-", "_").replace(".", "_").replace("/", "_")
    return normalized.split("_")


def is_prohibited(tool_name: str) -> bool:
    lowered = tool_name.lower()
    if any(term in lowered for term in PROHIBITED_TERMS):
        return True
    return any(token in PROHIBITED_TERMS for token in _normalized_tokens(tool_name))


def authorize_tool(tool_name: str, allowlist: set[str]) -> None:
    if is_prohibited(tool_name):
        raise PolicyDenied(f"R1 prohibited operation: {tool_name}")
    if tool_name not in allowlist:
        raise PolicyDenied(f"R1 tool is not explicitly allow-listed: {tool_name}")
