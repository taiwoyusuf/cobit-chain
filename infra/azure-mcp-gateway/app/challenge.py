from __future__ import annotations

import hashlib
import json
import re
from typing import Any


NEGATIVE_CHALLENGES = (
    "group_create",
    "role_assignment_create",
    "keyvault_secret_get",
    "storage_account_listkeys",
)

RESOURCE_GROUP_NAME = "rg-cobitchain-gateway-r1"
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def response_summary(value: Any) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "response_sha256": canonical_digest(value),
        "top_level_type": type(value).__name__,
    }
    if isinstance(value, dict):
        summary["top_level_keys"] = sorted(str(key) for key in value.keys())[:30]
        result = value.get("result")
        if isinstance(result, dict):
            summary["result_keys"] = sorted(str(key) for key in result.keys())[:30]
    elif isinstance(value, list):
        summary["top_level_count"] = len(value)
    return summary


def find_tool_schema(catalog_response: Any, tool_name: str) -> dict[str, Any] | None:
    if not isinstance(catalog_response, dict):
        return None
    result = catalog_response.get("result")
    if not isinstance(result, dict):
        return None
    tools = result.get("tools")
    if not isinstance(tools, list):
        return None
    for tool in tools:
        if isinstance(tool, dict) and tool.get("name") == tool_name:
            return tool
    return None


def tool_schema_evidence(tool_schema: dict[str, Any] | None) -> dict[str, Any]:
    if not tool_schema:
        return {"present_in_live_catalog": False}
    input_schema = tool_schema.get("inputSchema") or tool_schema.get("input_schema") or {}
    annotations = tool_schema.get("annotations") if isinstance(tool_schema.get("annotations"), dict) else {}
    return {
        "present_in_live_catalog": True,
        "input_schema_sha256": canonical_digest(input_schema),
        "required_parameters": sorted(input_schema.get("required") or []) if isinstance(input_schema, dict) else [],
        "annotations": {
            "readOnlyHint": annotations.get("readOnlyHint"),
            "destructiveHint": annotations.get("destructiveHint"),
            "idempotentHint": annotations.get("idempotentHint"),
            "openWorldHint": annotations.get("openWorldHint"),
        },
    }


def _walk_for_subscription_id(value: Any) -> str | None:
    if isinstance(value, dict):
        preferred = ("subscriptionId", "subscription_id", "id")
        for key in preferred:
            candidate = value.get(key)
            if isinstance(candidate, str) and _UUID_RE.fullmatch(candidate):
                return candidate
        for child in value.values():
            found = _walk_for_subscription_id(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _walk_for_subscription_id(child)
            if found:
                return found
    elif isinstance(value, str):
        try:
            parsed = json.loads(value)
        except Exception:
            parsed = None
        if parsed is not None:
            found = _walk_for_subscription_id(parsed)
            if found:
                return found
        for token in re.split(r"[^0-9a-fA-F-]+", value):
            if _UUID_RE.fullmatch(token):
                return token
    return None


def extract_subscription_id(subscription_response: Any) -> str | None:
    return _walk_for_subscription_id(subscription_response)


def build_group_resource_arguments(
    tool_schema: dict[str, Any] | None,
    *,
    resource_group: str,
    subscription_id: str | None,
) -> dict[str, str]:
    if not tool_schema:
        return {"resource-group": resource_group}

    input_schema = tool_schema.get("inputSchema") or tool_schema.get("input_schema") or {}
    properties = input_schema.get("properties") if isinstance(input_schema, dict) else {}
    required = input_schema.get("required") if isinstance(input_schema, dict) else []
    properties = properties if isinstance(properties, dict) else {}
    required = required if isinstance(required, list) else []

    args: dict[str, str] = {}
    for name in properties:
        normalized = re.sub(r"[^a-z0-9]", "", name.lower())
        if "resourcegroup" in normalized:
            args[name] = resource_group
        elif subscription_id and "subscription" in normalized:
            args[name] = subscription_id

    missing = [name for name in required if name not in args]
    if missing:
        raise ValueError(f"Unable to safely resolve required live tool parameters: {missing}")
    return args
