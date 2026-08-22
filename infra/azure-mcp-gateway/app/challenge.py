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
APPROVED_LIVE_TOOL_PREFIXES = (
    "azmcp_",
    "mcp_azure_mcp_",
)
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


def catalog_identifier_match_mode(live_name: str, canonical_name: str) -> str | None:
    """Reconcile only exact or explicitly approved Azure MCP catalog prefixes.

    Arbitrary suffix matching is intentionally forbidden so a different tool cannot
    become eligible merely because its name happens to end with a frozen R1 name.
    """
    if live_name == canonical_name:
        return "exact"
    for prefix in APPROVED_LIVE_TOOL_PREFIXES:
        if live_name == f"{prefix}{canonical_name}":
            return f"approved_prefix:{prefix}"
    return None


def _tool_list_from_value(value: Any) -> list[dict[str, Any]]:
    """Extract MCP tool descriptors from known catalog response shapes only.

    Azure MCP transports may surface `tools/list` either as the normal
    `result.tools` structure or as JSON embedded in MCP content. This helper parses
    only explicit `tools` arrays and JSON content envelopes; it never authorizes a
    tool and never performs fuzzy name matching.
    """
    found: list[dict[str, Any]] = []

    if isinstance(value, dict):
        tools = value.get("tools")
        if isinstance(tools, list):
            found.extend(item for item in tools if isinstance(item, dict) and isinstance(item.get("name"), str))

        content = value.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    text = item.get("text")
                    if isinstance(text, str):
                        try:
                            parsed = json.loads(text)
                        except (json.JSONDecodeError, TypeError):
                            parsed = None
                        if parsed is not None:
                            found.extend(_tool_list_from_value(parsed))
                    found.extend(_tool_list_from_value({k: v for k, v in item.items() if k != "text"}))
                elif isinstance(item, str):
                    try:
                        parsed = json.loads(item)
                    except (json.JSONDecodeError, TypeError):
                        parsed = None
                    if parsed is not None:
                        found.extend(_tool_list_from_value(parsed))

        result = value.get("result")
        if result is not None:
            found.extend(_tool_list_from_value(result))

    elif isinstance(value, list):
        if all(isinstance(item, dict) and isinstance(item.get("name"), str) for item in value):
            found.extend(value)
        else:
            for item in value:
                found.extend(_tool_list_from_value(item))

    elif isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            parsed = None
        if parsed is not None:
            found.extend(_tool_list_from_value(parsed))

    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in found:
        name = item.get("name")
        if isinstance(name, str) and name not in seen:
            seen.add(name)
            deduped.append(item)
    return deduped


def catalog_structure_evidence(catalog_response: Any) -> dict[str, Any]:
    tools = _tool_list_from_value(catalog_response)
    names = sorted(item["name"] for item in tools if isinstance(item.get("name"), str))
    evidence: dict[str, Any] = {
        "extracted_tool_count": len(names),
        "live_tool_identifiers": names,
        "tool_identifiers_sha256": canonical_digest(names),
    }
    if isinstance(catalog_response, dict):
        evidence["top_level_keys"] = sorted(str(key) for key in catalog_response.keys())[:30]
        result = catalog_response.get("result")
        if isinstance(result, dict):
            evidence["result_keys"] = sorted(str(key) for key in result.keys())[:30]
    return evidence


def find_tool_schema(catalog_response: Any, tool_name: str) -> dict[str, Any] | None:
    for tool in _tool_list_from_value(catalog_response):
        live_name = tool.get("name")
        if isinstance(live_name, str) and catalog_identifier_match_mode(live_name, tool_name):
            return tool
    return None


def tool_schema_evidence(tool_schema: dict[str, Any] | None, canonical_name: str | None = None) -> dict[str, Any]:
    if not tool_schema:
        return {"present_in_live_catalog": False}
    input_schema = tool_schema.get("inputSchema") or tool_schema.get("input_schema") or {}
    annotations = tool_schema.get("annotations") if isinstance(tool_schema.get("annotations"), dict) else {}
    live_name = tool_schema.get("name") if isinstance(tool_schema.get("name"), str) else None
    evidence: dict[str, Any] = {
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
    if live_name is not None:
        evidence["live_catalog_identifier"] = live_name
    if canonical_name is not None and live_name is not None:
        evidence["canonical_identifier"] = canonical_name
        evidence["identifier_match_mode"] = catalog_identifier_match_mode(live_name, canonical_name)
    return evidence


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
