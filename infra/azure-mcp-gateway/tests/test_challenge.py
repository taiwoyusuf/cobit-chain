from app.challenge import (
    NEGATIVE_CHALLENGES,
    build_group_resource_arguments,
    canonical_digest,
    catalog_identifier_match_mode,
    catalog_structure_evidence,
    extract_subscription_id,
    find_tool_schema,
    tool_schema_evidence,
)
from app.policy import PolicyDenied, authorize_tool, load_allowlist
from pathlib import Path
import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_canonical_digest_is_stable_and_order_independent() -> None:
    assert canonical_digest({"b": 2, "a": 1}) == canonical_digest({"a": 1, "b": 2})


def test_live_schema_evidence_records_annotations_without_raw_schema() -> None:
    schema = {
        "name": "group_resource_list",
        "inputSchema": {
            "type": "object",
            "properties": {"resource-group": {"type": "string"}},
            "required": ["resource-group"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    }
    evidence = tool_schema_evidence(schema, canonical_name="group_resource_list")
    assert evidence["present_in_live_catalog"] is True
    assert evidence["required_parameters"] == ["resource-group"]
    assert evidence["annotations"]["readOnlyHint"] is True
    assert evidence["annotations"]["destructiveHint"] is False
    assert evidence["live_catalog_identifier"] == "group_resource_list"
    assert evidence["canonical_identifier"] == "group_resource_list"
    assert evidence["identifier_match_mode"] == "exact"
    assert "inputSchema" not in evidence


def test_live_catalog_exact_name_matches() -> None:
    catalog = {"result": {"tools": [{"name": "subscription_list", "inputSchema": {"type": "object"}}]}}
    schema = find_tool_schema(catalog, "subscription_list")
    assert schema is not None
    assert schema["name"] == "subscription_list"
    assert catalog_identifier_match_mode("subscription_list", "subscription_list") == "exact"


def test_live_catalog_azmcp_prefix_matches_frozen_canonical_name() -> None:
    catalog = {
        "result": {
            "tools": [
                {"name": "azmcp_subscription_list", "inputSchema": {"type": "object"}},
                {"name": "azmcp_group_list", "inputSchema": {"type": "object"}},
                {"name": "azmcp_group_resource_list", "inputSchema": {"type": "object"}},
            ]
        }
    }
    for canonical in ("subscription_list", "group_list", "group_resource_list"):
        schema = find_tool_schema(catalog, canonical)
        assert schema is not None
        assert schema["name"] == f"azmcp_{canonical}"
        assert catalog_identifier_match_mode(schema["name"], canonical) == "approved_prefix:azmcp_"


def test_live_catalog_known_client_prefix_matches_without_relaxing_policy() -> None:
    catalog = {"result": {"tools": [{"name": "mcp_azure_mcp_group_list", "inputSchema": {"type": "object"}}]}}
    schema = find_tool_schema(catalog, "group_list")
    assert schema is not None
    assert catalog_identifier_match_mode("mcp_azure_mcp_group_list", "group_list") == "approved_prefix:mcp_azure_mcp_"


def test_live_catalog_arbitrary_suffix_is_rejected() -> None:
    catalog = {
        "result": {
            "tools": [
                {"name": "dangerous_subscription_list", "inputSchema": {"type": "object"}},
                {"name": "other/group_list", "inputSchema": {"type": "object"}},
            ]
        }
    }
    assert find_tool_schema(catalog, "subscription_list") is None
    assert find_tool_schema(catalog, "group_list") is None
    assert catalog_identifier_match_mode("dangerous_subscription_list", "subscription_list") is None
    assert catalog_identifier_match_mode("other/group_list", "group_list") is None


def test_catalog_tools_can_be_extracted_from_json_text_content() -> None:
    catalog = {
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": '{"tools":[{"name":"azmcp_subscription_list","inputSchema":{"type":"object"}},{"name":"azmcp_group_list","inputSchema":{"type":"object"}}]}',
                }
            ]
        }
    }
    sub = find_tool_schema(catalog, "subscription_list")
    group = find_tool_schema(catalog, "group_list")
    assert sub is not None and sub["name"] == "azmcp_subscription_list"
    assert group is not None and group["name"] == "azmcp_group_list"
    structure = catalog_structure_evidence(catalog)
    assert structure["extracted_tool_count"] == 2
    assert structure["live_tool_identifiers"] == ["azmcp_group_list", "azmcp_subscription_list"]
    assert structure["top_level_keys"] == ["result"]
    assert structure["result_keys"] == ["content"]
    assert "tool_identifiers_sha256" in structure


def test_catalog_structure_exposes_names_only_not_tool_details() -> None:
    catalog = {
        "result": {
            "tools": [
                {"name": "public_tool_a", "description": "detail", "inputSchema": {"private_field": "not-returned"}},
                {"name": "public_tool_b", "annotations": {"readOnlyHint": True}},
            ]
        }
    }
    structure = catalog_structure_evidence(catalog)
    assert structure["live_tool_identifiers"] == ["public_tool_a", "public_tool_b"]
    serialized = str(structure)
    assert "not-returned" not in serialized
    assert "description" not in serialized
    assert "annotations" not in serialized


def test_catalog_tools_can_be_extracted_from_direct_list_payload() -> None:
    catalog = {
        "result": {
            "content": [
                {"type": "text", "text": '[{"name":"subscription_list","inputSchema":{"type":"object"}}]'}
            ]
        }
    }
    schema = find_tool_schema(catalog, "subscription_list")
    assert schema is not None
    assert schema["name"] == "subscription_list"


def test_catalog_content_does_not_relax_identifier_matching() -> None:
    catalog = {
        "result": {
            "content": [
                {"type": "text", "text": '{"tools":[{"name":"dangerous_subscription_list","inputSchema":{"type":"object"}}]}'}
            ]
        }
    }
    assert find_tool_schema(catalog, "subscription_list") is None


def test_group_resource_arguments_follow_live_schema_names() -> None:
    schema = {
        "inputSchema": {
            "type": "object",
            "properties": {"subscription": {"type": "string"}, "resource-group": {"type": "string"}},
            "required": ["resource-group"],
        }
    }
    args = build_group_resource_arguments(
        schema,
        resource_group="rg-proof",
        subscription_id="11111111-1111-1111-1111-111111111111",
    )
    assert args == {"subscription": "11111111-1111-1111-1111-111111111111", "resource-group": "rg-proof"}


def test_group_resource_arguments_stop_if_required_parameter_cannot_be_resolved() -> None:
    schema = {"inputSchema": {"type": "object", "properties": {"tenant": {"type": "string"}}, "required": ["tenant"]}}
    with pytest.raises(ValueError):
        build_group_resource_arguments(schema, resource_group="rg-proof", subscription_id=None)


def test_subscription_id_can_be_found_inside_structured_mcp_text() -> None:
    response = {
        "result": {
            "content": [
                {"type": "text", "text": '[{"subscriptionId":"11111111-1111-1111-1111-111111111111","name":"Example"}]'}
            ]
        }
    }
    assert extract_subscription_id(response) == "11111111-1111-1111-1111-111111111111"


def test_every_negative_challenge_is_denied_before_upstream() -> None:
    allowlist = load_allowlist(ROOT / "config" / "allowlist.json")
    for tool_name in NEGATIVE_CHALLENGES:
        with pytest.raises(PolicyDenied):
            authorize_tool(tool_name, allowlist)
