from app.challenge import (
    NEGATIVE_CHALLENGES,
    build_group_resource_arguments,
    canonical_digest,
    extract_subscription_id,
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
    evidence = tool_schema_evidence(schema)
    assert evidence["present_in_live_catalog"] is True
    assert evidence["required_parameters"] == ["resource-group"]
    assert evidence["annotations"]["readOnlyHint"] is True
    assert evidence["annotations"]["destructiveHint"] is False
    assert "inputSchema" not in evidence


def test_group_resource_arguments_follow_live_schema_names() -> None:
    schema = {
        "inputSchema": {
            "type": "object",
            "properties": {
                "subscription": {"type": "string"},
                "resource-group": {"type": "string"},
            },
            "required": ["resource-group"],
        }
    }
    args = build_group_resource_arguments(
        schema,
        resource_group="rg-proof",
        subscription_id="11111111-1111-1111-1111-111111111111",
    )
    assert args == {
        "subscription": "11111111-1111-1111-1111-111111111111",
        "resource-group": "rg-proof",
    }


def test_group_resource_arguments_stop_if_required_parameter_cannot_be_resolved() -> None:
    schema = {
        "inputSchema": {
            "type": "object",
            "properties": {"tenant": {"type": "string"}},
            "required": ["tenant"],
        }
    }
    with pytest.raises(ValueError):
        build_group_resource_arguments(schema, resource_group="rg-proof", subscription_id=None)


def test_subscription_id_can_be_found_inside_structured_mcp_text() -> None:
    response = {
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": '[{"subscriptionId":"11111111-1111-1111-1111-111111111111","name":"Example"}]',
                }
            ]
        }
    }
    assert extract_subscription_id(response) == "11111111-1111-1111-1111-111111111111"


def test_every_negative_challenge_is_denied_before_upstream() -> None:
    allowlist = load_allowlist(ROOT / "config" / "allowlist.json")
    for tool_name in NEGATIVE_CHALLENGES:
        with pytest.raises(PolicyDenied):
            authorize_tool(tool_name, allowlist)
