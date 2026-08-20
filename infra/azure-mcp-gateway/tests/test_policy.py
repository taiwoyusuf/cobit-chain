import json
from pathlib import Path

import pytest

from app.policy import PolicyDenied, authorize_tool, is_prohibited, load_allowlist


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_ALLOWLIST = {"subscription_list", "group_list", "group_resource_list"}
EXPECTED_VERSION = "r1-catalog-reconciled-2026-08-20"


def test_allowlist_is_deny_by_default_and_no_wildcards() -> None:
    allowlist = load_allowlist(ROOT / "config" / "allowlist.json")
    assert allowlist == EXPECTED_ALLOWLIST
    assert all("*" not in tool for tool in allowlist)


def test_each_allowed_tool_has_verified_non_secret_catalog_evidence() -> None:
    data = json.loads((ROOT / "config" / "allowlist.json").read_text(encoding="utf-8"))
    assert data["version"] == EXPECTED_VERSION
    assert data["catalog_state"] == "frozen"
    evidence_record = data["evidence_record"]
    assert (ROOT / evidence_record).is_file()
    reconciliation = data["catalog_reconciliation"]
    assert set(reconciliation) == EXPECTED_ALLOWLIST
    for tool_name in EXPECTED_ALLOWLIST:
        evidence = reconciliation[tool_name]
        assert evidence["status"] == "verified"
        assert evidence["read_only"] is True
        assert evidence["secret"] is False


@pytest.mark.parametrize(
    "tool_name",
    [
        "resource_create",
        "resource_update",
        "resource_delete",
        "role_assignment_list",
        "rbac_get",
        "keyvault_secret_get",
        "storage_account_listkeys",
        "credential_export",
        "connection_string_get",
    ],
)
def test_prohibited_operation_names_are_blocked(tool_name: str) -> None:
    assert is_prohibited(tool_name)
    with pytest.raises(PolicyDenied):
        authorize_tool(tool_name, {tool_name})


def test_unlisted_tool_is_denied() -> None:
    with pytest.raises(PolicyDenied):
        authorize_tool("vm_get", EXPECTED_ALLOWLIST)


def test_explicit_safe_tools_are_allowed() -> None:
    for tool_name in EXPECTED_ALLOWLIST:
        authorize_tool(tool_name, EXPECTED_ALLOWLIST)
