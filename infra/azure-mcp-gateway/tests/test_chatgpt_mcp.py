from fastapi.testclient import TestClient

from app.main import FROZEN_R1_TOOLS, app


client = TestClient(app)


def _rpc(method, params=None, request_id="test-1"):
    payload = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        payload["params"] = params
    return client.post("/mcp", json=payload)


def test_mcp_initialize_exposes_tools_capability():
    response = _rpc(
        "initialize",
        {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["jsonrpc"] == "2.0"
    assert body["result"]["protocolVersion"] == "2025-03-26"
    assert body["result"]["capabilities"]["tools"]["listChanged"] is False
    assert body["result"]["serverInfo"]["name"] == "cobit-chain-azure-mcp-gateway-r1"


def test_mcp_tools_list_is_exactly_frozen_r1_surface():
    response = _rpc("tools/list", {})
    assert response.status_code == 200
    tools = response.json()["result"]["tools"]
    names = {tool["name"] for tool in tools}
    assert names == set(FROZEN_R1_TOOLS)
    assert all(tool["annotations"]["readOnlyHint"] is True for tool in tools)
    assert all(tool["annotations"]["destructiveHint"] is False for tool in tools)


def test_mcp_denies_non_allowlisted_tool_before_authentication():
    response = _rpc(
        "tools/call",
        {"name": "group_create", "arguments": {"name": "should-not-run"}},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["error"]["code"] == -32003
    assert "denied" in body["error"]["message"].lower()


def test_mcp_allowed_tool_requires_oauth_bearer_token():
    response = _rpc(
        "tools/call",
        {"name": "subscription_list", "arguments": {}},
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    body = response.json()
    assert body["error"]["code"] == -32001


def test_mcp_unknown_method_is_not_executed():
    response = _rpc("resources/list", {})
    assert response.status_code == 200
    assert response.json()["error"]["code"] == -32601
