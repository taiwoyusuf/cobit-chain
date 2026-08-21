from __future__ import annotations

import json
import secrets
from typing import Any

import httpx


class MCPProtocolError(RuntimeError):
    pass


def _decode_mcp_response(response: httpx.Response) -> dict[str, Any]:
    content_type = response.headers.get("content-type", "").lower()
    if "application/json" in content_type:
        payload = response.json()
        if not isinstance(payload, dict):
            raise MCPProtocolError("MCP response was not a JSON object")
        return payload

    if "text/event-stream" in content_type:
        events: list[dict[str, Any]] = []
        for line in response.text.splitlines():
            if not line.startswith("data:"):
                continue
            raw = line[5:].strip()
            if not raw:
                continue
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                events.append(item)
        if not events:
            raise MCPProtocolError("MCP event stream did not contain a JSON-RPC event")
        return events[-1]

    raise MCPProtocolError(f"Unsupported MCP content type: {content_type or 'missing'}")


class MCPHTTPClient:
    def __init__(self, *, url: str, access_token: str) -> None:
        self.url = url
        self.access_token = access_token
        self.session_id: str | None = None
        self.protocol_version: str | None = None
        self.server_info: dict[str, Any] | None = None
        self._client = httpx.AsyncClient(timeout=30)

    async def close(self) -> None:
        await self._client.aclose()

    def _headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers

    async def _post(self, payload: dict[str, Any], *, expect_body: bool = True) -> dict[str, Any] | None:
        response = await self._client.post(self.url, headers=self._headers(), content=json.dumps(payload))
        if not response.is_success:
            raise MCPProtocolError(f"Azure MCP returned HTTP {response.status_code}")
        session_id = response.headers.get("Mcp-Session-Id") or response.headers.get("mcp-session-id")
        if session_id:
            self.session_id = session_id
        if not expect_body or not response.content:
            return None
        return _decode_mcp_response(response)

    async def initialize(self) -> dict[str, Any]:
        payload = {
            "jsonrpc": "2.0",
            "id": secrets.token_hex(8),
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "cobit-chain-gateway-r1", "version": "0.1.0"},
            },
        }
        result = await self._post(payload)
        if not isinstance(result, dict):
            raise MCPProtocolError("MCP initialize returned no response")
        rpc_result = result.get("result")
        if isinstance(rpc_result, dict):
            self.protocol_version = rpc_result.get("protocolVersion")
            info = rpc_result.get("serverInfo")
            self.server_info = info if isinstance(info, dict) else None
        await self._post(
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            expect_body=False,
        )
        return result

    async def list_tools(self) -> dict[str, Any]:
        result = await self._post(
            {"jsonrpc": "2.0", "id": secrets.token_hex(8), "method": "tools/list", "params": {}}
        )
        if not isinstance(result, dict):
            raise MCPProtocolError("MCP tools/list returned no response")
        return result

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = await self._post(
            {
                "jsonrpc": "2.0",
                "id": secrets.token_hex(8),
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )
        if not isinstance(result, dict):
            raise MCPProtocolError(f"MCP tool {name} returned no response")
        return result
