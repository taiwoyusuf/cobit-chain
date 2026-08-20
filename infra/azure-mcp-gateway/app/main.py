from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any

import httpx
from fastapi import Cookie, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from .auth import build_authorization_url, create_pkce_pair, create_state, exchange_code, load_oauth_config
from .evidence import emit_event
from .policy import PolicyDenied, authorize_tool, load_allowlist


APP_ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = load_allowlist(APP_ROOT / "config" / "allowlist.json")
UPSTREAM_MCP_URL = os.getenv("AZURE_MCP_URL", "https://mcp.management.azure.com")
SESSION_COOKIE = "cobit_chain_gateway_r1"

app = FastAPI(title="COBIT-Chain Azure MCP Gateway R1", version="0.1.0")

# R1 scaffold only. Production deployment must replace this process-local store
# with an encrypted server-side session implementation. Tokens must never be
# placed in browser-visible storage or evidence logs.
_sessions: dict[str, dict[str, Any]] = {}
_pending_auth: dict[str, dict[str, str]] = {}


class MCPInvokeRequest(BaseModel):
    tool: str
    arguments: dict[str, Any] = {}


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "mode": "r1-read-only"}


@app.get("/oauth/start")
async def oauth_start() -> RedirectResponse:
    config = load_oauth_config()
    verifier, challenge = create_pkce_pair()
    state = create_state()
    _pending_auth[state] = {"verifier": verifier}
    emit_event(event_type="oauth_start", session_id=None, tool_name=None, decision="allow")
    return RedirectResponse(build_authorization_url(config, state=state, challenge=challenge), status_code=302)


@app.get("/oauth/callback")
async def oauth_callback(code: str, state: str) -> RedirectResponse:
    pending = _pending_auth.pop(state, None)
    if pending is None:
        emit_event(event_type="oauth_callback", session_id=None, tool_name=None, decision="deny", detail={"reason": "invalid_state"})
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")

    config = load_oauth_config()
    token_response = await exchange_code(config, code=code, verifier=pending["verifier"])
    access_token = token_response.get("access_token")
    if not access_token:
        emit_event(event_type="oauth_callback", session_id=None, tool_name=None, decision="deny", detail={"reason": "no_access_token"})
        raise HTTPException(status_code=502, detail="OAuth token exchange did not return an access token")

    session_id = secrets.token_urlsafe(32)
    _sessions[session_id] = {
        "access_token": access_token,
        "refresh_token": token_response.get("refresh_token"),
        "expires_in": token_response.get("expires_in"),
    }
    emit_event(event_type="oauth_callback", session_id=session_id, tool_name=None, decision="allow")

    response = RedirectResponse(url="/healthz", status_code=302)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=3600,
    )
    return response


@app.post("/mcp/invoke")
async def invoke_mcp(
    payload: MCPInvokeRequest,
    request: Request,
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> JSONResponse:
    try:
        authorize_tool(payload.tool, ALLOWLIST)
    except PolicyDenied as exc:
        emit_event(
            event_type="policy_decision",
            session_id=session_id,
            tool_name=payload.tool,
            decision="deny",
            detail={"reason": str(exc)},
        )
        raise HTTPException(status_code=403, detail="R1 policy denied this operation") from exc

    session = _sessions.get(session_id or "")
    if session is None:
        emit_event(event_type="mcp_invoke", session_id=session_id, tool_name=payload.tool, decision="deny", detail={"reason": "missing_session"})
        raise HTTPException(status_code=401, detail="OAuth session required")

    emit_event(
        event_type="policy_decision",
        session_id=session_id,
        tool_name=payload.tool,
        decision="allow",
        detail={"argument_names": sorted(payload.arguments.keys()), "request_path": str(request.url.path)},
    )

    rpc_request = {
        "jsonrpc": "2.0",
        "id": secrets.token_hex(8),
        "method": "tools/call",
        "params": {"name": payload.tool, "arguments": payload.arguments},
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            upstream = await client.post(
                UPSTREAM_MCP_URL,
                headers={
                    "Authorization": f"Bearer {session['access_token']}",
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
                content=json.dumps(rpc_request),
            )
    except httpx.HTTPError as exc:
        emit_event(event_type="upstream_result", session_id=session_id, tool_name=payload.tool, decision="error", detail={"error_type": type(exc).__name__})
        raise HTTPException(status_code=502, detail="Azure MCP upstream request failed") from exc

    emit_event(
        event_type="upstream_result",
        session_id=session_id,
        tool_name=payload.tool,
        decision="allow" if upstream.is_success else "error",
        detail={"status_code": upstream.status_code, "content_type": upstream.headers.get("content-type")},
    )

    if not upstream.is_success:
        raise HTTPException(status_code=502, detail="Azure MCP upstream returned an error")

    content_type = upstream.headers.get("content-type", "")
    if "application/json" not in content_type:
        raise HTTPException(status_code=502, detail="R1 scaffold expects JSON upstream responses")

    return JSONResponse(content=upstream.json(), status_code=upstream.status_code)
