from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import Cookie, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from .auth import build_authorization_url, create_pkce_pair, create_state, exchange_code, load_oauth_config
from .challenge import (
    NEGATIVE_CHALLENGES,
    RESOURCE_GROUP_NAME,
    build_group_resource_arguments,
    canonical_digest,
    catalog_structure_evidence,
    extract_subscription_id,
    find_tool_schema,
    response_summary,
    tool_schema_evidence,
)
from .evidence import emit_event
from .mcp_client import MCPHTTPClient, MCPProtocolError
from .policy import PolicyDenied, authorize_tool, load_allowlist


APP_ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = load_allowlist(APP_ROOT / "config" / "allowlist.json")
UPSTREAM_MCP_URL = os.getenv("AZURE_MCP_URL", "https://mcp.management.azure.com")
SESSION_COOKIE = "cobit_chain_gateway_r1"
FROZEN_R1_TOOLS = ("subscription_list", "group_list", "group_resource_list")

app = FastAPI(title="COBIT-Chain Azure MCP Gateway R1", version="0.1.0")

# R1 proof deployment only. Before multi-replica or production operation, replace
# this process-local store with encrypted server-side session storage. Tokens are
# never returned in browser-visible evidence and are never written to evidence logs.
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


@app.post("/challenge/ta14-greg")
async def ta14_greg_challenge(
    request: Request,
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> JSONResponse:
    """Run one bounded, inspectable read-only proof for the TA-14 exchange.

    Raw Azure inventory and OAuth tokens are intentionally excluded from the
    returned record. Successful upstream responses are represented by hashes
    and structural summaries only.
    """
    session = _sessions.get(session_id or "")
    if session is None:
        raise HTTPException(status_code=401, detail="OAuth session required; visit /oauth/start first")

    started = datetime.now(timezone.utc)
    record: dict[str, Any] = {
        "schema": "cobit-chain.ta14.greg-evidence.r1",
        "challenge_id": "TA14-VSA-GREG-R1-001",
        "started_at_utc": started.isoformat(),
        "bounded_question": "Can the deployed gateway exercise only its frozen read-only Azure MCP surface while refusing prohibited write, RBAC, secret, and key routes?",
        "gateway_mode": "r1-read-only",
        "frozen_tools": list(FROZEN_R1_TOOLS),
        "upstream": UPSTREAM_MCP_URL,
        "raw_inventory_in_evidence": False,
        "oauth_token_in_evidence": False,
        "positive_proofs": {},
        "negative_policy_proofs": [],
        "catalog_evidence": {},
        "mcp_protocol": {},
        "claims": [
            "The frozen canonical tool identifiers correspond to authenticated live-catalog identifiers only by exact match or an explicitly approved Azure MCP prefix.",
            "Catalog response-shape reconciliation parses only explicit MCP tools arrays or JSON content envelopes and does not relax authorization policy.",
            "A positive proof marked success received a live Azure MCP response and records only a SHA-256 digest and structural summary.",
            "A negative proof marked denied was rejected locally before any upstream MCP request was sent.",
        ],
        "non_claims": [
            "This proof does not establish authority to perform Azure write operations.",
            "This proof does not establish that every Azure read operation is safe or applicable in every future context.",
            "This proof does not bypass human authority or expand the frozen R1 allow-list.",
        ],
    }

    emit_event(
        event_type="ta14_challenge_start",
        session_id=session_id,
        tool_name=None,
        decision="allow",
        detail={"challenge_id": record["challenge_id"], "request_path": str(request.url.path)},
    )

    client = MCPHTTPClient(url=UPSTREAM_MCP_URL, access_token=session["access_token"])
    try:
        initialize_response = await client.initialize()
        record["mcp_protocol"] = {
            "initialize_response_sha256": canonical_digest(initialize_response),
            "protocol_version": client.protocol_version,
            "server_info_sha256": canonical_digest(client.server_info or {}),
            "session_id_exposed_in_evidence": False,
        }

        catalog = await client.list_tools()
        record["catalog_sha256"] = canonical_digest(catalog)
        record["catalog_structure"] = catalog_structure_evidence(catalog)
        schemas: dict[str, dict[str, Any] | None] = {}
        for tool_name in FROZEN_R1_TOOLS:
            schema = find_tool_schema(catalog, tool_name)
            schemas[tool_name] = schema
            record["catalog_evidence"][tool_name] = tool_schema_evidence(schema, canonical_name=tool_name)

        subscription_response = await client.call_tool("subscription_list", {})
        record["positive_proofs"]["subscription_list"] = {
            "success": "error" not in subscription_response,
            "argument_names": [],
            **response_summary(subscription_response),
        }

        group_response = await client.call_tool("group_list", {})
        record["positive_proofs"]["group_list"] = {
            "success": "error" not in group_response,
            "argument_names": [],
            **response_summary(group_response),
        }

        subscription_id = extract_subscription_id(subscription_response)
        group_args = build_group_resource_arguments(
            schemas.get("group_resource_list"),
            resource_group=RESOURCE_GROUP_NAME,
            subscription_id=subscription_id,
        )
        group_resource_response = await client.call_tool("group_resource_list", group_args)
        record["positive_proofs"]["group_resource_list"] = {
            "success": "error" not in group_resource_response,
            "argument_names": sorted(group_args.keys()),
            "resource_group_value_redacted": True,
            **response_summary(group_resource_response),
        }

    except (MCPProtocolError, ValueError, httpx.HTTPError) as exc:
        record["live_proof_error"] = {
            "error_type": type(exc).__name__,
            "message": str(exc)[:300],
        }
    finally:
        await client.close()

    for prohibited_tool in NEGATIVE_CHALLENGES:
        denied = False
        reason = None
        try:
            authorize_tool(prohibited_tool, ALLOWLIST)
        except PolicyDenied as exc:
            denied = True
            reason = str(exc)
        record["negative_policy_proofs"].append(
            {
                "tool": prohibited_tool,
                "decision": "deny" if denied else "unexpected_allow",
                "upstream_request_sent": False,
                "reason": reason,
            }
        )

    positive_complete = set(record["positive_proofs"].keys()) == set(FROZEN_R1_TOOLS)
    positives_pass = positive_complete and all(item.get("success") for item in record["positive_proofs"].values())
    catalog_pass = all(item.get("present_in_live_catalog") for item in record["catalog_evidence"].values()) if record["catalog_evidence"] else False
    negatives_pass = all(item["decision"] == "deny" and item["upstream_request_sent"] is False for item in record["negative_policy_proofs"])
    record["result"] = {
        "catalog_pass": catalog_pass,
        "positive_live_read_pass": positives_pass,
        "negative_restraint_pass": negatives_pass,
        "overall_pass": catalog_pass and positives_pass and negatives_pass and "live_proof_error" not in record,
    }
    record["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    record["evidence_sha256"] = canonical_digest(record)

    emit_event(
        event_type="ta14_challenge_complete",
        session_id=session_id,
        tool_name=None,
        decision="allow" if record["result"]["overall_pass"] else "error",
        detail={"challenge_id": record["challenge_id"], "evidence_sha256": record["evidence_sha256"], **record["result"]},
    )
    return JSONResponse(content=record, status_code=200)
