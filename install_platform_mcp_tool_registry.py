from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_MCP_TOOL_REGISTRY_V1_ACTIVE"

old_pattern = (
    r"\n?# ============================================================\n"
    r"# " + re.escape(MARKER) + r"\n"
    r"# ============================================================\n"
    r".*?"
    r"# ============================================================\n"
    r"# END " + re.escape(MARKER) + r"\n"
    r"# ============================================================\n?"
)
text = re.sub(old_pattern, "\n", text, flags=re.DOTALL)

all_routes = [
    "/platform/mcp-tools",
    "/platform/tool-call-evidence",
    "/mcp-tools",
    "/cobitchain-mcp-tools",
    "/api/platform/mcp/tools/demo",
    "/api/platform/mcp/tool-call/demo",
    "/api/platform/mcp/tool-call-log/demo"
]

for route in all_routes:
    if f'@app.route("{route}")' in text or f"@app.route('{route}')" in text:
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_MCP_TOOL_REGISTRY_V1_ACTIVE
# ============================================================

@app.route("/platform/mcp-tools")
@app.route("/platform/tool-call-evidence")
@app.route("/mcp-tools")
@app.route("/cobitchain-mcp-tools")
def cobitchain_platform_mcp_tool_registry():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_mcp_tool_registry.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_mcp_load_tools():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_mcp_tool_registry_seed.json")
    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("tools", [])
    except Exception:
        return []


def _cobitchain_mcp_find_tool(tool_id):
    wanted = str(tool_id or "").strip()
    for tool in _cobitchain_mcp_load_tools():
        if tool.get("tool_id") == wanted:
            return tool
    return None


def _cobitchain_mcp_append_log(record):
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_mcp_tool_call_log_demo.json")

    existing = []
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8")).get("tool_calls", [])
        except Exception:
            existing = []

    existing.append(record)
    existing = existing[-50:]

    path.write_text(
        json.dumps({"tool_calls": existing}, indent=2),
        encoding="utf-8"
    )


def _cobitchain_mcp_get_output(tool_id, object_id, package_id, asset_id, requested_action):
    output = {}
    evidence_binding = "No evidence binding available."
    decision_reason = "Tool executed in demo mode."

    if tool_id == "query_assurance_object":
        fn = globals().get("_cobitchain_build_unified_assurance_object")
        if fn:
            output = fn(object_id) or {}
            evidence_binding = "Bound to Unified Assurance Object demo response."
            decision_reason = "Read-only assurance object query completed."
        else:
            output = {"dependency_missing": "Unified Assurance Object service is not installed."}
            decision_reason = "Dependency missing."

    elif tool_id == "get_evidence_package":
        fn = globals().get("_cobitchain_load_demo_evidence_packages")
        enrich = globals().get("_cobitchain_enrich_evidence_package")
        if fn and enrich:
            packages = fn()
            found = None
            for item in packages:
                if item.get("package_id") == package_id:
                    found = item
                    break
            output = enrich(found) if found else {"package_not_found": package_id}
            evidence_binding = "Bound to Evidence Vault Live Package demo response."
            decision_reason = "Read-only evidence package query completed."
        else:
            output = {"dependency_missing": "Evidence Vault Live Package service is not installed."}
            decision_reason = "Dependency missing."

    elif tool_id == "vision_hud_lookup":
        find_asset = globals().get("_cobitchain_find_vision_asset")
        enrich_asset = globals().get("_cobitchain_enrich_vision_asset")
        if find_asset and enrich_asset:
            found = find_asset(asset_id)
            output = enrich_asset(found) if found else {"asset_not_found": asset_id}
            evidence_binding = "Bound to Governance Vision Lookup demo response."
            decision_reason = "Read-only HUD lookup completed."
        else:
            output = {"dependency_missing": "Governance Vision Lookup service is not installed."}
            decision_reason = "Dependency missing."

    elif tool_id == "action_guard_check":
        blocked_actions = [
            "approve_work",
            "modify_record",
            "bypass_sop",
            "change_access",
            "release_equipment",
            "approve_operation",
            "grant_access",
            "execute_change",
            "override_control"
        ]
        normalized_action = str(requested_action or "").strip().lower()
        action_blocked = normalized_action in blocked_actions
        output = {
            "object_id": object_id,
            "requested_action": requested_action,
            "action_allowed": not action_blocked,
            "decision": "BLOCKED" if action_blocked else "REVIEW_OR_READ_ONLY",
            "required_review": True,
            "limitations": [
                "Demo action guard only",
                "Does not execute the requested action",
                "High-risk actions require human review and formal workflow"
            ]
        }
        evidence_binding = "Bound to action guard rules and object identifier."
        decision_reason = "Requested action is blocked." if action_blocked else "Requested action is not directly blocked, but review is still required."

    else:
        output = {"error": "unknown_tool"}
        decision_reason = "Unknown tool."

    return output, evidence_binding, decision_reason


@app.route("/api/platform/mcp/tools/demo", methods=["GET"])
def cobitchain_platform_mcp_tools_demo_api():
    from flask import jsonify

    tools = _cobitchain_mcp_load_tools()
    return jsonify({
        "service": "COBIT-Chain MCP Tool Registry Demo",
        "count": len(tools),
        "tools": tools
    })


@app.route("/api/platform/mcp/tool-call/demo", methods=["GET"])
def cobitchain_platform_mcp_tool_call_demo_api():
    from flask import jsonify, request
    import uuid
    from datetime import datetime, timezone

    tool_id = request.args.get("tool_id", "query_assurance_object")
    object_id = request.args.get("object_id", "niagara-bms-supervisor")
    package_id = request.args.get("package_id", "EVP-NIAGARA-READINESS-001")
    asset_id = request.args.get("asset_id", "NIAGARA-BMS-SUPERVISOR")
    requested_action = request.args.get("requested_action", "read_assurance_state")

    tool = _cobitchain_mcp_find_tool(tool_id)
    if not tool:
        return jsonify({
            "error": "tool_not_found",
            "message": f"No MCP demo tool found for tool_id={tool_id}",
            "available_tool_ids": [item.get("tool_id") for item in _cobitchain_mcp_load_tools()]
        }), 404

    output, evidence_binding, decision_reason = _cobitchain_mcp_get_output(
        tool_id, object_id, package_id, asset_id, requested_action
    )

    blocked_actions = tool.get("blocked_actions", []) or []
    allowed_actions = tool.get("allowed_actions", []) or []

    normalized_action = str(requested_action or "").strip()
    action_blocked = normalized_action in blocked_actions
    action_allowed = normalized_action in allowed_actions and not action_blocked

    if action_blocked:
        decision = "BLOCKED"
    elif action_allowed:
        decision = "ALLOWED_READ_ONLY"
    elif tool.get("human_review_required"):
        decision = "REVIEW_REQUIRED"
    else:
        decision = "ALLOWED_WITH_LIMITATIONS"

    record = {
        "tool_call_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "tool_id": tool.get("tool_id"),
        "tool_name": tool.get("tool_name"),
        "tool_type": tool.get("tool_type"),
        "target_id": object_id or package_id or asset_id,
        "object_id": object_id,
        "package_id": package_id,
        "asset_id": asset_id,
        "requested_action": requested_action,
        "action_allowed": action_allowed,
        "decision": decision,
        "decision_reason": decision_reason,
        "evidence_binding": evidence_binding,
        "replay_ready": bool(tool.get("replay_required")) and bool(evidence_binding),
        "evidence_required": bool(tool.get("evidence_required")),
        "human_review_required": bool(tool.get("human_review_required")) or decision == "REVIEW_REQUIRED" or decision == "BLOCKED",
        "risk_level": tool.get("risk_level"),
        "allowed_actions": allowed_actions,
        "blocked_actions": blocked_actions,
        "output_summary": output,
        "service_note": "Demo MCP tool-call evidence. Future version should bind to Azure AI Foundry, Azure OpenAI, Azure AI Search, Azure API Management, Entra ID, and Application Insights."
    }

    _cobitchain_mcp_append_log(record)
    return jsonify(record)


@app.route("/api/platform/mcp/tool-call-log/demo", methods=["GET"])
def cobitchain_platform_mcp_tool_call_log_demo_api():
    from flask import jsonify
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_mcp_tool_call_log_demo.json")
    if not path.exists():
        return jsonify({
            "service": "COBIT-Chain MCP Tool Call Log Demo",
            "count": 0,
            "tool_calls": []
        })

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        calls = data.get("tool_calls", [])
    except Exception:
        calls = []

    return jsonify({
        "service": "COBIT-Chain MCP Tool Call Log Demo",
        "count": len(calls),
        "tool_calls": calls
    })

# ============================================================
# END COBITCHAIN_PLATFORM_MCP_TOOL_REGISTRY_V1_ACTIVE
# ============================================================

'''

targets = [
    'if __name__ == "__main__":',
    "if __name__ == '__main__':"
]

idx = -1
for target in targets:
    found = text.rfind(target)
    if found > idx:
        idx = found

if idx == -1:
    raise SystemExit("Could not locate Flask startup block. No changes made.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

Path("platform_mcp_tool_registry_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/mcp-tools",
        "http://127.0.0.1:5000/platform/tool-call-evidence",
        "http://127.0.0.1:5000/api/platform/mcp/tools/demo",
        "http://127.0.0.1:5000/api/platform/mcp/tool-call/demo?tool_id=query_assurance_object&object_id=niagara-bms-supervisor",
        "http://127.0.0.1:5000/api/platform/mcp/tool-call-log/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain MCP Tool Registry and Tool Call Evidence installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
