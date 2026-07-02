from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ASSURANCE_CONTROL_ROUTER_V1_ACTIVE"

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
    "/platform/ai-assurance-control-router",
    "/platform/ai-control-router",
    "/platform/architecture-control-router",
    "/ai-assurance-control-router",
    "/api/platform/ai-assurance-router/model/demo",
    "/api/platform/ai-assurance-router/route/demo",
    "/api/platform/ai-assurance-router/routing/demo",
    "/api/platform/ai-assurance-router/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ASSURANCE_CONTROL_ROUTER_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-assurance-control-router")
@app.route("/platform/ai-control-router")
@app.route("/platform/architecture-control-router")
@app.route("/ai-assurance-control-router")
def cobitchain_platform_ai_assurance_control_router():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_assurance_control_router.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_assurance_control_router():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_assurance_control_router_seed.json")
    if not path.exists():
        return {"control_routes": [], "sample_routing_decision": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"control_routes": [], "sample_routing_decision": {}}


def _cobitchain_enrich_ai_assurance_control_route(route):
    import uuid
    from datetime import datetime, timezone

    data = dict(route or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["platform_rule"] = "Boundary failures must activate the correct Platform A assurance controls before operational approval."
    data["engineering_principle"] = "Architecture assurance is not complete until boundary findings are routed to enforceable controls, evidence requirements, and accountable owners."
    return data


def _cobitchain_enrich_ai_assurance_routing_decision(decision):
    import uuid
    from datetime import datetime, timezone

    data = dict(decision or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["platform_rule"] = "AI Architecture Boundary Gate identifies the boundary state. AI Assurance Control Router determines which modules, controls, evidence objects, and approval gates must activate."
    data["engineering_principle"] = "Architecture assurance is not complete until boundary findings are routed to enforceable controls, evidence requirements, and accountable owners."

    if data.get("approved_for_operational_use") is True:
        data["routing_state"] = "APPROVED_AFTER_CONTROL_ROUTING"
    elif data.get("highest_priority") == "Critical":
        data["routing_state"] = "CRITICAL_CONTROL_ROUTING_REQUIRED"
    else:
        data["routing_state"] = "CONTROL_ROUTING_REQUIRED"

    return data


@app.route("/api/platform/ai-assurance-router/model/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_router_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_control_router()
    routes = [_cobitchain_enrich_ai_assurance_control_route(item) for item in payload.get("control_routes", [])]
    decision = _cobitchain_enrich_ai_assurance_routing_decision(payload.get("sample_routing_decision", {}))

    scores = [int(item.get("readiness_score", 0) or 0) for item in routes]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Assurance Control Router Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "depends_on": payload.get("depends_on", []),
        "routes_to_modules": payload.get("routes_to_modules", []),
        "control_route_count": len(routes),
        "average_route_readiness": average,
        "control_routes": routes,
        "sample_routing_decision": decision
    })


@app.route("/api/platform/ai-assurance-router/route/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_router_route_demo_api():
    from flask import jsonify, request

    route_id = request.args.get("route_id", "route_tool_assurance")
    payload = _cobitchain_load_ai_assurance_control_router()
    routes = payload.get("control_routes", []) or []

    for item in routes:
        if item.get("route_id") == route_id:
            return jsonify(_cobitchain_enrich_ai_assurance_control_route(item))

    return jsonify({
        "error": "route_not_found",
        "message": f"No AI Assurance Control Router route found for route_id={route_id}",
        "available_route_ids": [item.get("route_id") for item in routes]
    }), 404


@app.route("/api/platform/ai-assurance-router/routing/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_router_routing_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_assurance_control_router()
    return jsonify(_cobitchain_enrich_ai_assurance_routing_decision(payload.get("sample_routing_decision", {})))


@app.route("/api/platform/ai-assurance-router/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_router_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_control_router()
    routes = [_cobitchain_enrich_ai_assurance_control_route(item) for item in payload.get("control_routes", [])]
    decision = _cobitchain_enrich_ai_assurance_routing_decision(payload.get("sample_routing_decision", {}))

    critical = [
        {
            "route_id": item.get("route_id"),
            "boundary_name": item.get("boundary_name"),
            "priority": item.get("sample_priority"),
            "status": item.get("sample_status"),
            "owner_role": item.get("owner_role"),
            "activated_controls": item.get("activated_controls", [])
        }
        for item in routes
        if item.get("sample_priority") == "Critical"
    ]

    return jsonify({
        "service": "COBIT-Chain AI Assurance Control Router Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_routing_decision": decision,
        "critical_routes": critical,
        "required_module_actions": decision.get("required_module_actions", []),
        "engineering_principle": "Architecture assurance is not complete until boundary findings are routed to enforceable controls, evidence requirements, and accountable owners."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ASSURANCE_CONTROL_ROUTER_V1_ACTIVE
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

Path("platform_ai_assurance_control_router_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-assurance-control-router",
        "http://127.0.0.1:5000/platform/ai-control-router",
        "http://127.0.0.1:5000/platform/architecture-control-router",
        "http://127.0.0.1:5000/api/platform/ai-assurance-router/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-router/route/demo?route_id=route_knowledge_assurance",
        "http://127.0.0.1:5000/api/platform/ai-assurance-router/route/demo?route_id=route_tool_assurance",
        "http://127.0.0.1:5000/api/platform/ai-assurance-router/route/demo?route_id=route_autonomy_assurance",
        "http://127.0.0.1:5000/api/platform/ai-assurance-router/route/demo?route_id=route_evidence_assurance",
        "http://127.0.0.1:5000/api/platform/ai-assurance-router/routing/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-router/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Assurance Control Router installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
