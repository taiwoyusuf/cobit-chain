from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AGENTIC_ACTION_ASSURANCE_FLOW_V1_ACTIVE"

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
    "/platform/agentic-action-assurance",
    "/platform/agent-action-assurance",
    "/platform/ai-action-assurance",
    "/agentic-action-assurance",
    "/api/platform/agentic-action/flow/demo",
    "/api/platform/agentic-action/stage/demo",
    "/api/platform/agentic-action/check/demo",
    "/api/platform/agentic-action/readiness/demo"
]

for route in all_routes:
    if f'@app.route("{route}")' in text or f"@app.route('{route}')" in text:
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AGENTIC_ACTION_ASSURANCE_FLOW_V1_ACTIVE
# ============================================================

@app.route("/platform/agentic-action-assurance")
@app.route("/platform/agent-action-assurance")
@app.route("/platform/ai-action-assurance")
@app.route("/agentic-action-assurance")
def cobitchain_platform_agentic_action_assurance_flow():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_agentic_action_assurance_flow.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_agentic_action_assurance_flow():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_agentic_action_assurance_seed.json")
    if not path.exists():
        return {"workflow": [], "sample_actions": [], "assurance_controls": []}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"workflow": [], "sample_actions": [], "assurance_controls": []}


def _cobitchain_agentic_readiness_band(score):
    score = int(score or 0)
    if score >= 85:
        return "STRONG"
    if score >= 75:
        return "GOOD_WITH_CONTROL_GAPS"
    if score >= 65:
        return "CAUTION"
    return "LIMITED"


def _cobitchain_enrich_agentic_action_stage(stage):
    import uuid
    from datetime import datetime, timezone

    data = dict(stage or {})
    score = int(data.get("readiness_score", 0) or 0)
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_band"] = _cobitchain_agentic_readiness_band(score)
    data["platform_rule"] = "Do not create a separate governance product for Agentic AI. Strengthen existing Platform A modules using action assurance patterns."
    data["service_note"] = "Agentic Action Assurance Flow evaluates AI-assisted operational actions before and after they affect regulated systems."
    return data


def _cobitchain_enrich_agentic_action_check(action):
    import uuid
    from datetime import datetime, timezone

    data = dict(action or {})
    score = int(data.get("trust_score", 0) or 0)
    decision = data.get("decision", "")

    if decision == "BLOCKED" or score < 60:
        readiness_state = "BLOCKED"
    elif score < 75:
        readiness_state = "HOLD_OR_CAUTION"
    elif data.get("state_verification_status") == "PENDING":
        readiness_state = "READY_WITH_VERIFICATION_REQUIRED"
    else:
        readiness_state = "READY"

    required_gates = [
        "Intent captured",
        "Authority verified",
        "Context validated",
        "Policy and risk evaluated",
        "Human approval checked",
        "MCP tool boundary checked",
        "State verification required",
        "Evidence package recorded",
        "Continuous assurance enabled"
    ]

    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_state"] = readiness_state
    data["required_gates"] = required_gates
    data["platform_rule"] = "Cloud platforms execute AI agents. COBIT-Chain evaluates whether AI-assisted actions are operationally trustworthy before they affect regulated systems."
    data["service_note"] = "This action check strengthens Agent Passport, Tool Call Evidence Ledger, AI Output Clearance, Operational Trust, Evidence Vault, Knowledge Integrity, and Decision Confidence."
    return data


@app.route("/api/platform/agentic-action/flow/demo", methods=["GET"])
def cobitchain_platform_agentic_action_flow_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    flow = _cobitchain_load_agentic_action_assurance_flow()
    workflow = [_cobitchain_enrich_agentic_action_stage(item) for item in flow.get("workflow", [])]
    sample_actions = [_cobitchain_enrich_agentic_action_check(item) for item in flow.get("sample_actions", [])]

    scores = [int(item.get("readiness_score", 0) or 0) for item in workflow]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain Agentic Action Assurance Flow Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "flow_name": flow.get("flow_name"),
        "platform_rule": flow.get("platform_rule"),
        "positioning": flow.get("positioning"),
        "workflow_stage_count": len(workflow),
        "sample_action_count": len(sample_actions),
        "average_stage_readiness": average,
        "workflow": workflow,
        "sample_actions": sample_actions,
        "assurance_controls": flow.get("assurance_controls", [])
    })


@app.route("/api/platform/agentic-action/stage/demo", methods=["GET"])
def cobitchain_platform_agentic_action_stage_demo_api():
    from flask import jsonify, request

    stage_id = request.args.get("stage_id", "authority")
    flow = _cobitchain_load_agentic_action_assurance_flow()
    stages = flow.get("workflow", []) or []

    for item in stages:
        if item.get("stage_id") == stage_id:
            return jsonify(_cobitchain_enrich_agentic_action_stage(item))

    return jsonify({
        "error": "stage_not_found",
        "message": f"No agentic action workflow stage found for stage_id={stage_id}",
        "available_stage_ids": [item.get("stage_id") for item in stages]
    }), 404


@app.route("/api/platform/agentic-action/check/demo", methods=["GET"])
def cobitchain_platform_agentic_action_check_demo_api():
    from flask import jsonify, request

    action_id = request.args.get("action_id", "ACT-RBAC-CHANGE-001")
    flow = _cobitchain_load_agentic_action_assurance_flow()
    actions = flow.get("sample_actions", []) or []

    for item in actions:
        if item.get("action_id") == action_id:
            return jsonify(_cobitchain_enrich_agentic_action_check(item))

    return jsonify({
        "error": "action_not_found",
        "message": f"No sample agentic action found for action_id={action_id}",
        "available_action_ids": [item.get("action_id") for item in actions]
    }), 404


@app.route("/api/platform/agentic-action/readiness/demo", methods=["GET"])
def cobitchain_platform_agentic_action_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    flow = _cobitchain_load_agentic_action_assurance_flow()
    actions = [_cobitchain_enrich_agentic_action_check(item) for item in flow.get("sample_actions", [])]

    scores = [int(item.get("trust_score", 0) or 0) for item in actions]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    blocked = [item for item in actions if item.get("decision") == "BLOCKED" or item.get("readiness_state") == "BLOCKED"]
    hold = [item for item in actions if "HOLD" in (item.get("decision", "") + item.get("readiness_state", ""))]

    required_actions = [
        "Require Agent Passport before any operational action.",
        "Require delegated authority check before execution.",
        "Route high-risk actions through human approval gates.",
        "Force MCP-governed tool execution for agentic actions.",
        "Bind tool-call evidence, state verification, and evidence package records.",
        "Continuously monitor downstream effects and accountability feedback."
    ]

    return jsonify({
        "service": "COBIT-Chain Agentic Action Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "average_action_trust_score": average,
        "action_count": len(actions),
        "blocked_action_count": len(blocked),
        "hold_action_count": len(hold),
        "blocked_actions": blocked,
        "hold_actions": hold,
        "required_actions": required_actions,
        "platform_rule": "Cloud platforms execute AI agents. COBIT-Chain evaluates whether AI-assisted actions are operationally trustworthy before they affect regulated systems."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AGENTIC_ACTION_ASSURANCE_FLOW_V1_ACTIVE
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

Path("platform_agentic_action_assurance_flow_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/agentic-action-assurance",
        "http://127.0.0.1:5000/platform/agent-action-assurance",
        "http://127.0.0.1:5000/platform/ai-action-assurance",
        "http://127.0.0.1:5000/api/platform/agentic-action/flow/demo",
        "http://127.0.0.1:5000/api/platform/agentic-action/stage/demo?stage_id=authority",
        "http://127.0.0.1:5000/api/platform/agentic-action/check/demo?action_id=ACT-RBAC-CHANGE-001",
        "http://127.0.0.1:5000/api/platform/agentic-action/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Agentic Action Assurance Flow installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
