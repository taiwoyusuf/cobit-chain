from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ASSURANCE_DECISION_ORCHESTRATOR_V1_ACTIVE"

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
    "/platform/ai-assurance-decision-orchestrator",
    "/platform/ai-assurance-orchestrator",
    "/platform/assurance-decision-orchestrator",
    "/ai-assurance-decision-orchestrator",
    "/api/platform/ai-assurance-orchestrator/model/demo",
    "/api/platform/ai-assurance-orchestrator/stage/demo",
    "/api/platform/ai-assurance-orchestrator/decision/demo",
    "/api/platform/ai-assurance-orchestrator/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ASSURANCE_DECISION_ORCHESTRATOR_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-assurance-decision-orchestrator")
@app.route("/platform/ai-assurance-orchestrator")
@app.route("/platform/assurance-decision-orchestrator")
@app.route("/ai-assurance-decision-orchestrator")
def cobitchain_platform_ai_assurance_decision_orchestrator():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_assurance_decision_orchestrator.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_assurance_decision_orchestrator():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_assurance_decision_orchestrator_seed.json")
    if not path.exists():
        return {"orchestration_stages": [], "sample_orchestration": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"orchestration_stages": [], "sample_orchestration": {}}


def _cobitchain_enrich_ai_assurance_orchestrator_stage(stage):
    import uuid
    from datetime import datetime, timezone

    data = dict(stage or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["platform_rule"] = "AI-enabled workflows must pass through architecture boundary assessment, control routing, evidence binding, and operational trust evaluation before approval."
    data["engineering_principle"] = "Assurance is not a dashboard view; assurance is an executable decision pathway that converts boundary findings into controls, evidence, approvals, and operational trust decisions."
    return data


def _cobitchain_enrich_ai_assurance_orchestrator_decision(decision):
    import uuid
    from datetime import datetime, timezone

    data = dict(decision or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("overall_assurance_score", 0) or 0)
    approved = bool(data.get("approved_for_operational_use", False))

    if approved and score >= 85:
        data["orchestration_state"] = "APPROVED"
    elif data.get("escalation_required") is True:
        data["orchestration_state"] = "HOLD_WITH_ESCALATION"
    elif score < 65:
        data["orchestration_state"] = "BLOCK"
    else:
        data["orchestration_state"] = "HOLD"

    data["platform_rule"] = "Boundary assessment becomes operational trust only after control routing, evidence binding, human approval, and final decision."
    data["engineering_principle"] = "Assurance is not a dashboard view; assurance is an executable decision pathway that converts boundary findings into controls, evidence, approvals, and operational trust decisions."
    return data


@app.route("/api/platform/ai-assurance-orchestrator/model/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_orchestrator_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_decision_orchestrator()
    stages = [_cobitchain_enrich_ai_assurance_orchestrator_stage(item) for item in payload.get("orchestration_stages", [])]
    decision = _cobitchain_enrich_ai_assurance_orchestrator_decision(payload.get("sample_orchestration", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in stages]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Assurance Decision Orchestrator Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "stage_count": len(stages),
        "average_stage_score": average,
        "orchestration_stages": stages,
        "decision_policy": payload.get("decision_policy", {}),
        "sample_orchestration": decision
    })


@app.route("/api/platform/ai-assurance-orchestrator/stage/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_orchestrator_stage_demo_api():
    from flask import jsonify, request

    stage_id = request.args.get("stage_id", "stage_1_architecture_boundary_assessment")
    payload = _cobitchain_load_ai_assurance_decision_orchestrator()
    stages = payload.get("orchestration_stages", []) or []

    for item in stages:
        if item.get("stage_id") == stage_id:
            return jsonify(_cobitchain_enrich_ai_assurance_orchestrator_stage(item))

    return jsonify({
        "error": "stage_not_found",
        "message": f"No AI Assurance Decision Orchestrator stage found for stage_id={stage_id}",
        "available_stage_ids": [item.get("stage_id") for item in stages]
    }), 404


@app.route("/api/platform/ai-assurance-orchestrator/decision/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_orchestrator_decision_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_assurance_decision_orchestrator()
    return jsonify(_cobitchain_enrich_ai_assurance_orchestrator_decision(payload.get("sample_orchestration", {})))


@app.route("/api/platform/ai-assurance-orchestrator/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_orchestrator_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_decision_orchestrator()
    stages = [_cobitchain_enrich_ai_assurance_orchestrator_stage(item) for item in payload.get("orchestration_stages", [])]
    decision = _cobitchain_enrich_ai_assurance_orchestrator_decision(payload.get("sample_orchestration", {}))

    weakest = sorted(
        [
            {
                "stage_id": item.get("stage_id"),
                "stage_name": item.get("stage_name"),
                "sample_score": item.get("sample_score"),
                "sample_status": item.get("sample_status"),
                "stage_decision": item.get("stage_decision")
            }
            for item in stages
        ],
        key=lambda x: int(x.get("sample_score", 0) or 0)
    )

    return jsonify({
        "service": "COBIT-Chain AI Assurance Decision Orchestrator Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_orchestration": decision,
        "weakest_stages": weakest,
        "required_actions": decision.get("required_actions", []),
        "engineering_principle": "Assurance is not a dashboard view; assurance is an executable decision pathway that converts boundary findings into controls, evidence, approvals, and operational trust decisions."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ASSURANCE_DECISION_ORCHESTRATOR_V1_ACTIVE
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

Path("platform_ai_assurance_decision_orchestrator_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-assurance-decision-orchestrator",
        "http://127.0.0.1:5000/platform/ai-assurance-orchestrator",
        "http://127.0.0.1:5000/platform/assurance-decision-orchestrator",
        "http://127.0.0.1:5000/api/platform/ai-assurance-orchestrator/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-orchestrator/stage/demo?stage_id=stage_1_architecture_boundary_assessment",
        "http://127.0.0.1:5000/api/platform/ai-assurance-orchestrator/stage/demo?stage_id=stage_2_control_routing",
        "http://127.0.0.1:5000/api/platform/ai-assurance-orchestrator/stage/demo?stage_id=stage_3_evidence_binding",
        "http://127.0.0.1:5000/api/platform/ai-assurance-orchestrator/decision/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-orchestrator/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Assurance Decision Orchestrator installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
