from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_ACTION_ASSURANCE_WORKFLOW_V1_ACTIVE"

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
    "/platform/action-assurance-workflow",
    "/platform/action-assurance",
    "/platform/action-governance",
    "/action-assurance-workflow",
    "/api/platform/action-assurance/workflow/demo",
    "/api/platform/action-assurance/stage/demo",
    "/api/platform/action-assurance/check/demo",
    "/api/platform/action-assurance/readiness/demo"
]

for route in all_routes:
    if f'@app.route("{route}")' in text or f"@app.route('{route}')" in text:
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_ACTION_ASSURANCE_WORKFLOW_V1_ACTIVE
# ============================================================

@app.route("/platform/action-assurance-workflow")
@app.route("/platform/action-assurance")
@app.route("/platform/action-governance")
@app.route("/action-assurance-workflow")
def cobitchain_platform_action_assurance_workflow():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_action_assurance_workflow.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_action_assurance_workflow():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_action_assurance_workflow_seed.json")
    if not path.exists():
        return {"workflow": [], "module_adoption_map": [], "sample_action": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"workflow": [], "module_adoption_map": [], "sample_action": {}}


def _cobitchain_action_assurance_band(score):
    score = int(score or 0)
    if score >= 85:
        return "STRONG"
    if score >= 75:
        return "GOOD_WITH_CONTROL_GAPS"
    if score >= 65:
        return "CAUTION"
    return "LIMITED"


def _cobitchain_enrich_action_assurance_stage(stage):
    import uuid
    from datetime import datetime, timezone

    data = dict(stage or {})
    score = int(data.get("readiness_score", 0) or 0)
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_band"] = _cobitchain_action_assurance_band(score)
    data["platform_rule"] = "Use Action Assurance Workflow across Platform A modules rather than creating separate governance products for Agentic AI."
    data["engineering_principle"] = "A chatbot produces information. An AI agent performs actions. Platform A should govern operational actions, not only AI outputs."
    return data


def _cobitchain_enrich_action_assurance_check(action):
    import uuid
    from datetime import datetime, timezone

    data = dict(action or {})
    score = int(data.get("trust_score", 0) or 0)

    if score < 60:
        readiness_state = "BLOCKED"
    elif score < 75:
        readiness_state = "HOLD_OR_CAUTION"
    elif data.get("state_verification_required"):
        readiness_state = "READY_WITH_VERIFICATION_REQUIRED"
    else:
        readiness_state = "READY"

    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_state"] = readiness_state
    data["platform_rule"] = "Cloud platforms execute AI agents. COBIT-Chain evaluates whether AI-assisted actions are operationally trustworthy before they affect regulated systems."
    data["engineering_principle"] = "A chatbot produces information. An AI agent performs actions. Platform A should govern operational actions, not only AI outputs."
    return data


@app.route("/api/platform/action-assurance/workflow/demo", methods=["GET"])
def cobitchain_platform_action_assurance_workflow_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    workflow = _cobitchain_load_action_assurance_workflow()
    stages = [_cobitchain_enrich_action_assurance_stage(item) for item in workflow.get("workflow", [])]
    sample_action = _cobitchain_enrich_action_assurance_check(workflow.get("sample_action", {}))

    scores = [int(item.get("readiness_score", 0) or 0) for item in stages]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain Action Assurance Workflow Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": workflow.get("capability_name"),
        "platform_rule": workflow.get("platform_rule"),
        "engineering_principle": workflow.get("engineering_principle"),
        "platform_position": workflow.get("platform_position"),
        "workflow_stage_count": len(stages),
        "average_stage_readiness": average,
        "workflow": stages,
        "module_adoption_map": workflow.get("module_adoption_map", []),
        "sample_action": sample_action
    })


@app.route("/api/platform/action-assurance/stage/demo", methods=["GET"])
def cobitchain_platform_action_assurance_stage_demo_api():
    from flask import jsonify, request

    stage_id = request.args.get("stage_id", "authority")
    workflow = _cobitchain_load_action_assurance_workflow()
    stages = workflow.get("workflow", []) or []

    for item in stages:
        if item.get("stage_id") == stage_id:
            return jsonify(_cobitchain_enrich_action_assurance_stage(item))

    return jsonify({
        "error": "stage_not_found",
        "message": f"No Action Assurance Workflow stage found for stage_id={stage_id}",
        "available_stage_ids": [item.get("stage_id") for item in stages]
    }), 404


@app.route("/api/platform/action-assurance/check/demo", methods=["GET"])
def cobitchain_platform_action_assurance_check_demo_api():
    from flask import jsonify

    workflow = _cobitchain_load_action_assurance_workflow()
    return jsonify(_cobitchain_enrich_action_assurance_check(workflow.get("sample_action", {})))


@app.route("/api/platform/action-assurance/readiness/demo", methods=["GET"])
def cobitchain_platform_action_assurance_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    workflow = _cobitchain_load_action_assurance_workflow()
    stages = [_cobitchain_enrich_action_assurance_stage(item) for item in workflow.get("workflow", [])]
    sample_action = _cobitchain_enrich_action_assurance_check(workflow.get("sample_action", {}))

    scores = [int(item.get("readiness_score", 0) or 0) for item in stages]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    weakest = sorted(
        [
            {
                "stage_id": item.get("stage_id"),
                "stage_name": item.get("stage_name"),
                "readiness_score": item.get("readiness_score"),
                "gate_decision": item.get("gate_decision")
            }
            for item in stages
        ],
        key=lambda x: int(x.get("readiness_score", 0) or 0)
    )[:4]

    required_actions = [
        "Use Action Assurance Workflow as the reusable action gate across Platform A modules.",
        "Bind Agent Passport to authority and execution gates.",
        "Bind Tool Call Evidence Ledger to execution and evidence recording gates.",
        "Bind Evidence Vault to action replay and inspection readiness.",
        "Bind Operational Trust to context, state verification, and continuous assurance.",
        "Require human approval for regulated, privileged, irreversible, or high-risk actions."
    ]

    return jsonify({
        "service": "COBIT-Chain Action Assurance Workflow Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "average_stage_readiness": average,
        "weakest_stages": weakest,
        "sample_action": sample_action,
        "required_actions": required_actions,
        "engineering_principle": "A chatbot produces information. An AI agent performs actions. Platform A should govern operational actions, not only AI outputs."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_ACTION_ASSURANCE_WORKFLOW_V1_ACTIVE
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

Path("platform_action_assurance_workflow_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/action-assurance-workflow",
        "http://127.0.0.1:5000/platform/action-assurance",
        "http://127.0.0.1:5000/platform/action-governance",
        "http://127.0.0.1:5000/api/platform/action-assurance/workflow/demo",
        "http://127.0.0.1:5000/api/platform/action-assurance/stage/demo?stage_id=authority",
        "http://127.0.0.1:5000/api/platform/action-assurance/check/demo",
        "http://127.0.0.1:5000/api/platform/action-assurance/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Action Assurance Workflow installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
