from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ASSURANCE_NEW_WORKFLOW_INTAKE_ENGINE_V1_ACTIVE"

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
    "/platform/ai-assurance-new-workflow-intake",
    "/platform/ai-workflow-intake",
    "/platform/new-workflow-assurance-intake",
    "/ai-assurance-new-workflow-intake",
    "/api/platform/ai-workflow-intake/model/demo",
    "/api/platform/ai-workflow-intake/check/demo",
    "/api/platform/ai-workflow-intake/intake/demo",
    "/api/platform/ai-workflow-intake/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ASSURANCE_NEW_WORKFLOW_INTAKE_ENGINE_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-assurance-new-workflow-intake")
@app.route("/platform/ai-workflow-intake")
@app.route("/platform/new-workflow-assurance-intake")
@app.route("/ai-assurance-new-workflow-intake")
def cobitchain_platform_ai_assurance_new_workflow_intake():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_assurance_new_workflow_intake.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_assurance_new_workflow_intake():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_assurance_new_workflow_intake_seed.json")
    if not path.exists():
        return {"intake_checks": [], "sample_intake": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"intake_checks": [], "sample_intake": {}}


def _cobitchain_enrich_ai_workflow_intake_check(check):
    import uuid
    from datetime import datetime, timezone

    data = dict(check or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("sample_score", 0) or 0)
    blocks = bool(data.get("blocks_intake_completion", False))
    state = data.get("sample_state", "")

    if blocks and (score < 85 or state not in ["COMPLETE", "READY", "APPROVED", "PASS"]):
        data["computed_intake_check_state"] = "BLOCKING_INTAKE_CHECK_NOT_COMPLETE"
    elif score >= 85:
        data["computed_intake_check_state"] = "INTAKE_CHECK_READY"
    else:
        data["computed_intake_check_state"] = "INTAKE_CHECK_REVIEW_REQUIRED"

    data["platform_rule"] = "Every new AI-enabled workflow must enter governed assurance intake before architecture, evidence, control, approval, or release activity."
    data["engineering_principle"] = "A new AI workflow should not begin with tools, prompts, or deployment. It should begin with a governed intake record that defines context, autonomy, tools, data, evidence, owners, risk, reuse eligibility, and assurance path."
    return data


def _cobitchain_enrich_ai_workflow_intake(intake):
    import uuid
    from datetime import datetime, timezone

    data = dict(intake or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("intake_score", 0) or 0)
    approved_execution = bool(data.get("approved_for_assurance_execution", False))
    blockers = data.get("blocking_intake_checks", []) or []
    full_required = bool(data.get("full_architecture_assurance_required", False))

    if approved_execution and full_required:
        data["computed_intake_state"] = "ACCEPTED_INTO_FULL_ASSURANCE_PATH"
    elif approved_execution and score >= 85 and len(blockers) == 0:
        data["computed_intake_state"] = "INTAKE_COMPLETE_READY_FOR_ASSURANCE_EXECUTION"
    elif len(blockers) > 0:
        data["computed_intake_state"] = "INTAKE_ACCEPTED_WITH_BLOCKING_COMPLETION_GAPS"
    else:
        data["computed_intake_state"] = "INTAKE_NOT_READY"

    data["platform_rule"] = "New AI workflow intake determines the minimum assurance path before trust can be claimed."
    data["engineering_principle"] = "A new AI workflow should not begin with tools, prompts, or deployment. It should begin with a governed intake record that defines context, autonomy, tools, data, evidence, owners, risk, reuse eligibility, and assurance path."
    return data


@app.route("/api/platform/ai-workflow-intake/model/demo", methods=["GET"])
def cobitchain_platform_ai_workflow_intake_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_new_workflow_intake()
    checks = [_cobitchain_enrich_ai_workflow_intake_check(item) for item in payload.get("intake_checks", [])]
    intake = _cobitchain_enrich_ai_workflow_intake(payload.get("sample_intake", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in checks]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Assurance New Workflow Intake Engine Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "depends_on": payload.get("depends_on", []),
        "intake_check_count": len(checks),
        "average_check_score": average,
        "intake_checks": checks,
        "sample_intake": intake
    })


@app.route("/api/platform/ai-workflow-intake/check/demo", methods=["GET"])
def cobitchain_platform_ai_workflow_intake_check_demo_api():
    from flask import jsonify, request

    check_id = request.args.get("check_id", "context_of_use_check")
    payload = _cobitchain_load_ai_assurance_new_workflow_intake()
    checks = payload.get("intake_checks", []) or []

    for item in checks:
        if item.get("check_id") == check_id:
            return jsonify(_cobitchain_enrich_ai_workflow_intake_check(item))

    return jsonify({
        "error": "intake_check_not_found",
        "message": f"No AI Assurance New Workflow Intake check found for check_id={check_id}",
        "available_check_ids": [item.get("check_id") for item in checks]
    }), 404


@app.route("/api/platform/ai-workflow-intake/intake/demo", methods=["GET"])
def cobitchain_platform_ai_workflow_intake_intake_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_assurance_new_workflow_intake()
    return jsonify(_cobitchain_enrich_ai_workflow_intake(payload.get("sample_intake", {})))


@app.route("/api/platform/ai-workflow-intake/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_workflow_intake_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_new_workflow_intake()
    checks = [_cobitchain_enrich_ai_workflow_intake_check(item) for item in payload.get("intake_checks", [])]
    intake = _cobitchain_enrich_ai_workflow_intake(payload.get("sample_intake", {}))

    blocking = [
        {
            "check_id": item.get("check_id"),
            "check_name": item.get("check_name"),
            "sample_state": item.get("sample_state"),
            "sample_score": item.get("sample_score"),
            "source_module": item.get("source_module"),
            "required_evidence": item.get("required_evidence", [])
        }
        for item in checks
        if item.get("computed_intake_check_state") == "BLOCKING_INTAKE_CHECK_NOT_COMPLETE"
    ]

    return jsonify({
        "service": "COBIT-Chain AI Assurance New Workflow Intake Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_intake": intake,
        "blocking_intake_checks": blocking,
        "required_next_actions": intake.get("required_next_actions", []),
        "engineering_principle": "A new AI workflow should not begin with tools, prompts, or deployment. It should begin with a governed intake record that defines context, autonomy, tools, data, evidence, owners, risk, reuse eligibility, and assurance path."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ASSURANCE_NEW_WORKFLOW_INTAKE_ENGINE_V1_ACTIVE
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

Path("platform_ai_assurance_new_workflow_intake_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-assurance-new-workflow-intake",
        "http://127.0.0.1:5000/platform/ai-workflow-intake",
        "http://127.0.0.1:5000/platform/new-workflow-assurance-intake",
        "http://127.0.0.1:5000/api/platform/ai-workflow-intake/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-workflow-intake/check/demo?check_id=context_of_use_check",
        "http://127.0.0.1:5000/api/platform/ai-workflow-intake/check/demo?check_id=autonomy_level_check",
        "http://127.0.0.1:5000/api/platform/ai-workflow-intake/intake/demo",
        "http://127.0.0.1:5000/api/platform/ai-workflow-intake/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Assurance New Workflow Intake Engine installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
