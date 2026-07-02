from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ACCOUNTABILITY_RACI_MATRIX_ENGINE_V1_ACTIVE"

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
    "/platform/ai-accountability-raci",
    "/platform/ai-raci-matrix",
    "/platform/ai-accountability-matrix",
    "/ai-accountability-raci",
    "/api/platform/ai-accountability-raci/model/demo",
    "/api/platform/ai-accountability-raci/stage/demo",
    "/api/platform/ai-accountability-raci/assessment/demo",
    "/api/platform/ai-accountability-raci/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ACCOUNTABILITY_RACI_MATRIX_ENGINE_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-accountability-raci")
@app.route("/platform/ai-raci-matrix")
@app.route("/platform/ai-accountability-matrix")
@app.route("/ai-accountability-raci")
def cobitchain_platform_ai_accountability_raci():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_accountability_raci.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_accountability_raci():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_accountability_raci_seed.json")
    if not path.exists():
        return {"lifecycle_raci_stages": [], "sample_assessment": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"lifecycle_raci_stages": [], "sample_assessment": {}}


def _cobitchain_enrich_ai_raci_stage(stage):
    import uuid
    from datetime import datetime, timezone

    data = dict(stage or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("sample_score", 0) or 0)
    blocks = bool(data.get("blocks_raci_readiness", False))
    state = data.get("sample_state", "")

    ready_states = ["READY", "COMPLETE", "DEFINED", "APPROVED", "MATURE"]
    if blocks and (score < 85 or state not in ready_states):
        data["computed_raci_stage_state"] = "BLOCKING_RACI_ACCOUNTABILITY_GAP"
    elif score >= 85:
        data["computed_raci_stage_state"] = "RACI_STAGE_READY"
    elif score >= 75:
        data["computed_raci_stage_state"] = "RACI_STAGE_REVIEW_REQUIRED"
    else:
        data["computed_raci_stage_state"] = "RACI_STAGE_NOT_READY"

    data["platform_rule"] = "Every AI assurance activity must have clear Responsible, Accountable, Consulted, and Informed roles before trust can be claimed."
    data["engineering_principle"] = "AI accountability becomes operational only when responsibility assignments are explicit across the lifecycle, tied to evidence, and enforceable at decision gates."
    return data


def _cobitchain_enrich_ai_raci_assessment(assessment):
    import uuid
    from datetime import datetime, timezone

    data = dict(assessment or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("raci_score", 0) or 0)
    release_ready = bool(data.get("approved_for_release_decision", False))
    op_ready = bool(data.get("approved_for_operational_readiness", False))
    blockers = data.get("blocking_stages", []) or []

    if op_ready and release_ready and score >= 85 and len(blockers) == 0:
        data["computed_raci_assessment_state"] = "RACI_READY_FOR_OPERATIONAL_TRUST_AND_RELEASE"
    elif len(blockers) > 0:
        data["computed_raci_assessment_state"] = "RACI_BLOCKED_BY_LIFECYCLE_ACCOUNTABILITY_GAPS"
    elif score >= 75:
        data["computed_raci_assessment_state"] = "RACI_REVIEW_REQUIRED"
    else:
        data["computed_raci_assessment_state"] = "RACI_NOT_READY"

    data["platform_rule"] = "Lifecycle accountability must be explicit, evidence-bound, and enforceable across AI assurance gates."
    data["engineering_principle"] = "AI accountability becomes operational only when responsibility assignments are explicit across the lifecycle, tied to evidence, and enforceable at decision gates."
    return data


@app.route("/api/platform/ai-accountability-raci/model/demo", methods=["GET"])
def cobitchain_platform_ai_accountability_raci_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_accountability_raci()
    stages = [_cobitchain_enrich_ai_raci_stage(item) for item in payload.get("lifecycle_raci_stages", [])]
    assessment = _cobitchain_enrich_ai_raci_assessment(payload.get("sample_assessment", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in stages]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Accountability RACI Matrix Engine Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "depends_on": payload.get("depends_on", []),
        "lifecycle_raci_stage_count": len(stages),
        "average_stage_score": average,
        "lifecycle_raci_stages": stages,
        "sample_assessment": assessment
    })


@app.route("/api/platform/ai-accountability-raci/stage/demo", methods=["GET"])
def cobitchain_platform_ai_accountability_raci_stage_demo_api():
    from flask import jsonify, request

    stage_id = request.args.get("stage_id", "evidence_contract_accountability")
    payload = _cobitchain_load_ai_accountability_raci()
    stages = payload.get("lifecycle_raci_stages", []) or []

    for item in stages:
        if item.get("stage_id") == stage_id:
            return jsonify(_cobitchain_enrich_ai_raci_stage(item))

    return jsonify({
        "error": "raci_stage_not_found",
        "message": f"No AI Accountability RACI stage found for stage_id={stage_id}",
        "available_stage_ids": [item.get("stage_id") for item in stages]
    }), 404


@app.route("/api/platform/ai-accountability-raci/assessment/demo", methods=["GET"])
def cobitchain_platform_ai_accountability_raci_assessment_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_accountability_raci()
    return jsonify(_cobitchain_enrich_ai_raci_assessment(payload.get("sample_assessment", {})))


@app.route("/api/platform/ai-accountability-raci/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_accountability_raci_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_accountability_raci()
    stages = [_cobitchain_enrich_ai_raci_stage(item) for item in payload.get("lifecycle_raci_stages", [])]
    assessment = _cobitchain_enrich_ai_raci_assessment(payload.get("sample_assessment", {}))

    blocking = [
        {
            "stage_id": item.get("stage_id"),
            "stage_name": item.get("stage_name"),
            "lifecycle_phase": item.get("lifecycle_phase"),
            "sample_state": item.get("sample_state"),
            "sample_score": item.get("sample_score"),
            "accountable": item.get("accountable"),
            "computed_raci_stage_state": item.get("computed_raci_stage_state"),
            "required_evidence": item.get("required_evidence", [])
        }
        for item in stages
        if item.get("computed_raci_stage_state") == "BLOCKING_RACI_ACCOUNTABILITY_GAP"
    ]

    return jsonify({
        "service": "COBIT-Chain AI Accountability RACI Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_assessment": assessment,
        "blocking_raci_stages": blocking,
        "required_next_actions": assessment.get("required_next_actions", []),
        "evidence_to_bind": assessment.get("evidence_to_bind", []),
        "engineering_principle": "AI accountability becomes operational only when responsibility assignments are explicit across the lifecycle, tied to evidence, and enforceable at decision gates."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ACCOUNTABILITY_RACI_MATRIX_ENGINE_V1_ACTIVE
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

Path("platform_ai_accountability_raci_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-accountability-raci",
        "http://127.0.0.1:5000/platform/ai-raci-matrix",
        "http://127.0.0.1:5000/platform/ai-accountability-matrix",
        "http://127.0.0.1:5000/api/platform/ai-accountability-raci/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-accountability-raci/stage/demo?stage_id=evidence_contract_accountability",
        "http://127.0.0.1:5000/api/platform/ai-accountability-raci/stage/demo?stage_id=decision_rights_accountability",
        "http://127.0.0.1:5000/api/platform/ai-accountability-raci/assessment/demo",
        "http://127.0.0.1:5000/api/platform/ai-accountability-raci/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Accountability RACI Matrix Engine installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
