from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ASSURANCE_REUSE_APPLICABILITY_ENGINE_V1_ACTIVE"

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
    "/platform/ai-assurance-reuse-applicability",
    "/platform/ai-reuse-applicability-engine",
    "/platform/assurance-pattern-applicability",
    "/ai-assurance-reuse-applicability",
    "/api/platform/ai-reuse-applicability/model/demo",
    "/api/platform/ai-reuse-applicability/check/demo",
    "/api/platform/ai-reuse-applicability/assessment/demo",
    "/api/platform/ai-reuse-applicability/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ASSURANCE_REUSE_APPLICABILITY_ENGINE_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-assurance-reuse-applicability")
@app.route("/platform/ai-reuse-applicability-engine")
@app.route("/platform/assurance-pattern-applicability")
@app.route("/ai-assurance-reuse-applicability")
def cobitchain_platform_ai_assurance_reuse_applicability():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_assurance_reuse_applicability.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_assurance_reuse_applicability():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_assurance_reuse_applicability_seed.json")
    if not path.exists():
        return {"applicability_checks": [], "sample_assessment": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"applicability_checks": [], "sample_assessment": {}}


def _cobitchain_enrich_ai_reuse_check(check):
    import uuid
    from datetime import datetime, timezone

    data = dict(check or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("sample_score", 0) or 0)
    blocks = bool(data.get("blocks_reuse", False))
    state = data.get("sample_state", "")

    if blocks and (score < 85 or state not in ["MATCH", "APPROVED", "PASS", "COMPLETE"]):
        data["computed_applicability_state"] = "BLOCKING_REUSE_CHECK_NOT_SATISFIED"
    elif score >= 85:
        data["computed_applicability_state"] = "REUSE_CHECK_SATISFIED"
    else:
        data["computed_applicability_state"] = "REUSE_CHECK_REVIEW_REQUIRED"

    data["platform_rule"] = "Reusable AI assurance knowledge may be applied only when context, boundary, evidence, autonomy, tool, regulatory, owner, and lifecycle conditions match."
    data["engineering_principle"] = "Reuse is not copy-paste. Reuse is a governed applicability decision that determines whether prior operational learning safely applies to a new AI workflow."
    return data


def _cobitchain_enrich_ai_reuse_assessment(assessment):
    import uuid
    from datetime import datetime, timezone

    data = dict(assessment or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("reuse_applicability_score", 0) or 0)
    approved = bool(data.get("approved_for_reuse", False))
    full_assessment = bool(data.get("full_assessment_required", False))
    blockers = data.get("blocking_checks", []) or []

    if approved and score >= 85 and len(blockers) == 0:
        data["computed_reuse_decision_state"] = "APPROVED_FOR_GOVERNED_REUSE"
    elif full_assessment or len(blockers) > 0:
        data["computed_reuse_decision_state"] = "REUSE_BLOCKED_FULL_ASSURANCE_REQUIRED"
    elif score >= 75:
        data["computed_reuse_decision_state"] = "REUSE_REVIEW_REQUIRED"
    else:
        data["computed_reuse_decision_state"] = "REUSE_NOT_READY"

    data["platform_rule"] = "Prior learning may advise future assurance, but governed reuse requires evidence, boundary match, owner approval, and lifecycle control."
    data["engineering_principle"] = "Reuse is not copy-paste. Reuse is a governed applicability decision that determines whether prior operational learning safely applies to a new AI workflow."
    return data


@app.route("/api/platform/ai-reuse-applicability/model/demo", methods=["GET"])
def cobitchain_platform_ai_reuse_applicability_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_reuse_applicability()
    checks = [_cobitchain_enrich_ai_reuse_check(item) for item in payload.get("applicability_checks", [])]
    assessment = _cobitchain_enrich_ai_reuse_assessment(payload.get("sample_assessment", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in checks]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Assurance Reuse Applicability Engine Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "depends_on": payload.get("depends_on", []),
        "applicability_check_count": len(checks),
        "average_check_score": average,
        "applicability_checks": checks,
        "sample_assessment": assessment
    })


@app.route("/api/platform/ai-reuse-applicability/check/demo", methods=["GET"])
def cobitchain_platform_ai_reuse_applicability_check_demo_api():
    from flask import jsonify, request

    check_id = request.args.get("check_id", "context_of_use_match")
    payload = _cobitchain_load_ai_assurance_reuse_applicability()
    checks = payload.get("applicability_checks", []) or []

    for item in checks:
        if item.get("check_id") == check_id:
            return jsonify(_cobitchain_enrich_ai_reuse_check(item))

    return jsonify({
        "error": "applicability_check_not_found",
        "message": f"No AI Assurance Reuse Applicability check found for check_id={check_id}",
        "available_check_ids": [item.get("check_id") for item in checks]
    }), 404


@app.route("/api/platform/ai-reuse-applicability/assessment/demo", methods=["GET"])
def cobitchain_platform_ai_reuse_applicability_assessment_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_assurance_reuse_applicability()
    return jsonify(_cobitchain_enrich_ai_reuse_assessment(payload.get("sample_assessment", {})))


@app.route("/api/platform/ai-reuse-applicability/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_reuse_applicability_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_reuse_applicability()
    checks = [_cobitchain_enrich_ai_reuse_check(item) for item in payload.get("applicability_checks", [])]
    assessment = _cobitchain_enrich_ai_reuse_assessment(payload.get("sample_assessment", {}))

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
        if item.get("computed_applicability_state") == "BLOCKING_REUSE_CHECK_NOT_SATISFIED"
    ]

    return jsonify({
        "service": "COBIT-Chain AI Assurance Reuse Applicability Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_assessment": assessment,
        "blocking_reuse_checks": blocking,
        "required_next_actions": assessment.get("required_next_actions", []),
        "engineering_principle": "Reuse is not copy-paste. Reuse is a governed applicability decision that determines whether prior operational learning safely applies to a new AI workflow."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ASSURANCE_REUSE_APPLICABILITY_ENGINE_V1_ACTIVE
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

Path("platform_ai_assurance_reuse_applicability_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-assurance-reuse-applicability",
        "http://127.0.0.1:5000/platform/ai-reuse-applicability-engine",
        "http://127.0.0.1:5000/platform/assurance-pattern-applicability",
        "http://127.0.0.1:5000/api/platform/ai-reuse-applicability/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-reuse-applicability/check/demo?check_id=context_of_use_match",
        "http://127.0.0.1:5000/api/platform/ai-reuse-applicability/check/demo?check_id=tool_permission_match",
        "http://127.0.0.1:5000/api/platform/ai-reuse-applicability/assessment/demo",
        "http://127.0.0.1:5000/api/platform/ai-reuse-applicability/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Assurance Reuse Applicability Engine installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
