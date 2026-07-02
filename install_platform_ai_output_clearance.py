from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_OUTPUT_CLEARANCE_CONSOLE_V1_ACTIVE"

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
    "/platform/ai-output-clearance",
    "/platform/output-clearance",
    "/platform/ai-output-release-clearance",
    "/ai-output-clearance",
    "/api/platform/ai-output-clearance/model/demo",
    "/api/platform/ai-output-clearance/domain/demo",
    "/api/platform/ai-output-clearance/assessment/demo",
    "/api/platform/ai-output-clearance/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_OUTPUT_CLEARANCE_CONSOLE_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-output-clearance")
@app.route("/platform/output-clearance")
@app.route("/platform/ai-output-release-clearance")
@app.route("/ai-output-clearance")
def cobitchain_platform_ai_output_clearance():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_output_clearance.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_output_clearance():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_output_clearance_seed.json")
    if not path.exists():
        return {"clearance_domains": [], "sample_assessment": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"clearance_domains": [], "sample_assessment": {}}


def _cobitchain_enrich_output_clearance_domain(domain):
    import uuid
    from datetime import datetime, timezone

    data = dict(domain or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("sample_score", 0) or 0)
    blocks = bool(data.get("blocks_output_clearance", False))
    state = data.get("sample_state", "")

    ready_states = ["READY", "COMPLETE", "CLEARED", "APPROVED", "PASS"]
    if blocks and (score < 85 or state not in ready_states):
        data["computed_clearance_domain_state"] = "BLOCKING_OUTPUT_CLEARANCE_GAP"
    elif score >= 85:
        data["computed_clearance_domain_state"] = "OUTPUT_CLEARANCE_DOMAIN_READY"
    elif score >= 75:
        data["computed_clearance_domain_state"] = "OUTPUT_CLEARANCE_REVIEW_REQUIRED"
    else:
        data["computed_clearance_domain_state"] = "OUTPUT_CLEARANCE_NOT_READY"

    data["platform_rule"] = "AI outputs must be cleared before they enter operational, regulated, quality, clinical, business, or decision-support workflows."
    data["engineering_principle"] = "An AI output is not operationally trusted because it was generated. It becomes trusted only when context, lineage, risk, evidence, human approval, and clearance conditions are satisfied."
    return data


def _cobitchain_enrich_output_clearance_assessment(assessment):
    import uuid
    from datetime import datetime, timezone

    data = dict(assessment or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("output_clearance_score", 0) or 0)
    workflow_clear = bool(data.get("cleared_for_workflow_use", False))
    decision_clear = bool(data.get("cleared_for_decision_support", False))
    release_clear = bool(data.get("cleared_for_release_decision", False))
    blockers = data.get("blocking_domains", []) or []
    review_required = bool(data.get("human_review_required", False))
    revalidation_required = bool(data.get("revalidation_required", False))

    if workflow_clear and decision_clear and release_clear and score >= 85 and len(blockers) == 0:
        data["computed_output_clearance_state"] = "OUTPUT_CLEARED_FOR_CONTROLLED_WORKFLOW_USE"
    elif review_required or revalidation_required or len(blockers) > 0:
        data["computed_output_clearance_state"] = "OUTPUT_CLEARANCE_BLOCKED_REVIEW_OR_REVALIDATION_REQUIRED"
    elif score >= 75:
        data["computed_output_clearance_state"] = "OUTPUT_CLEARANCE_REVIEW_REQUIRED"
    else:
        data["computed_output_clearance_state"] = "OUTPUT_CLEARANCE_NOT_READY"

    data["platform_rule"] = "No AI output enters a consequential workflow without clearance evidence, lineage, risk alignment, and accountability."
    data["engineering_principle"] = "An AI output is not operationally trusted because it was generated. It becomes trusted only when context, lineage, risk, evidence, human approval, and clearance conditions are satisfied."
    return data


@app.route("/api/platform/ai-output-clearance/model/demo", methods=["GET"])
def cobitchain_platform_ai_output_clearance_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_output_clearance()
    domains = [_cobitchain_enrich_output_clearance_domain(item) for item in payload.get("clearance_domains", [])]
    assessment = _cobitchain_enrich_output_clearance_assessment(payload.get("sample_assessment", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in domains]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Output Clearance Console Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "assurance_question": payload.get("assurance_question"),
        "depends_on": payload.get("depends_on", []),
        "clearance_domain_count": len(domains),
        "average_domain_score": average,
        "clearance_domains": domains,
        "sample_assessment": assessment
    })


@app.route("/api/platform/ai-output-clearance/domain/demo", methods=["GET"])
def cobitchain_platform_ai_output_clearance_domain_demo_api():
    from flask import jsonify, request

    domain_id = request.args.get("domain_id", "prompt_model_lineage")
    payload = _cobitchain_load_ai_output_clearance()
    domains = payload.get("clearance_domains", []) or []

    for item in domains:
        if item.get("domain_id") == domain_id:
            return jsonify(_cobitchain_enrich_output_clearance_domain(item))

    return jsonify({
        "error": "output_clearance_domain_not_found",
        "message": f"No AI Output Clearance domain found for domain_id={domain_id}",
        "available_domain_ids": [item.get("domain_id") for item in domains]
    }), 404


@app.route("/api/platform/ai-output-clearance/assessment/demo", methods=["GET"])
def cobitchain_platform_ai_output_clearance_assessment_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_output_clearance()
    return jsonify(_cobitchain_enrich_output_clearance_assessment(payload.get("sample_assessment", {})))


@app.route("/api/platform/ai-output-clearance/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_output_clearance_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_output_clearance()
    domains = [_cobitchain_enrich_output_clearance_domain(item) for item in payload.get("clearance_domains", [])]
    assessment = _cobitchain_enrich_output_clearance_assessment(payload.get("sample_assessment", {}))

    blocking = [
        {
            "domain_id": item.get("domain_id"),
            "domain_name": item.get("domain_name"),
            "sample_state": item.get("sample_state"),
            "sample_score": item.get("sample_score"),
            "computed_clearance_domain_state": item.get("computed_clearance_domain_state"),
            "required_evidence": item.get("required_evidence", []),
            "required_actions": item.get("required_actions", [])
        }
        for item in domains
        if item.get("computed_clearance_domain_state") == "BLOCKING_OUTPUT_CLEARANCE_GAP"
    ]

    return jsonify({
        "service": "COBIT-Chain AI Output Clearance Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_assessment": assessment,
        "blocking_clearance_domains": blocking,
        "required_next_actions": assessment.get("required_next_actions", []),
        "evidence_to_bind": assessment.get("evidence_to_bind", []),
        "engineering_principle": "An AI output is not operationally trusted because it was generated. It becomes trusted only when context, lineage, risk, evidence, human approval, and clearance conditions are satisfied."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_OUTPUT_CLEARANCE_CONSOLE_V1_ACTIVE
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

Path("platform_ai_output_clearance_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-output-clearance",
        "http://127.0.0.1:5000/platform/output-clearance",
        "http://127.0.0.1:5000/platform/ai-output-release-clearance",
        "http://127.0.0.1:5000/api/platform/ai-output-clearance/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-output-clearance/domain/demo?domain_id=prompt_model_lineage",
        "http://127.0.0.1:5000/api/platform/ai-output-clearance/domain/demo?domain_id=evidence_completeness",
        "http://127.0.0.1:5000/api/platform/ai-output-clearance/assessment/demo",
        "http://127.0.0.1:5000/api/platform/ai-output-clearance/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Output Clearance Console installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
