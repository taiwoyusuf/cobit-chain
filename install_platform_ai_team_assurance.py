from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_TEAM_ASSURANCE_CONSOLE_V1_ACTIVE"

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
    "/platform/ai-team-assurance",
    "/platform/team-assurance",
    "/platform/ai-operational-team-assurance",
    "/ai-team-assurance",
    "/api/platform/ai-team-assurance/model/demo",
    "/api/platform/ai-team-assurance/domain/demo",
    "/api/platform/ai-team-assurance/assessment/demo",
    "/api/platform/ai-team-assurance/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_TEAM_ASSURANCE_CONSOLE_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-team-assurance")
@app.route("/platform/team-assurance")
@app.route("/platform/ai-operational-team-assurance")
@app.route("/ai-team-assurance")
def cobitchain_platform_ai_team_assurance():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_team_assurance.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_team_assurance():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_team_assurance_seed.json")
    if not path.exists():
        return {"team_assurance_domains": [], "sample_assessment": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"team_assurance_domains": [], "sample_assessment": {}}


def _cobitchain_enrich_ai_team_domain(domain):
    import uuid
    from datetime import datetime, timezone

    data = dict(domain or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("sample_score", 0) or 0)
    blocks = bool(data.get("blocks_team_readiness", False))
    state = data.get("sample_state", "")

    ready_states = ["READY", "COMPLETE", "DEFINED", "APPROVED", "MATURE"]
    if blocks and (score < 85 or state not in ready_states):
        data["computed_team_domain_state"] = "BLOCKING_TEAM_ACCOUNTABILITY_GAP"
    elif score >= 85:
        data["computed_team_domain_state"] = "TEAM_DOMAIN_READY"
    elif score >= 75:
        data["computed_team_domain_state"] = "TEAM_DOMAIN_REVIEW_REQUIRED"
    else:
        data["computed_team_domain_state"] = "TEAM_DOMAIN_NOT_READY"

    data["platform_rule"] = "Enterprise AI trust requires defined ownership, decision rights, accountability, evidence ownership, approvals, escalation, and collaboration maturity."
    data["engineering_principle"] = "Enterprise AI scales through coordinated governance rather than isolated technical expertise."
    return data


def _cobitchain_enrich_ai_team_assessment(assessment):
    import uuid
    from datetime import datetime, timezone

    data = dict(assessment or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("team_assurance_score", 0) or 0)
    op_ready = bool(data.get("approved_for_operational_readiness", False))
    release_ready = bool(data.get("approved_for_release_decision", False))
    blockers = data.get("blocking_domains", []) or []

    if op_ready and release_ready and score >= 85 and len(blockers) == 0:
        data["computed_team_assurance_state"] = "TEAM_ASSURANCE_READY_FOR_OPERATIONAL_TRUST"
    elif len(blockers) > 0:
        data["computed_team_assurance_state"] = "TEAM_ASSURANCE_BLOCKED_BY_ACCOUNTABILITY_GAPS"
    elif score >= 75:
        data["computed_team_assurance_state"] = "TEAM_ASSURANCE_REVIEW_REQUIRED"
    else:
        data["computed_team_assurance_state"] = "TEAM_ASSURANCE_NOT_READY"

    data["platform_rule"] = "AI operational readiness must include team accountability, not only technical readiness."
    data["engineering_principle"] = "Enterprise AI scales through coordinated governance rather than isolated technical expertise."
    return data


@app.route("/api/platform/ai-team-assurance/model/demo", methods=["GET"])
def cobitchain_platform_ai_team_assurance_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_team_assurance()
    domains = [_cobitchain_enrich_ai_team_domain(item) for item in payload.get("team_assurance_domains", [])]
    assessment = _cobitchain_enrich_ai_team_assessment(payload.get("sample_assessment", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in domains]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Team Assurance Console Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "assurance_question": payload.get("assurance_question"),
        "depends_on": payload.get("depends_on", []),
        "team_assurance_domain_count": len(domains),
        "average_domain_score": average,
        "team_assurance_domains": domains,
        "sample_assessment": assessment
    })


@app.route("/api/platform/ai-team-assurance/domain/demo", methods=["GET"])
def cobitchain_platform_ai_team_assurance_domain_demo_api():
    from flask import jsonify, request

    domain_id = request.args.get("domain_id", "role_ownership")
    payload = _cobitchain_load_ai_team_assurance()
    domains = payload.get("team_assurance_domains", []) or []

    for item in domains:
        if item.get("domain_id") == domain_id:
            return jsonify(_cobitchain_enrich_ai_team_domain(item))

    return jsonify({
        "error": "team_assurance_domain_not_found",
        "message": f"No AI Team Assurance domain found for domain_id={domain_id}",
        "available_domain_ids": [item.get("domain_id") for item in domains]
    }), 404


@app.route("/api/platform/ai-team-assurance/assessment/demo", methods=["GET"])
def cobitchain_platform_ai_team_assurance_assessment_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_team_assurance()
    return jsonify(_cobitchain_enrich_ai_team_assessment(payload.get("sample_assessment", {})))


@app.route("/api/platform/ai-team-assurance/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_team_assurance_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_team_assurance()
    domains = [_cobitchain_enrich_ai_team_domain(item) for item in payload.get("team_assurance_domains", [])]
    assessment = _cobitchain_enrich_ai_team_assessment(payload.get("sample_assessment", {}))

    blocking = [
        {
            "domain_id": item.get("domain_id"),
            "domain_name": item.get("domain_name"),
            "sample_state": item.get("sample_state"),
            "sample_score": item.get("sample_score"),
            "computed_team_domain_state": item.get("computed_team_domain_state"),
            "required_evidence": item.get("required_evidence", []),
            "required_actions": item.get("required_actions", [])
        }
        for item in domains
        if item.get("computed_team_domain_state") == "BLOCKING_TEAM_ACCOUNTABILITY_GAP"
    ]

    return jsonify({
        "service": "COBIT-Chain AI Team Assurance Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_assessment": assessment,
        "blocking_team_domains": blocking,
        "required_next_actions": assessment.get("required_next_actions", []),
        "evidence_to_bind": assessment.get("evidence_to_bind", []),
        "engineering_principle": "Enterprise AI scales through coordinated governance rather than isolated technical expertise."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_TEAM_ASSURANCE_CONSOLE_V1_ACTIVE
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

Path("platform_ai_team_assurance_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-team-assurance",
        "http://127.0.0.1:5000/platform/team-assurance",
        "http://127.0.0.1:5000/platform/ai-operational-team-assurance",
        "http://127.0.0.1:5000/api/platform/ai-team-assurance/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-team-assurance/domain/demo?domain_id=role_ownership",
        "http://127.0.0.1:5000/api/platform/ai-team-assurance/domain/demo?domain_id=evidence_ownership",
        "http://127.0.0.1:5000/api/platform/ai-team-assurance/assessment/demo",
        "http://127.0.0.1:5000/api/platform/ai-team-assurance/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Team Assurance Console installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
