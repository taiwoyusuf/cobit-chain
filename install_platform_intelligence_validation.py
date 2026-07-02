from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_INTELLIGENCE_VALIDATION_CONSOLE_V1_ACTIVE"

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
    "/platform/intelligence-validation",
    "/platform/ai-intelligence-validation",
    "/platform/ai-lifecycle-intelligence-validation",
    "/intelligence-validation",
    "/api/platform/intelligence-validation/model/demo",
    "/api/platform/intelligence-validation/domain/demo",
    "/api/platform/intelligence-validation/assessment/demo",
    "/api/platform/intelligence-validation/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_INTELLIGENCE_VALIDATION_CONSOLE_V1_ACTIVE
# ============================================================

@app.route("/platform/intelligence-validation")
@app.route("/platform/ai-intelligence-validation")
@app.route("/platform/ai-lifecycle-intelligence-validation")
@app.route("/intelligence-validation")
def cobitchain_platform_intelligence_validation():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_intelligence_validation.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_intelligence_validation():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_intelligence_validation_seed.json")
    if not path.exists():
        return {"validation_domains": [], "sample_assessment": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"validation_domains": [], "sample_assessment": {}}


def _cobitchain_enrich_intelligence_validation_domain(domain):
    import uuid
    from datetime import datetime, timezone

    data = dict(domain or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("sample_score", 0) or 0)
    blocks = bool(data.get("blocks_validation_readiness", False))
    state = data.get("sample_state", "")

    ready_states = ["READY", "COMPLETE", "VALIDATED", "APPROVED", "MONITORED"]
    if blocks and (score < 85 or state not in ready_states):
        data["computed_validation_domain_state"] = "BLOCKING_INTELLIGENCE_VALIDATION_GAP"
    elif score >= 85:
        data["computed_validation_domain_state"] = "INTELLIGENCE_VALIDATION_DOMAIN_READY"
    elif score >= 75:
        data["computed_validation_domain_state"] = "INTELLIGENCE_VALIDATION_REVIEW_REQUIRED"
    else:
        data["computed_validation_domain_state"] = "INTELLIGENCE_VALIDATION_NOT_READY"

    data["platform_rule"] = "AI-enabled systems must remain operationally fit for intended use through continuous validation of behavior, traceability, evidence, drift, human approval, and lifecycle change triggers."
    data["engineering_principle"] = "Operational trust depends upon continuous validation of intelligence rather than one-time validation of software."
    return data


def _cobitchain_enrich_intelligence_validation_assessment(assessment):
    import uuid
    from datetime import datetime, timezone

    data = dict(assessment or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("intelligence_validation_score", 0) or 0)
    fit = bool(data.get("operationally_fit_for_intended_use", False))
    output_clearance = bool(data.get("approved_for_output_clearance", False))
    op_ready = bool(data.get("approved_for_operational_readiness", False))
    blockers = data.get("blocking_domains", []) or []
    revalidation_required = bool(data.get("revalidation_required", False))

    if fit and output_clearance and op_ready and score >= 85 and len(blockers) == 0:
        data["computed_intelligence_validation_state"] = "INTELLIGENCE_VALIDATED_FOR_OPERATIONAL_TRUST"
    elif revalidation_required or len(blockers) > 0:
        data["computed_intelligence_validation_state"] = "INTELLIGENCE_VALIDATION_BLOCKED_REVALIDATION_REQUIRED"
    elif score >= 75:
        data["computed_intelligence_validation_state"] = "INTELLIGENCE_VALIDATION_REVIEW_REQUIRED"
    else:
        data["computed_intelligence_validation_state"] = "INTELLIGENCE_VALIDATION_NOT_READY"

    data["platform_rule"] = "Operational AI trust requires continuous validation of intended use, behavior, lineage, approval, drift, monitoring, and evidence."
    data["engineering_principle"] = "Operational trust depends upon continuous validation of intelligence rather than one-time validation of software."
    return data


@app.route("/api/platform/intelligence-validation/model/demo", methods=["GET"])
def cobitchain_platform_intelligence_validation_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_intelligence_validation()
    domains = [_cobitchain_enrich_intelligence_validation_domain(item) for item in payload.get("validation_domains", [])]
    assessment = _cobitchain_enrich_intelligence_validation_assessment(payload.get("sample_assessment", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in domains]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain Intelligence Validation Console Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "assurance_question": payload.get("assurance_question"),
        "depends_on": payload.get("depends_on", []),
        "validation_domain_count": len(domains),
        "average_domain_score": average,
        "validation_domains": domains,
        "sample_assessment": assessment
    })


@app.route("/api/platform/intelligence-validation/domain/demo", methods=["GET"])
def cobitchain_platform_intelligence_validation_domain_demo_api():
    from flask import jsonify, request

    domain_id = request.args.get("domain_id", "prompt_traceability")
    payload = _cobitchain_load_intelligence_validation()
    domains = payload.get("validation_domains", []) or []

    for item in domains:
        if item.get("domain_id") == domain_id:
            return jsonify(_cobitchain_enrich_intelligence_validation_domain(item))

    return jsonify({
        "error": "intelligence_validation_domain_not_found",
        "message": f"No Intelligence Validation domain found for domain_id={domain_id}",
        "available_domain_ids": [item.get("domain_id") for item in domains]
    }), 404


@app.route("/api/platform/intelligence-validation/assessment/demo", methods=["GET"])
def cobitchain_platform_intelligence_validation_assessment_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_intelligence_validation()
    return jsonify(_cobitchain_enrich_intelligence_validation_assessment(payload.get("sample_assessment", {})))


@app.route("/api/platform/intelligence-validation/readiness/demo", methods=["GET"])
def cobitchain_platform_intelligence_validation_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_intelligence_validation()
    domains = [_cobitchain_enrich_intelligence_validation_domain(item) for item in payload.get("validation_domains", [])]
    assessment = _cobitchain_enrich_intelligence_validation_assessment(payload.get("sample_assessment", {}))

    blocking = [
        {
            "domain_id": item.get("domain_id"),
            "domain_name": item.get("domain_name"),
            "sample_state": item.get("sample_state"),
            "sample_score": item.get("sample_score"),
            "computed_validation_domain_state": item.get("computed_validation_domain_state"),
            "required_evidence": item.get("required_evidence", []),
            "required_actions": item.get("required_actions", [])
        }
        for item in domains
        if item.get("computed_validation_domain_state") == "BLOCKING_INTELLIGENCE_VALIDATION_GAP"
    ]

    return jsonify({
        "service": "COBIT-Chain Intelligence Validation Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_assessment": assessment,
        "blocking_validation_domains": blocking,
        "required_next_actions": assessment.get("required_next_actions", []),
        "evidence_to_bind": assessment.get("evidence_to_bind", []),
        "engineering_principle": "Operational trust depends upon continuous validation of intelligence rather than one-time validation of software."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_INTELLIGENCE_VALIDATION_CONSOLE_V1_ACTIVE
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

Path("platform_intelligence_validation_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/intelligence-validation",
        "http://127.0.0.1:5000/platform/ai-intelligence-validation",
        "http://127.0.0.1:5000/platform/ai-lifecycle-intelligence-validation",
        "http://127.0.0.1:5000/api/platform/intelligence-validation/model/demo",
        "http://127.0.0.1:5000/api/platform/intelligence-validation/domain/demo?domain_id=prompt_traceability",
        "http://127.0.0.1:5000/api/platform/intelligence-validation/domain/demo?domain_id=revalidation_triggers",
        "http://127.0.0.1:5000/api/platform/intelligence-validation/assessment/demo",
        "http://127.0.0.1:5000/api/platform/intelligence-validation/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Intelligence Validation Console installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
