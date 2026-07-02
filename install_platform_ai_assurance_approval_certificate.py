from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ASSURANCE_APPROVAL_CERTIFICATE_V1_ACTIVE"

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
    "/platform/ai-assurance-approval-certificate",
    "/platform/ai-approval-certificate",
    "/platform/operational-trust-certificate",
    "/ai-assurance-approval-certificate",
    "/api/platform/ai-assurance-certificate/model/demo",
    "/api/platform/ai-assurance-certificate/section/demo",
    "/api/platform/ai-assurance-certificate/certificate/demo",
    "/api/platform/ai-assurance-certificate/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ASSURANCE_APPROVAL_CERTIFICATE_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-assurance-approval-certificate")
@app.route("/platform/ai-approval-certificate")
@app.route("/platform/operational-trust-certificate")
@app.route("/ai-assurance-approval-certificate")
def cobitchain_platform_ai_assurance_approval_certificate():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_assurance_approval_certificate.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_assurance_approval_certificate():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_assurance_approval_certificate_seed.json")
    if not path.exists():
        return {"certificate_sections": [], "sample_certificate": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"certificate_sections": [], "sample_certificate": {}}


def _cobitchain_enrich_ai_assurance_certificate_section(section):
    import uuid
    from datetime import datetime, timezone

    data = dict(section or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("sample_score", 0) or 0)
    state = data.get("sample_state", "")

    if state in ["BLOCKED", "NOT_AUTHORIZED"] or score < 70:
        data["computed_section_state"] = "SECTION_BLOCKS_CERTIFICATE"
    elif score < 85:
        data["computed_section_state"] = "SECTION_REQUIRES_REVIEW"
    else:
        data["computed_section_state"] = "SECTION_READY"

    data["platform_rule"] = "No AI-enabled workflow should be operationally approved without a bounded evidence-backed approval certificate."
    data["engineering_principle"] = "Approval is not a verbal decision. Approval is a bounded, evidence-backed, time-limited operational trust state with named conditions, owners, monitoring obligations, and replayable proof."
    return data


def _cobitchain_enrich_ai_assurance_certificate(cert):
    import uuid
    from datetime import datetime, timezone

    data = dict(cert or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("certificate_score", 0) or 0)
    release = bool(data.get("release_authorized", False))
    status = data.get("certificate_status", "")

    if release and score >= 85 and status == "ISSUED":
        data["computed_certificate_state"] = "CERTIFICATE_ISSUED_OPERATIONAL_RELEASE_AUTHORIZED"
    elif status == "CONDITIONAL":
        data["computed_certificate_state"] = "CONDITIONAL_CERTIFICATE_REQUIRES_ACTIVE_MONITORING"
    elif status == "NOT_ISSUED":
        data["computed_certificate_state"] = "CERTIFICATE_NOT_ISSUED"
    else:
        data["computed_certificate_state"] = "CERTIFICATE_REVIEW_REQUIRED"

    data["platform_rule"] = "Final operational approval must be recorded as a certificate with scope, evidence basis, conditions, validity, and release authorization."
    data["engineering_principle"] = "Approval is not a verbal decision. Approval is a bounded, evidence-backed, time-limited operational trust state with named conditions, owners, monitoring obligations, and replayable proof."
    return data


@app.route("/api/platform/ai-assurance-certificate/model/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_certificate_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_approval_certificate()
    sections = [_cobitchain_enrich_ai_assurance_certificate_section(item) for item in payload.get("certificate_sections", [])]
    certificate = _cobitchain_enrich_ai_assurance_certificate(payload.get("sample_certificate", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in sections]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Assurance Approval Certificate Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "depends_on": payload.get("depends_on", []),
        "certificate_section_count": len(sections),
        "average_section_score": average,
        "certificate_sections": sections,
        "sample_certificate": certificate
    })


@app.route("/api/platform/ai-assurance-certificate/section/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_certificate_section_demo_api():
    from flask import jsonify, request

    section_id = request.args.get("section_id", "approval_decision")
    payload = _cobitchain_load_ai_assurance_approval_certificate()
    sections = payload.get("certificate_sections", []) or []

    for item in sections:
        if item.get("section_id") == section_id:
            return jsonify(_cobitchain_enrich_ai_assurance_certificate_section(item))

    return jsonify({
        "error": "certificate_section_not_found",
        "message": f"No AI Assurance Approval Certificate section found for section_id={section_id}",
        "available_section_ids": [item.get("section_id") for item in sections]
    }), 404


@app.route("/api/platform/ai-assurance-certificate/certificate/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_certificate_certificate_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_assurance_approval_certificate()
    return jsonify(_cobitchain_enrich_ai_assurance_certificate(payload.get("sample_certificate", {})))


@app.route("/api/platform/ai-assurance-certificate/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_certificate_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_approval_certificate()
    sections = [_cobitchain_enrich_ai_assurance_certificate_section(item) for item in payload.get("certificate_sections", [])]
    certificate = _cobitchain_enrich_ai_assurance_certificate(payload.get("sample_certificate", {}))

    blocking_sections = [
        {
            "section_id": item.get("section_id"),
            "section_name": item.get("section_name"),
            "sample_state": item.get("sample_state"),
            "sample_score": item.get("sample_score"),
            "computed_section_state": item.get("computed_section_state")
        }
        for item in sections
        if item.get("computed_section_state") == "SECTION_BLOCKS_CERTIFICATE"
    ]

    return jsonify({
        "service": "COBIT-Chain AI Assurance Approval Certificate Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_certificate": certificate,
        "blocking_certificate_sections": blocking_sections,
        "conditions_required_before_certificate": certificate.get("conditions_required_before_certificate", []),
        "engineering_principle": "Approval is not a verbal decision. Approval is a bounded, evidence-backed, time-limited operational trust state with named conditions, owners, monitoring obligations, and replayable proof."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ASSURANCE_APPROVAL_CERTIFICATE_V1_ACTIVE
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

Path("platform_ai_assurance_approval_certificate_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-assurance-approval-certificate",
        "http://127.0.0.1:5000/platform/ai-approval-certificate",
        "http://127.0.0.1:5000/platform/operational-trust-certificate",
        "http://127.0.0.1:5000/api/platform/ai-assurance-certificate/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-certificate/section/demo?section_id=approval_decision",
        "http://127.0.0.1:5000/api/platform/ai-assurance-certificate/section/demo?section_id=release_authorization",
        "http://127.0.0.1:5000/api/platform/ai-assurance-certificate/certificate/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-certificate/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Assurance Approval Certificate installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
