from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_LIFECYCLE_CHANGE_ASSURANCE_V1_ACTIVE"

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
    "/platform/ai-lifecycle-change-assurance",
    "/platform/ai-change-lifecycle-assurance",
    "/platform/pccp-assurance",
    "/platform/ai-changecontroltrust",
    "/ai-lifecycle-change-assurance",
    "/api/platform/ai-lifecycle-change/model/demo",
    "/api/platform/ai-lifecycle-change/dimension/demo",
    "/api/platform/ai-lifecycle-change/change/demo",
    "/api/platform/ai-lifecycle-change/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_LIFECYCLE_CHANGE_ASSURANCE_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-lifecycle-change-assurance")
@app.route("/platform/ai-change-lifecycle-assurance")
@app.route("/platform/pccp-assurance")
@app.route("/platform/ai-changecontroltrust")
@app.route("/ai-lifecycle-change-assurance")
def cobitchain_platform_ai_lifecycle_change_assurance():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_lifecycle_change_assurance.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_lifecycle_change_assurance():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_lifecycle_change_assurance_seed.json")
    if not path.exists():
        return {"assessment_dimensions": [], "change_decision_states": [], "sample_change": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"assessment_dimensions": [], "change_decision_states": [], "sample_change": {}}


def _cobitchain_ai_lifecycle_change_band(score):
    score = int(score or 0)
    if score >= 85:
        return "READY_WITHIN_APPROVED_BOUNDARY"
    if score >= 75:
        return "GOOD_WITH_EVIDENCE_GAPS"
    if score >= 65:
        return "CONDITIONAL_REVIEW_REQUIRED"
    return "BLOCK_OR_REVALIDATE"


def _cobitchain_enrich_ai_lifecycle_change_dimension(dimension):
    import uuid
    from datetime import datetime, timezone

    data = dict(dimension or {})
    score = int(data.get("readiness_score", 0) or 0)
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_band"] = _cobitchain_ai_lifecycle_change_band(score)
    data["platform_rule"] = "AI Lifecycle Change Assurance strengthens AI ChangeControlTrust rather than creating a separate governance framework."
    data["engineering_principle"] = "Every AI change is a governance event."
    return data


def _cobitchain_enrich_ai_lifecycle_change_record(change):
    import uuid
    from datetime import datetime, timezone

    data = dict(change or {})
    score = int(data.get("change_readiness_score", 0) or 0)

    if score < 65:
        readiness_state = "BLOCK_OR_REVALIDATE"
    elif score < 75:
        readiness_state = "CONDITIONAL_HOLD"
    elif data.get("human_review_state") != "COMPLETED":
        readiness_state = "READY_AFTER_HUMAN_REVIEW"
    else:
        readiness_state = "READY"

    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_state"] = readiness_state
    data["platform_rule"] = "Platform A determines whether a proposed AI modification remains within approved operational and regulatory boundaries or requires escalation, revalidation, or additional review."
    data["engineering_principle"] = "Every AI change is a governance event."
    return data


@app.route("/api/platform/ai-lifecycle-change/model/demo", methods=["GET"])
def cobitchain_platform_ai_lifecycle_change_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_lifecycle_change_assurance()
    dimensions = [_cobitchain_enrich_ai_lifecycle_change_dimension(item) for item in payload.get("assessment_dimensions", [])]
    change = _cobitchain_enrich_ai_lifecycle_change_record(payload.get("sample_change", {}))

    scores = [int(item.get("readiness_score", 0) or 0) for item in dimensions]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Lifecycle Change Assurance Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "implementation_example": payload.get("implementation_example"),
        "engineering_principle": payload.get("engineering_principle"),
        "strengthens_modules": payload.get("strengthens_modules", []),
        "dimension_count": len(dimensions),
        "average_dimension_readiness": average,
        "assessment_dimensions": dimensions,
        "change_decision_states": payload.get("change_decision_states", []),
        "sample_change": change
    })


@app.route("/api/platform/ai-lifecycle-change/dimension/demo", methods=["GET"])
def cobitchain_platform_ai_lifecycle_change_dimension_demo_api():
    from flask import jsonify, request

    dimension_id = request.args.get("dimension_id", "approved_change_boundaries")
    payload = _cobitchain_load_ai_lifecycle_change_assurance()
    dimensions = payload.get("assessment_dimensions", []) or []

    for item in dimensions:
        if item.get("dimension_id") == dimension_id:
            return jsonify(_cobitchain_enrich_ai_lifecycle_change_dimension(item))

    return jsonify({
        "error": "dimension_not_found",
        "message": f"No AI Lifecycle Change Assurance dimension found for dimension_id={dimension_id}",
        "available_dimension_ids": [item.get("dimension_id") for item in dimensions]
    }), 404


@app.route("/api/platform/ai-lifecycle-change/change/demo", methods=["GET"])
def cobitchain_platform_ai_lifecycle_change_record_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_lifecycle_change_assurance()
    return jsonify(_cobitchain_enrich_ai_lifecycle_change_record(payload.get("sample_change", {})))


@app.route("/api/platform/ai-lifecycle-change/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_lifecycle_change_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_lifecycle_change_assurance()
    dimensions = [_cobitchain_enrich_ai_lifecycle_change_dimension(item) for item in payload.get("assessment_dimensions", [])]
    change = _cobitchain_enrich_ai_lifecycle_change_record(payload.get("sample_change", {}))

    weakest = sorted(
        [
            {
                "dimension_id": item.get("dimension_id"),
                "dimension_name": item.get("dimension_name"),
                "readiness_score": item.get("readiness_score"),
                "gaps_to_watch": item.get("gaps_to_watch", [])
            }
            for item in dimensions
        ],
        key=lambda x: int(x.get("readiness_score", 0) or 0)
    )[:5]

    required_actions = [
        "Confirm whether the proposed AI change remains within approved change boundaries.",
        "Complete dataset representativeness and lineage review.",
        "Complete validation methodology and acceptance criteria.",
        "Require named human review and decision evidence.",
        "Define post-deployment monitoring thresholds and revalidation triggers.",
        "Complete rollback procedure and bind all evidence to Evidence Vault."
    ]

    return jsonify({
        "service": "COBIT-Chain AI Lifecycle Change Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_change": change,
        "weakest_dimensions": weakest,
        "required_actions": required_actions,
        "engineering_principle": "Every AI change is a governance event."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_LIFECYCLE_CHANGE_ASSURANCE_V1_ACTIVE
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

Path("platform_ai_lifecycle_change_assurance_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-lifecycle-change-assurance",
        "http://127.0.0.1:5000/platform/ai-change-lifecycle-assurance",
        "http://127.0.0.1:5000/platform/pccp-assurance",
        "http://127.0.0.1:5000/platform/ai-changecontroltrust",
        "http://127.0.0.1:5000/api/platform/ai-lifecycle-change/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-lifecycle-change/dimension/demo?dimension_id=approved_change_boundaries",
        "http://127.0.0.1:5000/api/platform/ai-lifecycle-change/change/demo",
        "http://127.0.0.1:5000/api/platform/ai-lifecycle-change/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Lifecycle Change Assurance installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
