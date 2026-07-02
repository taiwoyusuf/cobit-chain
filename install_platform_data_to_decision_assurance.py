from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_DATA_TO_DECISION_ASSURANCE_V1_ACTIVE"

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
    "/platform/data-to-decision-assurance",
    "/platform/data-decision-assurance",
    "/platform/data-to-decision",
    "/data-to-decision-assurance",
    "/api/platform/data-to-decision/lifecycle/demo",
    "/api/platform/data-to-decision/stage/demo",
    "/api/platform/data-to-decision/check/demo",
    "/api/platform/data-to-decision/readiness/demo"
]

for route in all_routes:
    if f'@app.route("{route}")' in text or f"@app.route('{route}')" in text:
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_DATA_TO_DECISION_ASSURANCE_V1_ACTIVE
# ============================================================

@app.route("/platform/data-to-decision-assurance")
@app.route("/platform/data-decision-assurance")
@app.route("/platform/data-to-decision")
@app.route("/data-to-decision-assurance")
def cobitchain_platform_data_to_decision_assurance():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_data_to_decision_assurance.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_data_to_decision_assurance():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_data_to_decision_assurance_seed.json")
    if not path.exists():
        return {"lifecycle": [], "sample_decision": {}, "assurance_controls": []}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"lifecycle": [], "sample_decision": {}, "assurance_controls": []}


def _cobitchain_data_to_decision_band(score):
    score = int(score or 0)
    if score >= 85:
        return "STRONG"
    if score >= 75:
        return "GOOD_WITH_EVIDENCE_GAPS"
    if score >= 65:
        return "CAUTION"
    return "LIMITED"


def _cobitchain_enrich_data_to_decision_stage(stage):
    import uuid
    from datetime import datetime, timezone

    data = dict(stage or {})
    score = int(data.get("readiness_score", 0) or 0)
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_band"] = _cobitchain_data_to_decision_band(score)
    data["platform_rule"] = "Use Data-to-Decision Assurance to strengthen existing Platform A modules rather than creating multiple new data governance products."
    data["engineering_principle"] = "Trusted data -> Trusted context -> Trusted recommendation -> Trusted decision -> Trusted evidence."
    return data


def _cobitchain_enrich_data_to_decision_check(decision):
    import uuid
    from datetime import datetime, timezone

    data = dict(decision or {})
    score = int(data.get("decision_confidence_score", 0) or 0)

    if score < 60:
        readiness_state = "BLOCKED"
    elif score < 75:
        readiness_state = "HOLD_FOR_REVIEW"
    elif data.get("human_review_state") != "COMPLETED":
        readiness_state = "READY_AFTER_HUMAN_REVIEW"
    else:
        readiness_state = "READY"

    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_state"] = readiness_state
    data["platform_rule"] = "Azure provides enterprise data engineering capabilities. COBIT-Chain evaluates the lifecycle before AI-assisted decisions are made."
    data["engineering_principle"] = "Trusted data -> Trusted context -> Trusted recommendation -> Trusted decision -> Trusted evidence."
    return data


@app.route("/api/platform/data-to-decision/lifecycle/demo", methods=["GET"])
def cobitchain_platform_data_to_decision_lifecycle_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_data_to_decision_assurance()
    lifecycle = [_cobitchain_enrich_data_to_decision_stage(item) for item in payload.get("lifecycle", [])]
    sample_decision = _cobitchain_enrich_data_to_decision_check(payload.get("sample_decision", {}))

    scores = [int(item.get("readiness_score", 0) or 0) for item in lifecycle]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain Data-to-Decision Assurance Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "engineering_principle": payload.get("engineering_principle"),
        "positioning": payload.get("positioning"),
        "lifecycle_stage_count": len(lifecycle),
        "average_stage_readiness": average,
        "lifecycle": lifecycle,
        "sample_decision": sample_decision,
        "assurance_controls": payload.get("assurance_controls", [])
    })


@app.route("/api/platform/data-to-decision/stage/demo", methods=["GET"])
def cobitchain_platform_data_to_decision_stage_demo_api():
    from flask import jsonify, request

    stage_id = request.args.get("stage_id", "data_lineage")
    payload = _cobitchain_load_data_to_decision_assurance()
    stages = payload.get("lifecycle", []) or []

    for item in stages:
        if item.get("stage_id") == stage_id:
            return jsonify(_cobitchain_enrich_data_to_decision_stage(item))

    return jsonify({
        "error": "stage_not_found",
        "message": f"No Data-to-Decision lifecycle stage found for stage_id={stage_id}",
        "available_stage_ids": [item.get("stage_id") for item in stages]
    }), 404


@app.route("/api/platform/data-to-decision/check/demo", methods=["GET"])
def cobitchain_platform_data_to_decision_check_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_data_to_decision_assurance()
    return jsonify(_cobitchain_enrich_data_to_decision_check(payload.get("sample_decision", {})))


@app.route("/api/platform/data-to-decision/readiness/demo", methods=["GET"])
def cobitchain_platform_data_to_decision_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_data_to_decision_assurance()
    lifecycle = [_cobitchain_enrich_data_to_decision_stage(item) for item in payload.get("lifecycle", [])]
    sample_decision = _cobitchain_enrich_data_to_decision_check(payload.get("sample_decision", {}))

    scores = [int(item.get("readiness_score", 0) or 0) for item in lifecycle]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    weakest = sorted(
        [
            {
                "stage_id": item.get("stage_id"),
                "stage_name": item.get("stage_name"),
                "readiness_score": item.get("readiness_score"),
                "gaps_to_watch": item.get("gaps_to_watch", [])
            }
            for item in lifecycle
        ],
        key=lambda x: int(x.get("readiness_score", 0) or 0)
    )[:4]

    required_actions = [
        "Bind data source ownership and permitted-use rules to Evidence Vault.",
        "Create traceable ingestion, transformation, quality, and lineage evidence.",
        "Validate serving-layer freshness and AI context grounding before recommendations are used.",
        "Require human review before regulated or operationally significant decisions.",
        "Bind decision evidence to outcome metrics and continuous assurance."
    ]

    return jsonify({
        "service": "COBIT-Chain Data-to-Decision Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "average_stage_readiness": average,
        "weakest_stages": weakest,
        "sample_decision": sample_decision,
        "required_actions": required_actions,
        "engineering_principle": "Trusted data -> Trusted context -> Trusted recommendation -> Trusted decision -> Trusted evidence."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_DATA_TO_DECISION_ASSURANCE_V1_ACTIVE
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

Path("platform_data_to_decision_assurance_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/data-to-decision-assurance",
        "http://127.0.0.1:5000/platform/data-decision-assurance",
        "http://127.0.0.1:5000/platform/data-to-decision",
        "http://127.0.0.1:5000/api/platform/data-to-decision/lifecycle/demo",
        "http://127.0.0.1:5000/api/platform/data-to-decision/stage/demo?stage_id=data_lineage",
        "http://127.0.0.1:5000/api/platform/data-to-decision/check/demo",
        "http://127.0.0.1:5000/api/platform/data-to-decision/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Data-to-Decision Assurance installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
