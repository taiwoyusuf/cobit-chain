from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_DECISION_CONTEXT_ASSURANCE_FLOW_V1_ACTIVE"

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
    "/platform/decision-context-assurance",
    "/platform/decision-confidence-flow",
    "/platform/trusted-data-context-flow",
    "/decision-context-assurance",
    "/api/platform/decision-context/flow/demo",
    "/api/platform/decision-context/stage/demo",
    "/api/platform/decision-context/readiness/demo"
]

for route in all_routes:
    if f'@app.route("{route}")' in text or f"@app.route('{route}')" in text:
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_DECISION_CONTEXT_ASSURANCE_FLOW_V1_ACTIVE
# ============================================================

@app.route("/platform/decision-context-assurance")
@app.route("/platform/decision-confidence-flow")
@app.route("/platform/trusted-data-context-flow")
@app.route("/decision-context-assurance")
def cobitchain_platform_decision_context_assurance_flow():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_decision_context_assurance_flow.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_decision_context_assurance_flow():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_decision_context_assurance_seed.json")
    if not path.exists():
        return {"stages": [], "assurance_chain": []}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"stages": [], "assurance_chain": []}


def _cobitchain_enrich_decision_context_stage(stage):
    import uuid
    from datetime import datetime, timezone

    data = dict(stage or {})
    score = int(data.get("readiness_score", 0) or 0)

    if score >= 85:
        band = "STRONG"
    elif score >= 75:
        band = "GOOD_WITH_EVIDENCE_GAPS"
    elif score >= 65:
        band = "CAUTION"
    else:
        band = "LIMITED"

    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_band"] = band
    data["engineering_principle"] = "Models generate recommendations. Platform A demonstrates whether those recommendations are operationally trustworthy."
    data["platform_rule"] = "Strengthen existing Platform A capabilities. Do not introduce new foundational modules solely because industry terminology changes."
    data["service_note"] = "Decision Context Assurance Flow strengthens Decision Confidence, Evidence Vault, Operational Trust, Governance Vision, Knowledge Integrity, CITrust, and AI ChangeControlTrust."
    return data


@app.route("/api/platform/decision-context/flow/demo", methods=["GET"])
def cobitchain_platform_decision_context_flow_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    flow = _cobitchain_load_decision_context_assurance_flow()
    stages = [_cobitchain_enrich_decision_context_stage(item) for item in flow.get("stages", [])]

    scores = [int(item.get("readiness_score", 0) or 0) for item in stages]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain Decision Context Assurance Flow Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "flow_name": flow.get("flow_name"),
        "platform_rule": flow.get("platform_rule"),
        "positioning": flow.get("positioning"),
        "stage_count": len(stages),
        "average_readiness_score": average,
        "assurance_chain": flow.get("assurance_chain", []),
        "stages": stages
    })


@app.route("/api/platform/decision-context/stage/demo", methods=["GET"])
def cobitchain_platform_decision_context_stage_demo_api():
    from flask import jsonify, request

    stage_id = request.args.get("stage_id", "trusted_data")
    flow = _cobitchain_load_decision_context_assurance_flow()
    stages = flow.get("stages", []) or []

    for item in stages:
        if item.get("stage_id") == stage_id:
            return jsonify(_cobitchain_enrich_decision_context_stage(item))

    return jsonify({
        "error": "stage_not_found",
        "message": f"No decision context stage found for stage_id={stage_id}",
        "available_stage_ids": [item.get("stage_id") for item in stages]
    }), 404


@app.route("/api/platform/decision-context/readiness/demo", methods=["GET"])
def cobitchain_platform_decision_context_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    flow = _cobitchain_load_decision_context_assurance_flow()
    stages = [_cobitchain_enrich_decision_context_stage(item) for item in flow.get("stages", [])]

    scores = [int(item.get("readiness_score", 0) or 0) for item in stages]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    weakest = sorted(
        [
            {
                "stage_id": item.get("stage_id"),
                "stage_name": item.get("stage_name"),
                "readiness_score": item.get("readiness_score"),
                "gaps_to_watch": item.get("gaps_to_watch", [])
            }
            for item in stages
        ],
        key=lambda x: int(x.get("readiness_score", 0) or 0)
    )[:3]

    required_actions = [
        "Bind data source traceability to Evidence Vault packages.",
        "Validate workflow context and ownership before AI recommendation use.",
        "Capture prompt, model, tool-call, and knowledge-source evidence.",
        "Require named human review before operational decision use.",
        "Measure operational outcomes and feed results back into Decision Confidence."
    ]

    return jsonify({
        "service": "COBIT-Chain Decision Context Assurance Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "average_readiness_score": average,
        "stage_count": len(stages),
        "weakest_stages": weakest,
        "required_actions": required_actions,
        "engineering_principle": "Models generate recommendations. Platform A demonstrates whether those recommendations are operationally trustworthy."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_DECISION_CONTEXT_ASSURANCE_FLOW_V1_ACTIVE
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

Path("platform_decision_context_assurance_flow_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/decision-context-assurance",
        "http://127.0.0.1:5000/platform/decision-confidence-flow",
        "http://127.0.0.1:5000/platform/trusted-data-context-flow",
        "http://127.0.0.1:5000/api/platform/decision-context/flow/demo",
        "http://127.0.0.1:5000/api/platform/decision-context/stage/demo?stage_id=trusted_context",
        "http://127.0.0.1:5000/api/platform/decision-context/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Decision Context Assurance Flow installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
