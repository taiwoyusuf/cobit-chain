from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ARCHITECTURE_ASSURANCE_V1_ACTIVE"

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
    "/platform/ai-architecture-assurance",
    "/platform/architecture-assurance",
    "/platform/ai-assurance-architecture",
    "/ai-architecture-assurance",
    "/api/platform/ai-architecture-assurance/model/demo",
    "/api/platform/ai-architecture-assurance/boundary/demo",
    "/api/platform/ai-architecture-assurance/workflow/demo",
    "/api/platform/ai-architecture-assurance/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ARCHITECTURE_ASSURANCE_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-architecture-assurance")
@app.route("/platform/architecture-assurance")
@app.route("/platform/ai-assurance-architecture")
@app.route("/ai-architecture-assurance")
def cobitchain_platform_ai_architecture_assurance():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_architecture_assurance.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_architecture_assurance():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_architecture_assurance_seed.json")
    if not path.exists():
        return {"assurance_boundaries": [], "sample_workflow": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"assurance_boundaries": [], "sample_workflow": {}}


def _cobitchain_ai_architecture_band(score):
    score = int(score or 0)
    if score >= 85:
        return "ARCHITECTURE_TRUST_READY"
    if score >= 75:
        return "GOOD_WITH_BOUNDARY_GAPS"
    if score >= 65:
        return "CONDITIONAL_ARCHITECTURE_REVIEW"
    return "ARCHITECTURE_NOT_READY"


def _cobitchain_enrich_ai_architecture_boundary(boundary):
    import uuid
    from datetime import datetime, timezone

    data = dict(boundary or {})
    score = int(data.get("readiness_score", 0) or 0)
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_band"] = _cobitchain_ai_architecture_band(score)
    data["platform_rule"] = "Platform A should independently evaluate knowledge, tools, autonomy, and evidence before determining overall operational trust."
    data["engineering_principle"] = "Modern AI systems combine knowledge, tools and autonomous decision making. Platform A should independently evaluate each assurance boundary before determining overall operational trust."
    return data


def _cobitchain_enrich_ai_architecture_workflow(workflow):
    import uuid
    from datetime import datetime, timezone

    data = dict(workflow or {})
    score = int(data.get("overall_operational_trust_score", 0) or 0)

    if score < 65:
        readiness_state = "ARCHITECTURE_NOT_READY"
    elif score < 75:
        readiness_state = "CONDITIONAL_ARCHITECTURE_REVIEW"
    elif score < 85:
        readiness_state = "GOOD_WITH_BOUNDARY_GAPS"
    else:
        readiness_state = "ARCHITECTURE_TRUST_READY"

    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_state"] = readiness_state
    data["platform_rule"] = "Overall operational trust must be derived from independent boundary assurance results."
    data["engineering_principle"] = "Modern AI systems combine knowledge, tools and autonomous decision making. Platform A should independently evaluate each assurance boundary before determining overall operational trust."
    return data


@app.route("/api/platform/ai-architecture-assurance/model/demo", methods=["GET"])
def cobitchain_platform_ai_architecture_assurance_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_architecture_assurance()
    boundaries = [_cobitchain_enrich_ai_architecture_boundary(item) for item in payload.get("assurance_boundaries", [])]
    workflow = _cobitchain_enrich_ai_architecture_workflow(payload.get("sample_workflow", {}))

    scores = [int(item.get("readiness_score", 0) or 0) for item in boundaries]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Architecture Assurance Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "reusable_across_modules": payload.get("reusable_across_modules", []),
        "boundary_count": len(boundaries),
        "average_boundary_readiness": average,
        "assurance_boundaries": boundaries,
        "sample_workflow": workflow
    })


@app.route("/api/platform/ai-architecture-assurance/boundary/demo", methods=["GET"])
def cobitchain_platform_ai_architecture_assurance_boundary_demo_api():
    from flask import jsonify, request

    boundary_id = request.args.get("boundary_id", "knowledge_assurance")
    payload = _cobitchain_load_ai_architecture_assurance()
    boundaries = payload.get("assurance_boundaries", []) or []

    for item in boundaries:
        if item.get("boundary_id") == boundary_id:
            return jsonify(_cobitchain_enrich_ai_architecture_boundary(item))

    return jsonify({
        "error": "boundary_not_found",
        "message": f"No AI Architecture Assurance boundary found for boundary_id={boundary_id}",
        "available_boundary_ids": [item.get("boundary_id") for item in boundaries]
    }), 404


@app.route("/api/platform/ai-architecture-assurance/workflow/demo", methods=["GET"])
def cobitchain_platform_ai_architecture_assurance_workflow_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_architecture_assurance()
    return jsonify(_cobitchain_enrich_ai_architecture_workflow(payload.get("sample_workflow", {})))


@app.route("/api/platform/ai-architecture-assurance/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_architecture_assurance_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_architecture_assurance()
    boundaries = [_cobitchain_enrich_ai_architecture_boundary(item) for item in payload.get("assurance_boundaries", [])]
    workflow = _cobitchain_enrich_ai_architecture_workflow(payload.get("sample_workflow", {}))

    weakest = sorted(
        [
            {
                "boundary_id": item.get("boundary_id"),
                "boundary_name": item.get("boundary_name"),
                "readiness_score": item.get("readiness_score"),
                "gaps_to_watch": item.get("gaps_to_watch", [])
            }
            for item in boundaries
        ],
        key=lambda x: int(x.get("readiness_score", 0) or 0)
    )[:4]

    required_actions = [
        "Confirm trusted knowledge sources, context quality, data lineage, and version control.",
        "Confirm MCP governance, tool authorization, API permissions, and runtime controls.",
        "Assess autonomy level, decision authority, human approval gates, action boundaries, and monitoring.",
        "Bind evidence lineage, decision traceability, operational trust, and regulatory readiness to Evidence Vault.",
        "Calculate overall operational trust only after all four assurance boundaries are evaluated."
    ]

    return jsonify({
        "service": "COBIT-Chain AI Architecture Assurance Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_workflow": workflow,
        "weakest_boundaries": weakest,
        "required_actions": required_actions,
        "engineering_principle": "Modern AI systems combine knowledge, tools and autonomous decision making. Platform A should independently evaluate each assurance boundary before determining overall operational trust."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ARCHITECTURE_ASSURANCE_V1_ACTIVE
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

Path("platform_ai_architecture_assurance_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-architecture-assurance",
        "http://127.0.0.1:5000/platform/architecture-assurance",
        "http://127.0.0.1:5000/platform/ai-assurance-architecture",
        "http://127.0.0.1:5000/api/platform/ai-architecture-assurance/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-architecture-assurance/boundary/demo?boundary_id=knowledge_assurance",
        "http://127.0.0.1:5000/api/platform/ai-architecture-assurance/boundary/demo?boundary_id=tool_assurance",
        "http://127.0.0.1:5000/api/platform/ai-architecture-assurance/boundary/demo?boundary_id=autonomy_assurance",
        "http://127.0.0.1:5000/api/platform/ai-architecture-assurance/boundary/demo?boundary_id=evidence_assurance",
        "http://127.0.0.1:5000/api/platform/ai-architecture-assurance/workflow/demo",
        "http://127.0.0.1:5000/api/platform/ai-architecture-assurance/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Architecture Assurance installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
