from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_OPERATIONAL_READINESS_V1_ACTIVE"

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
    "/platform/ai-operational-readiness",
    "/platform/operational-ai-readiness",
    "/platform/ai-ops-readiness",
    "/ai-operational-readiness",
    "/api/platform/ai-operational-readiness/model/demo",
    "/api/platform/ai-operational-readiness/dimension/demo",
    "/api/platform/ai-operational-readiness/level/demo",
    "/api/platform/ai-operational-readiness/assessment/demo",
    "/api/platform/ai-operational-readiness/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_OPERATIONAL_READINESS_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-operational-readiness")
@app.route("/platform/operational-ai-readiness")
@app.route("/platform/ai-ops-readiness")
@app.route("/ai-operational-readiness")
def cobitchain_platform_ai_operational_readiness():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_operational_readiness.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_operational_readiness():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_operational_readiness_seed.json")
    if not path.exists():
        return {"assessment_dimensions": [], "maturity_model": [], "sample_readiness_assessment": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"assessment_dimensions": [], "maturity_model": [], "sample_readiness_assessment": {}}


def _cobitchain_ai_operational_readiness_band(score):
    score = int(score or 0)
    if score >= 85:
        return "TRANSFORMATION_READY"
    if score >= 75:
        return "GOOD_WITH_OPERATING_MODEL_GAPS"
    if score >= 65:
        return "PARTIAL_READINESS"
    return "NOT_READY"


def _cobitchain_enrich_ai_operational_dimension(dimension):
    import uuid
    from datetime import datetime, timezone

    data = dict(dimension or {})
    score = int(data.get("readiness_score", 0) or 0)
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_band"] = _cobitchain_ai_operational_readiness_band(score)
    data["platform_rule"] = "AI Operational Readiness strengthens existing Platform A modules rather than introducing a separate governance framework."
    data["engineering_principle"] = "Technology adoption alone does not constitute transformation. Transformation occurs when AI becomes an accountable operational capability supported by governance, evidence, and human oversight."
    return data


def _cobitchain_enrich_ai_operational_level(level):
    import uuid
    from datetime import datetime, timezone

    data = dict(level or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["platform_rule"] = "Evaluate operating model maturity before claiming AI transformation."
    data["engineering_principle"] = "Transformation occurs when AI becomes an accountable operational capability."
    return data


def _cobitchain_enrich_ai_operational_assessment(assessment, maturity_model):
    import uuid
    from datetime import datetime, timezone

    data = dict(assessment or {})
    level_map = {item.get("level_id"): item for item in maturity_model}
    current = level_map.get(data.get("current_maturity_level"), {})
    target = level_map.get(data.get("target_maturity_level"), {})

    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["current_maturity_name"] = current.get("level_name")
    data["target_maturity_name"] = target.get("level_name")
    data["readiness_band"] = _cobitchain_ai_operational_readiness_band(data.get("readiness_score", 0))
    data["platform_rule"] = "AI Operational Readiness evaluates organizational readiness for AI-enabled operations."
    data["engineering_principle"] = "Technology adoption alone does not constitute transformation. Transformation occurs when AI becomes an accountable operational capability supported by governance, evidence, and human oversight."
    return data


@app.route("/api/platform/ai-operational-readiness/model/demo", methods=["GET"])
def cobitchain_platform_ai_operational_readiness_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_operational_readiness()
    dimensions = [_cobitchain_enrich_ai_operational_dimension(item) for item in payload.get("assessment_dimensions", [])]
    maturity = [_cobitchain_enrich_ai_operational_level(item) for item in payload.get("maturity_model", [])]
    assessment = _cobitchain_enrich_ai_operational_assessment(payload.get("sample_readiness_assessment", {}), payload.get("maturity_model", []))

    scores = [int(item.get("readiness_score", 0) or 0) for item in dimensions]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Operational Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "strengthens_modules": payload.get("strengthens_modules", []),
        "dimension_count": len(dimensions),
        "maturity_level_count": len(maturity),
        "average_dimension_readiness": average,
        "assessment_dimensions": dimensions,
        "maturity_model": maturity,
        "sample_readiness_assessment": assessment
    })


@app.route("/api/platform/ai-operational-readiness/dimension/demo", methods=["GET"])
def cobitchain_platform_ai_operational_readiness_dimension_demo_api():
    from flask import jsonify, request

    dimension_id = request.args.get("dimension_id", "workflow_redesign")
    payload = _cobitchain_load_ai_operational_readiness()
    dimensions = payload.get("assessment_dimensions", []) or []

    for item in dimensions:
        if item.get("dimension_id") == dimension_id:
            return jsonify(_cobitchain_enrich_ai_operational_dimension(item))

    return jsonify({
        "error": "dimension_not_found",
        "message": f"No AI Operational Readiness dimension found for dimension_id={dimension_id}",
        "available_dimension_ids": [item.get("dimension_id") for item in dimensions]
    }), 404


@app.route("/api/platform/ai-operational-readiness/level/demo", methods=["GET"])
def cobitchain_platform_ai_operational_readiness_level_demo_api():
    from flask import jsonify, request

    level_id = request.args.get("level_id", "level_3")
    payload = _cobitchain_load_ai_operational_readiness()
    levels = payload.get("maturity_model", []) or []

    for item in levels:
        if item.get("level_id") == level_id:
            return jsonify(_cobitchain_enrich_ai_operational_level(item))

    return jsonify({
        "error": "level_not_found",
        "message": f"No AI Operational Readiness maturity level found for level_id={level_id}",
        "available_level_ids": [item.get("level_id") for item in levels]
    }), 404


@app.route("/api/platform/ai-operational-readiness/assessment/demo", methods=["GET"])
def cobitchain_platform_ai_operational_readiness_assessment_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_operational_readiness()
    return jsonify(_cobitchain_enrich_ai_operational_assessment(payload.get("sample_readiness_assessment", {}), payload.get("maturity_model", [])))


@app.route("/api/platform/ai-operational-readiness/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_operational_readiness_summary_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_operational_readiness()
    dimensions = [_cobitchain_enrich_ai_operational_dimension(item) for item in payload.get("assessment_dimensions", [])]
    assessment = _cobitchain_enrich_ai_operational_assessment(payload.get("sample_readiness_assessment", {}), payload.get("maturity_model", []))

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
        "Redesign workflows around AI-enabled operations rather than layering AI onto old processes.",
        "Define decision ownership and human-AI responsibility boundaries.",
        "Formalize governance cadence, approval pathways, and escalation paths.",
        "Implement operational controls, runtime monitoring, and evidence packages.",
        "Measure outcomes, control effectiveness, exception trends, and improvement actions."
    ]

    return jsonify({
        "service": "COBIT-Chain AI Operational Readiness Summary Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_assessment": assessment,
        "weakest_dimensions": weakest,
        "required_actions": required_actions,
        "engineering_principle": "Technology adoption alone does not constitute transformation. Transformation occurs when AI becomes an accountable operational capability supported by governance, evidence, and human oversight."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_OPERATIONAL_READINESS_V1_ACTIVE
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

Path("platform_ai_operational_readiness_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-operational-readiness",
        "http://127.0.0.1:5000/platform/operational-ai-readiness",
        "http://127.0.0.1:5000/platform/ai-ops-readiness",
        "http://127.0.0.1:5000/api/platform/ai-operational-readiness/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-operational-readiness/dimension/demo?dimension_id=workflow_redesign",
        "http://127.0.0.1:5000/api/platform/ai-operational-readiness/level/demo?level_id=level_3",
        "http://127.0.0.1:5000/api/platform/ai-operational-readiness/assessment/demo",
        "http://127.0.0.1:5000/api/platform/ai-operational-readiness/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Operational Readiness installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
