from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_AUTONOMY_MODEL_V1_ACTIVE"

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
    "/platform/ai-autonomy-model",
    "/platform/automation-agentic-assurance",
    "/platform/autonomy-assurance",
    "/ai-autonomy-model",
    "/api/platform/ai-autonomy/model/demo",
    "/api/platform/ai-autonomy/level/demo",
    "/api/platform/ai-autonomy/check/demo",
    "/api/platform/ai-autonomy/readiness/demo"
]

for route in all_routes:
    if f'@app.route("{route}")' in text or f"@app.route('{route}')" in text:
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_AUTONOMY_MODEL_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-autonomy-model")
@app.route("/platform/automation-agentic-assurance")
@app.route("/platform/autonomy-assurance")
@app.route("/ai-autonomy-model")
def cobitchain_platform_ai_autonomy_model():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_autonomy_model.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_autonomy_model():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_autonomy_model_seed.json")
    if not path.exists():
        return {"autonomy_levels": [], "sample_workflow": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"autonomy_levels": [], "sample_workflow": {}}


def _cobitchain_ai_autonomy_band(score):
    score = int(score or 0)
    if score >= 85:
        return "STRONG"
    if score >= 75:
        return "GOOD_WITH_CONTROL_GAPS"
    if score >= 65:
        return "CAUTION"
    return "HIGH_ASSURANCE_REQUIRED"


def _cobitchain_enrich_ai_autonomy_level(level):
    import uuid
    from datetime import datetime, timezone

    data = dict(level or {})
    score = int(data.get("readiness_score", 0) or 0)
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_band"] = _cobitchain_ai_autonomy_band(score)
    data["platform_rule"] = "Classify workflows by autonomy level and scale Assurance Engineering controls accordingly."
    data["engineering_principle"] = "As AI autonomy increases, Assurance Engineering requirements should also increase."
    data["framework_position"] = "LangChain and LangGraph are implementation examples only. COBIT-Chain remains framework-neutral."
    return data


def _cobitchain_enrich_ai_autonomy_workflow(workflow, levels):
    import uuid
    from datetime import datetime, timezone

    data = dict(workflow or {})
    detected = data.get("detected_autonomy_level", "level_1")
    level_map = {item.get("level_id"): item for item in levels}
    level = level_map.get(detected, {})

    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["detected_level_number"] = level.get("level_number")
    data["detected_level_name"] = level.get("level_name")
    data["minimum_assurance_controls"] = level.get("minimum_assurance_controls", {})
    data["platform_rule"] = "Workflow automation follows predefined paths. Agentic AI evaluates context, selects actions, adapts strategies, and coordinates tools before execution."
    data["engineering_principle"] = "As AI autonomy increases, Assurance Engineering requirements should also increase."
    data["framework_position"] = "LangChain and LangGraph may be used as examples, but are not COBIT-Chain platform dependencies."
    return data


@app.route("/api/platform/ai-autonomy/model/demo", methods=["GET"])
def cobitchain_platform_ai_autonomy_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_autonomy_model()
    levels = [_cobitchain_enrich_ai_autonomy_level(item) for item in payload.get("autonomy_levels", [])]
    sample = _cobitchain_enrich_ai_autonomy_workflow(payload.get("sample_workflow", {}), payload.get("autonomy_levels", []))

    scores = [int(item.get("readiness_score", 0) or 0) for item in levels]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Autonomy Model Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "implementation_note": payload.get("implementation_note"),
        "autonomy_level_count": len(levels),
        "average_level_readiness": average,
        "autonomy_levels": levels,
        "sample_workflow": sample
    })


@app.route("/api/platform/ai-autonomy/level/demo", methods=["GET"])
def cobitchain_platform_ai_autonomy_level_demo_api():
    from flask import jsonify, request

    level_id = request.args.get("level_id", "level_4")
    payload = _cobitchain_load_ai_autonomy_model()
    levels = payload.get("autonomy_levels", []) or []

    for item in levels:
        if item.get("level_id") == level_id:
            return jsonify(_cobitchain_enrich_ai_autonomy_level(item))

    return jsonify({
        "error": "level_not_found",
        "message": f"No AI Autonomy level found for level_id={level_id}",
        "available_level_ids": [item.get("level_id") for item in levels]
    }), 404


@app.route("/api/platform/ai-autonomy/check/demo", methods=["GET"])
def cobitchain_platform_ai_autonomy_check_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_autonomy_model()
    return jsonify(_cobitchain_enrich_ai_autonomy_workflow(payload.get("sample_workflow", {}), payload.get("autonomy_levels", [])))


@app.route("/api/platform/ai-autonomy/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_autonomy_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_autonomy_model()
    levels = [_cobitchain_enrich_ai_autonomy_level(item) for item in payload.get("autonomy_levels", [])]
    sample = _cobitchain_enrich_ai_autonomy_workflow(payload.get("sample_workflow", {}), payload.get("autonomy_levels", []))

    weakest = sorted(
        [
            {
                "level_id": item.get("level_id"),
                "level_number": item.get("level_number"),
                "level_name": item.get("level_name"),
                "readiness_score": item.get("readiness_score"),
                "required_controls": item.get("required_controls", [])
            }
            for item in levels
        ],
        key=lambda x: int(x.get("readiness_score", 0) or 0)
    )[:3]

    required_actions = [
        "Classify each AI-assisted workflow by autonomy level before deployment or use.",
        "Require Agent Passport and authority verification at Level 3 and above.",
        "Require MCP-governed tool execution for adaptive and agentic workflows.",
        "Require human approval for Level 4 and Level 5 regulated or high-impact actions.",
        "Require continuous monitoring, audit replay, and rollback assurance for Level 5 coordination."
    ]

    return jsonify({
        "service": "COBIT-Chain AI Autonomy Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "weakest_levels": weakest,
        "sample_workflow": sample,
        "required_actions": required_actions,
        "engineering_principle": "As AI autonomy increases, Assurance Engineering requirements should also increase."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_AUTONOMY_MODEL_V1_ACTIVE
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

Path("platform_ai_autonomy_model_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-autonomy-model",
        "http://127.0.0.1:5000/platform/automation-agentic-assurance",
        "http://127.0.0.1:5000/platform/autonomy-assurance",
        "http://127.0.0.1:5000/api/platform/ai-autonomy/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-autonomy/level/demo?level_id=level_4",
        "http://127.0.0.1:5000/api/platform/ai-autonomy/check/demo",
        "http://127.0.0.1:5000/api/platform/ai-autonomy/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Autonomy Model installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
