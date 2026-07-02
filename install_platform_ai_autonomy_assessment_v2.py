from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

markers = [
    "COBITCHAIN_PLATFORM_AI_AUTONOMY_MODEL_V1_ACTIVE",
    "COBITCHAIN_PLATFORM_AI_AUTONOMY_ASSESSMENT_V2_ACTIVE"
]

for marker in markers:
    pattern = (
        r"\n?# ============================================================\n"
        r"# " + re.escape(marker) + r"\n"
        r"# ============================================================\n"
        r".*?"
        r"# ============================================================\n"
        r"# END " + re.escape(marker) + r"\n"
        r"# ============================================================\n?"
    )
    text = re.sub(pattern, "\n", text, flags=re.DOTALL)

MARKER = "COBITCHAIN_PLATFORM_AI_AUTONOMY_ASSESSMENT_V2_ACTIVE"

all_routes = [
    "/platform/ai-autonomy-model",
    "/platform/ai-autonomy-assessment",
    "/platform/automation-agentic-assurance",
    "/platform/autonomy-assurance",
    "/ai-autonomy-model",
    "/api/platform/ai-autonomy/model/demo",
    "/api/platform/ai-autonomy/level/demo",
    "/api/platform/ai-autonomy/check/demo",
    "/api/platform/ai-autonomy/assessment/demo",
    "/api/platform/ai-autonomy/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside known AI Autonomy marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_AUTONOMY_ASSESSMENT_V2_ACTIVE
# ============================================================

@app.route("/platform/ai-autonomy-model")
@app.route("/platform/ai-autonomy-assessment")
@app.route("/platform/automation-agentic-assurance")
@app.route("/platform/autonomy-assurance")
@app.route("/ai-autonomy-model")
def cobitchain_platform_ai_autonomy_assessment_v2():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_autonomy_model.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_autonomy_assessment_v2():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_autonomy_model_seed.json")
    if not path.exists():
        return {"autonomy_levels": [], "sample_assessment": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"autonomy_levels": [], "sample_assessment": {}}


def _cobitchain_ai_autonomy_assessment_band_v2(score):
    score = int(score or 0)
    if score >= 85:
        return "STRONG"
    if score >= 75:
        return "GOOD_WITH_CONTROL_GAPS"
    if score >= 65:
        return "CAUTION"
    return "HIGH_ASSURANCE_REQUIRED"


def _cobitchain_enrich_ai_autonomy_level_v2(level):
    import uuid
    from datetime import datetime, timezone

    data = dict(level or {})
    score = int(data.get("readiness_score", 0) or 0)
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_band"] = _cobitchain_ai_autonomy_assessment_band_v2(score)
    data["platform_rule"] = "Every AI-assisted workflow should be evaluated according to its level of operational autonomy before use."
    data["engineering_principle"] = "As autonomy increases, Platform A must automatically require stronger Assurance Engineering controls."
    return data


def _cobitchain_enrich_ai_autonomy_assessment_v2(assessment, levels):
    import uuid
    from datetime import datetime, timezone

    data = dict(assessment or {})
    detected = data.get("detected_autonomy_level", "level_1")
    level_map = {item.get("level_id"): item for item in levels}
    level = level_map.get(detected, {})

    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["detected_level_number"] = level.get("level_number")
    data["detected_level_name"] = level.get("level_name") or data.get("detected_level_name")
    data["automatic_control_requirements"] = level.get("automatic_control_requirements", {})
    data["mapped_modules"] = level.get("mapped_modules", [])
    data["platform_rule"] = "AI Autonomy Assessment is reusable across all Platform A modules."
    data["engineering_principle"] = "As autonomy increases, Platform A must automatically require stronger Assurance Engineering controls."
    return data


@app.route("/api/platform/ai-autonomy/model/demo", methods=["GET"])
def cobitchain_platform_ai_autonomy_model_demo_api_v2():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_autonomy_assessment_v2()
    raw_levels = payload.get("autonomy_levels", []) or []
    levels = [_cobitchain_enrich_ai_autonomy_level_v2(item) for item in raw_levels]
    assessment = _cobitchain_enrich_ai_autonomy_assessment_v2(payload.get("sample_assessment", {}), raw_levels)

    scores = [int(item.get("readiness_score", 0) or 0) for item in levels]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Autonomy Assessment v2 Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "reusable_across_modules": payload.get("reusable_across_modules", []),
        "control_families": payload.get("control_families", []),
        "autonomy_level_count": len(levels),
        "average_level_readiness": average,
        "autonomy_levels": levels,
        "sample_assessment": assessment
    })


@app.route("/api/platform/ai-autonomy/level/demo", methods=["GET"])
def cobitchain_platform_ai_autonomy_level_demo_api_v2():
    from flask import jsonify, request

    level_id = request.args.get("level_id", "level_4")
    payload = _cobitchain_load_ai_autonomy_assessment_v2()
    levels = payload.get("autonomy_levels", []) or []

    for item in levels:
        if item.get("level_id") == level_id:
            return jsonify(_cobitchain_enrich_ai_autonomy_level_v2(item))

    return jsonify({
        "error": "level_not_found",
        "message": f"No AI Autonomy level found for level_id={level_id}",
        "available_level_ids": [item.get("level_id") for item in levels]
    }), 404


@app.route("/api/platform/ai-autonomy/check/demo", methods=["GET"])
@app.route("/api/platform/ai-autonomy/assessment/demo", methods=["GET"])
def cobitchain_platform_ai_autonomy_assessment_demo_api_v2():
    from flask import jsonify

    payload = _cobitchain_load_ai_autonomy_assessment_v2()
    return jsonify(_cobitchain_enrich_ai_autonomy_assessment_v2(payload.get("sample_assessment", {}), payload.get("autonomy_levels", [])))


@app.route("/api/platform/ai-autonomy/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_autonomy_readiness_demo_api_v2():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_autonomy_assessment_v2()
    raw_levels = payload.get("autonomy_levels", []) or []
    levels = [_cobitchain_enrich_ai_autonomy_level_v2(item) for item in raw_levels]
    assessment = _cobitchain_enrich_ai_autonomy_assessment_v2(payload.get("sample_assessment", {}), raw_levels)

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
        "Run AI Autonomy Assessment for every AI-assisted workflow before operational use.",
        "Automatically scale controls as autonomy increases.",
        "Require human approval for Level 3 and above when regulated, privileged, irreversible, or high-impact decisions are involved.",
        "Require tool governance and runtime monitoring for Level 3 and above.",
        "Require evidence collection and operational trust evaluation at every level.",
        "Require multi-agent accountability, rollback assurance, and continuous assurance at Level 5."
    ]

    return jsonify({
        "service": "COBIT-Chain AI Autonomy Assessment Readiness v2 Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "weakest_levels": weakest,
        "sample_assessment": assessment,
        "required_actions": required_actions,
        "engineering_principle": "As autonomy increases, Platform A must automatically require stronger Assurance Engineering controls."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_AUTONOMY_ASSESSMENT_V2_ACTIVE
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

Path("platform_ai_autonomy_assessment_v2_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-autonomy-assessment",
        "http://127.0.0.1:5000/platform/ai-autonomy-model",
        "http://127.0.0.1:5000/platform/automation-agentic-assurance",
        "http://127.0.0.1:5000/platform/autonomy-assurance",
        "http://127.0.0.1:5000/api/platform/ai-autonomy/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-autonomy/level/demo?level_id=level_4",
        "http://127.0.0.1:5000/api/platform/ai-autonomy/assessment/demo",
        "http://127.0.0.1:5000/api/platform/ai-autonomy/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Autonomy Assessment v2 installed.")
print("Routes installed or refreshed:")
for route in all_routes:
    print("  " + route)
