from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ASSURANCE_OUTCOME_LEARNING_ENGINE_V1_ACTIVE"

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
    "/platform/ai-assurance-outcome-learning",
    "/platform/ai-outcome-learning",
    "/platform/assurance-continuous-improvement",
    "/ai-assurance-outcome-learning",
    "/api/platform/ai-assurance-learning/model/demo",
    "/api/platform/ai-assurance-learning/loop/demo",
    "/api/platform/ai-assurance-learning/learning/demo",
    "/api/platform/ai-assurance-learning/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ASSURANCE_OUTCOME_LEARNING_ENGINE_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-assurance-outcome-learning")
@app.route("/platform/ai-outcome-learning")
@app.route("/platform/assurance-continuous-improvement")
@app.route("/ai-assurance-outcome-learning")
def cobitchain_platform_ai_assurance_outcome_learning():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_assurance_outcome_learning.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_assurance_outcome_learning():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_assurance_outcome_learning_seed.json")
    if not path.exists():
        return {"learning_loops": [], "sample_learning": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"learning_loops": [], "sample_learning": {}}


def _cobitchain_enrich_ai_assurance_learning_loop(loop):
    import uuid
    from datetime import datetime, timezone

    data = dict(loop or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("sample_score", 0) or 0)
    blocks = bool(data.get("blocks_continuous_improvement", False))
    state = data.get("sample_state", "")

    if blocks and (score < 85 or state in ["OPEN", "PARTIAL", "INCOMPLETE", "TRIGGERED"]):
        data["computed_learning_state"] = "BLOCKING_LEARNING_LOOP_NOT_READY"
    elif score >= 85:
        data["computed_learning_state"] = "LEARNING_LOOP_READY_FOR_REUSE"
    else:
        data["computed_learning_state"] = "LEARNING_LOOP_REVIEW_REQUIRED"

    data["platform_rule"] = "AI operational outcomes, exceptions, drift events, incidents, and response evidence must feed governed learning and continuous improvement."
    data["engineering_principle"] = "Continuous assurance is not complete until operational outcomes improve the system of control. Learning must be evidence-bound, governed, reusable, and traceable."
    return data


def _cobitchain_enrich_ai_assurance_outcome_learning(learning):
    import uuid
    from datetime import datetime, timezone

    data = dict(learning or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("learning_score", 0) or 0)
    ready = bool(data.get("learning_ready_for_reuse", False))
    blockers = data.get("blocking_learning_loops", []) or []

    if ready and score >= 85 and len(blockers) == 0:
        data["computed_outcome_learning_state"] = "LEARNING_READY_FOR_REUSE_AND_CONTINUOUS_IMPROVEMENT"
    elif len(blockers) > 0:
        data["computed_outcome_learning_state"] = "CONTINUOUS_IMPROVEMENT_BLOCKED_BY_LEARNING_GAPS"
    elif score >= 75:
        data["computed_outcome_learning_state"] = "LEARNING_REVIEW_REQUIRED"
    else:
        data["computed_outcome_learning_state"] = "LEARNING_NOT_READY"

    data["platform_rule"] = "Learning becomes valuable only when it updates evidence, controls, scope, monitoring, and organizational intelligence."
    data["engineering_principle"] = "Continuous assurance is not complete until operational outcomes improve the system of control. Learning must be evidence-bound, governed, reusable, and traceable."
    return data


@app.route("/api/platform/ai-assurance-learning/model/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_learning_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_outcome_learning()
    loops = [_cobitchain_enrich_ai_assurance_learning_loop(item) for item in payload.get("learning_loops", [])]
    learning = _cobitchain_enrich_ai_assurance_outcome_learning(payload.get("sample_learning", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in loops]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Assurance Outcome Learning Engine Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "depends_on": payload.get("depends_on", []),
        "learning_loop_count": len(loops),
        "average_loop_score": average,
        "learning_loops": loops,
        "sample_learning": learning
    })


@app.route("/api/platform/ai-assurance-learning/loop/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_learning_loop_demo_api():
    from flask import jsonify, request

    loop_id = request.args.get("loop_id", "organizational_intelligence_loop")
    payload = _cobitchain_load_ai_assurance_outcome_learning()
    loops = payload.get("learning_loops", []) or []

    for item in loops:
        if item.get("loop_id") == loop_id:
            return jsonify(_cobitchain_enrich_ai_assurance_learning_loop(item))

    return jsonify({
        "error": "learning_loop_not_found",
        "message": f"No AI Assurance Outcome Learning loop found for loop_id={loop_id}",
        "available_loop_ids": [item.get("loop_id") for item in loops]
    }), 404


@app.route("/api/platform/ai-assurance-learning/learning/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_learning_learning_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_assurance_outcome_learning()
    return jsonify(_cobitchain_enrich_ai_assurance_outcome_learning(payload.get("sample_learning", {})))


@app.route("/api/platform/ai-assurance-learning/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_learning_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_outcome_learning()
    loops = [_cobitchain_enrich_ai_assurance_learning_loop(item) for item in payload.get("learning_loops", [])]
    learning = _cobitchain_enrich_ai_assurance_outcome_learning(payload.get("sample_learning", {}))

    blocking = [
        {
            "loop_id": item.get("loop_id"),
            "loop_name": item.get("loop_name"),
            "sample_state": item.get("sample_state"),
            "sample_score": item.get("sample_score"),
            "source_module": item.get("source_module"),
            "improvement_outputs": item.get("improvement_outputs", [])
        }
        for item in loops
        if item.get("computed_learning_state") == "BLOCKING_LEARNING_LOOP_NOT_READY"
    ]

    return jsonify({
        "service": "COBIT-Chain AI Assurance Outcome Learning Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_learning": learning,
        "blocking_learning_loops": blocking,
        "required_learning_actions": learning.get("required_learning_actions", []),
        "evidence_to_bind": learning.get("evidence_to_bind", []),
        "engineering_principle": "Continuous assurance is not complete until operational outcomes improve the system of control. Learning must be evidence-bound, governed, reusable, and traceable."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ASSURANCE_OUTCOME_LEARNING_ENGINE_V1_ACTIVE
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

Path("platform_ai_assurance_outcome_learning_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-assurance-outcome-learning",
        "http://127.0.0.1:5000/platform/ai-outcome-learning",
        "http://127.0.0.1:5000/platform/assurance-continuous-improvement",
        "http://127.0.0.1:5000/api/platform/ai-assurance-learning/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-learning/loop/demo?loop_id=organizational_intelligence_loop",
        "http://127.0.0.1:5000/api/platform/ai-assurance-learning/loop/demo?loop_id=lifecycle_change_learning_loop",
        "http://127.0.0.1:5000/api/platform/ai-assurance-learning/learning/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-learning/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Assurance Outcome Learning Engine installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
