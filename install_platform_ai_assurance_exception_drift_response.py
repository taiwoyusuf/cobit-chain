from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ASSURANCE_EXCEPTION_DRIFT_RESPONSE_V1_ACTIVE"

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
    "/platform/ai-assurance-exception-drift-response",
    "/platform/ai-exception-drift-response",
    "/platform/ai-assurance-response-engine",
    "/ai-assurance-exception-drift-response",
    "/api/platform/ai-assurance-response/model/demo",
    "/api/platform/ai-assurance-response/trigger/demo",
    "/api/platform/ai-assurance-response/response/demo",
    "/api/platform/ai-assurance-response/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ASSURANCE_EXCEPTION_DRIFT_RESPONSE_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-assurance-exception-drift-response")
@app.route("/platform/ai-exception-drift-response")
@app.route("/platform/ai-assurance-response-engine")
@app.route("/ai-assurance-exception-drift-response")
def cobitchain_platform_ai_assurance_exception_drift_response():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_assurance_exception_drift_response.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_assurance_exception_drift_response():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_assurance_exception_drift_response_seed.json")
    if not path.exists():
        return {"response_triggers": [], "sample_response": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"response_triggers": [], "sample_response": {}}


def _cobitchain_enrich_ai_assurance_response_trigger(trigger):
    import uuid
    from datetime import datetime, timezone

    data = dict(trigger or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("sample_score", 0) or 0)
    blocks = bool(data.get("blocks_continued_operation", False))
    stop_use = bool(data.get("requires_stop_use", False))
    severity = data.get("severity", "")
    state = data.get("sample_state", "")

    if stop_use or (severity == "Critical" and blocks):
        data["computed_trigger_state"] = "STOP_USE_OR_ESCALATION_REQUIRED"
    elif blocks and (score < 85 or state in ["TRIGGERED", "FAILED", "BREACH", "EXPIRED", "PARTIAL"]):
        data["computed_trigger_state"] = "CONTROLLED_RESPONSE_REQUIRED"
    elif score >= 85:
        data["computed_trigger_state"] = "SIGNAL_ACCEPTABLE"
    else:
        data["computed_trigger_state"] = "REVIEW_REQUIRED"

    data["platform_rule"] = "AI monitoring exceptions, drift, unsafe tool behavior, evidence lapses, and lifecycle changes must trigger controlled operational response."
    data["engineering_principle"] = "Continuous assurance is only useful if monitoring signals trigger governed action. A detected AI exception must become a controlled response, not just an alert."
    return data


def _cobitchain_enrich_ai_assurance_response(response):
    import uuid
    from datetime import datetime, timezone

    data = dict(response or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("response_score", 0) or 0)
    stop_use = bool(data.get("stop_use_required", False))
    rollback = bool(data.get("rollback_required", False))
    change = bool(data.get("change_assurance_required", False))
    continued = bool(data.get("continued_operation_allowed", False))

    if stop_use or rollback or change:
        data["computed_response_state"] = "CONTROLLED_STOP_USE_ROLLBACK_OR_CHANGE_ASSURANCE_REQUIRED"
    elif continued and score >= 85:
        data["computed_response_state"] = "CONTINUED_OPERATION_ALLOWED_WITH_MONITORING"
    elif score >= 75:
        data["computed_response_state"] = "CONDITIONAL_OPERATION_WITH_ESCALATION"
    else:
        data["computed_response_state"] = "CONTINUED_OPERATION_NOT_ALLOWED"

    data["platform_rule"] = "Exception and drift response determines whether operation continues, is contained, is downgraded, or enters change assurance."
    data["engineering_principle"] = "Continuous assurance is only useful if monitoring signals trigger governed action. A detected AI exception must become a controlled response, not just an alert."
    return data


@app.route("/api/platform/ai-assurance-response/model/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_response_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_exception_drift_response()
    triggers = [_cobitchain_enrich_ai_assurance_response_trigger(item) for item in payload.get("response_triggers", [])]
    response = _cobitchain_enrich_ai_assurance_response(payload.get("sample_response", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in triggers]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Assurance Exception and Drift Response Engine Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "depends_on": payload.get("depends_on", []),
        "response_trigger_count": len(triggers),
        "average_trigger_score": average,
        "response_triggers": triggers,
        "sample_response": response
    })


@app.route("/api/platform/ai-assurance-response/trigger/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_response_trigger_demo_api():
    from flask import jsonify, request

    trigger_id = request.args.get("trigger_id", "drift_threshold_breach_trigger")
    payload = _cobitchain_load_ai_assurance_exception_drift_response()
    triggers = payload.get("response_triggers", []) or []

    for item in triggers:
        if item.get("trigger_id") == trigger_id:
            return jsonify(_cobitchain_enrich_ai_assurance_response_trigger(item))

    return jsonify({
        "error": "response_trigger_not_found",
        "message": f"No AI Assurance Response trigger found for trigger_id={trigger_id}",
        "available_trigger_ids": [item.get("trigger_id") for item in triggers]
    }), 404


@app.route("/api/platform/ai-assurance-response/response/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_response_response_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_assurance_exception_drift_response()
    return jsonify(_cobitchain_enrich_ai_assurance_response(payload.get("sample_response", {})))


@app.route("/api/platform/ai-assurance-response/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_response_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_exception_drift_response()
    triggers = [_cobitchain_enrich_ai_assurance_response_trigger(item) for item in payload.get("response_triggers", [])]
    response = _cobitchain_enrich_ai_assurance_response(payload.get("sample_response", {}))

    stop_use_triggers = [
        {
            "trigger_id": item.get("trigger_id"),
            "trigger_name": item.get("trigger_name"),
            "severity": item.get("severity"),
            "sample_state": item.get("sample_state"),
            "source_signal": item.get("source_signal"),
            "required_response": item.get("required_response", [])
        }
        for item in triggers
        if item.get("requires_stop_use") is True
    ]

    return jsonify({
        "service": "COBIT-Chain AI Assurance Exception and Drift Response Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_response": response,
        "stop_use_triggers": stop_use_triggers,
        "required_response_actions": response.get("required_response_actions", []),
        "evidence_to_bind": response.get("evidence_to_bind", []),
        "engineering_principle": "Continuous assurance is only useful if monitoring signals trigger governed action. A detected AI exception must become a controlled response, not just an alert."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ASSURANCE_EXCEPTION_DRIFT_RESPONSE_V1_ACTIVE
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

Path("platform_ai_assurance_exception_drift_response_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-assurance-exception-drift-response",
        "http://127.0.0.1:5000/platform/ai-exception-drift-response",
        "http://127.0.0.1:5000/platform/ai-assurance-response-engine",
        "http://127.0.0.1:5000/api/platform/ai-assurance-response/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-response/trigger/demo?trigger_id=drift_threshold_breach_trigger",
        "http://127.0.0.1:5000/api/platform/ai-assurance-response/trigger/demo?trigger_id=unsafe_tool_action_trigger",
        "http://127.0.0.1:5000/api/platform/ai-assurance-response/response/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-response/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Assurance Exception and Drift Response Engine installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
