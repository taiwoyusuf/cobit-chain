from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ASSURANCE_POST_RELEASE_MONITORING_V1_ACTIVE"

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
    "/platform/ai-assurance-post-release-monitoring",
    "/platform/ai-post-release-monitoring",
    "/platform/post-release-ai-monitoring",
    "/ai-assurance-post-release-monitoring",
    "/api/platform/ai-assurance-post-release/model/demo",
    "/api/platform/ai-assurance-post-release/signal/demo",
    "/api/platform/ai-assurance-post-release/monitoring/demo",
    "/api/platform/ai-assurance-post-release/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ASSURANCE_POST_RELEASE_MONITORING_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-assurance-post-release-monitoring")
@app.route("/platform/ai-post-release-monitoring")
@app.route("/platform/post-release-ai-monitoring")
@app.route("/ai-assurance-post-release-monitoring")
def cobitchain_platform_ai_assurance_post_release_monitoring():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_assurance_post_release_monitoring.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_assurance_post_release_monitoring():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_assurance_post_release_monitoring_seed.json")
    if not path.exists():
        return {"monitoring_signals": [], "sample_monitoring": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"monitoring_signals": [], "sample_monitoring": {}}


def _cobitchain_enrich_ai_assurance_post_release_signal(signal):
    import uuid
    from datetime import datetime, timezone

    data = dict(signal or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("sample_score", 0) or 0)
    blocks = bool(data.get("blocks_continued_operation", False))
    state = data.get("sample_state", "")

    if blocks and (score < 85 or state not in ["ACTIVE", "READY", "VALID", "PASS"]):
        data["computed_signal_state"] = "BLOCKING_MONITORING_SIGNAL_NOT_READY"
    elif score >= 85:
        data["computed_signal_state"] = "MONITORING_SIGNAL_READY"
    else:
        data["computed_signal_state"] = "NON_BLOCKING_SIGNAL_REVIEW"

    data["platform_rule"] = "Operational trust must be monitored after release against scope, certificate, runtime, evidence, rollback, and change boundaries."
    data["engineering_principle"] = "Release does not end assurance. Release starts continuous assurance. A released AI workflow remains trusted only while monitoring proves it stays within approved boundaries."
    return data


def _cobitchain_enrich_ai_assurance_post_release_monitoring(monitoring):
    import uuid
    from datetime import datetime, timezone

    data = dict(monitoring or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("monitoring_score", 0) or 0)
    active = bool(data.get("active_monitoring", False))
    blockers = data.get("blocking_signals", []) or []
    released = data.get("operational_state") == "RELEASED"

    if released and active and score >= 85 and len(blockers) == 0:
        data["computed_monitoring_state"] = "CONTINUED_OPERATION_APPROVED"
    elif not released:
        data["computed_monitoring_state"] = "MONITORING_NOT_ACTIVE_RELEASE_NOT_AUTHORIZED"
    elif len(blockers) > 0:
        data["computed_monitoring_state"] = "CONTINUED_OPERATION_AT_RISK_BLOCKING_SIGNALS"
    else:
        data["computed_monitoring_state"] = "MONITORING_REVIEW_REQUIRED"

    data["platform_rule"] = "Post-release monitoring is the continuous evidence layer for operational trust."
    data["engineering_principle"] = "Release does not end assurance. Release starts continuous assurance. A released AI workflow remains trusted only while monitoring proves it stays within approved boundaries."
    return data


@app.route("/api/platform/ai-assurance-post-release/model/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_post_release_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_post_release_monitoring()
    signals = [_cobitchain_enrich_ai_assurance_post_release_signal(item) for item in payload.get("monitoring_signals", [])]
    monitoring = _cobitchain_enrich_ai_assurance_post_release_monitoring(payload.get("sample_monitoring", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in signals]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Assurance Post-Release Monitoring Console Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "depends_on": payload.get("depends_on", []),
        "monitoring_signal_count": len(signals),
        "average_signal_score": average,
        "monitoring_signals": signals,
        "sample_monitoring": monitoring
    })


@app.route("/api/platform/ai-assurance-post-release/signal/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_post_release_signal_demo_api():
    from flask import jsonify, request

    signal_id = request.args.get("signal_id", "runtime_monitoring_signal")
    payload = _cobitchain_load_ai_assurance_post_release_monitoring()
    signals = payload.get("monitoring_signals", []) or []

    for item in signals:
        if item.get("signal_id") == signal_id:
            return jsonify(_cobitchain_enrich_ai_assurance_post_release_signal(item))

    return jsonify({
        "error": "monitoring_signal_not_found",
        "message": f"No AI Assurance Post-Release Monitoring signal found for signal_id={signal_id}",
        "available_signal_ids": [item.get("signal_id") for item in signals]
    }), 404


@app.route("/api/platform/ai-assurance-post-release/monitoring/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_post_release_monitoring_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_assurance_post_release_monitoring()
    return jsonify(_cobitchain_enrich_ai_assurance_post_release_monitoring(payload.get("sample_monitoring", {})))


@app.route("/api/platform/ai-assurance-post-release/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_post_release_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_post_release_monitoring()
    signals = [_cobitchain_enrich_ai_assurance_post_release_signal(item) for item in payload.get("monitoring_signals", [])]
    monitoring = _cobitchain_enrich_ai_assurance_post_release_monitoring(payload.get("sample_monitoring", {}))

    blocking = [
        {
            "signal_id": item.get("signal_id"),
            "signal_name": item.get("signal_name"),
            "sample_state": item.get("sample_state"),
            "sample_score": item.get("sample_score"),
            "source_module": item.get("source_module"),
            "required_state": item.get("required_state")
        }
        for item in signals
        if item.get("computed_signal_state") == "BLOCKING_MONITORING_SIGNAL_NOT_READY"
    ]

    return jsonify({
        "service": "COBIT-Chain AI Assurance Post-Release Monitoring Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_monitoring": monitoring,
        "blocking_monitoring_signals": blocking,
        "monitoring_obligations": monitoring.get("monitoring_obligations", []),
        "next_required_actions": monitoring.get("next_required_actions", []),
        "engineering_principle": "Release does not end assurance. Release starts continuous assurance. A released AI workflow remains trusted only while monitoring proves it stays within approved boundaries."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ASSURANCE_POST_RELEASE_MONITORING_V1_ACTIVE
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

Path("platform_ai_assurance_post_release_monitoring_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-assurance-post-release-monitoring",
        "http://127.0.0.1:5000/platform/ai-post-release-monitoring",
        "http://127.0.0.1:5000/platform/post-release-ai-monitoring",
        "http://127.0.0.1:5000/api/platform/ai-assurance-post-release/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-post-release/signal/demo?signal_id=runtime_monitoring_signal",
        "http://127.0.0.1:5000/api/platform/ai-assurance-post-release/signal/demo?signal_id=drift_detection_signal",
        "http://127.0.0.1:5000/api/platform/ai-assurance-post-release/monitoring/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-post-release/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Assurance Post-Release Monitoring Console installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
