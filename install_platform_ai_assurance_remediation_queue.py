from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ASSURANCE_REMEDIATION_QUEUE_V1_ACTIVE"

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
    "/platform/ai-assurance-remediation-queue",
    "/platform/ai-remediation-queue",
    "/platform/assurance-remediation-queue",
    "/ai-assurance-remediation-queue",
    "/api/platform/ai-assurance-remediation/model/demo",
    "/api/platform/ai-assurance-remediation/action/demo",
    "/api/platform/ai-assurance-remediation/queue/demo",
    "/api/platform/ai-assurance-remediation/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ASSURANCE_REMEDIATION_QUEUE_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-assurance-remediation-queue")
@app.route("/platform/ai-remediation-queue")
@app.route("/platform/assurance-remediation-queue")
@app.route("/ai-assurance-remediation-queue")
def cobitchain_platform_ai_assurance_remediation_queue():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_assurance_remediation_queue.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_assurance_remediation_queue():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_assurance_remediation_queue_seed.json")
    if not path.exists():
        return {"remediation_actions": [], "sample_queue": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"remediation_actions": [], "sample_queue": {}}


def _cobitchain_enrich_ai_assurance_remediation_action(action):
    import uuid
    from datetime import datetime, timezone

    data = dict(action or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["platform_rule"] = "AI assurance gaps must be converted into owner-assigned remediation actions before operational trust can be approved."
    data["engineering_principle"] = "An assurance gap is not closed because it is known. It is closed only when it is assigned, remediated, verified, evidence-bound, and reflected in the operational trust decision."

    if data.get("blocks_operational_approval") is True and data.get("status") != "Closed":
        data["remediation_state"] = "BLOCKING_OPEN"
    elif data.get("status") == "Closed":
        data["remediation_state"] = "CLOSED_PENDING_TRUST_RECALCULATION"
    else:
        data["remediation_state"] = "NON_BLOCKING"

    return data


def _cobitchain_enrich_ai_assurance_remediation_queue(queue):
    import uuid
    from datetime import datetime, timezone

    data = dict(queue or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    blocking = int(data.get("blocking_actions", 0) or 0)
    closed = int(data.get("closed_actions", 0) or 0)
    total = int(data.get("total_actions", 0) or 0)

    if blocking > 0:
        data["queue_state"] = "OPERATIONAL_APPROVAL_BLOCKED"
    elif closed == total and total > 0:
        data["queue_state"] = "READY_FOR_TRUST_RECALCULATION"
    else:
        data["queue_state"] = "REMEDIATION_IN_PROGRESS"

    data["platform_rule"] = "Operational approval can resume only when blocking remediation actions are closed with verified evidence."
    data["engineering_principle"] = "An assurance gap is not closed because it is known. It is closed only when it is assigned, remediated, verified, evidence-bound, and reflected in the operational trust decision."
    return data


@app.route("/api/platform/ai-assurance-remediation/model/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_remediation_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_remediation_queue()
    actions = [_cobitchain_enrich_ai_assurance_remediation_action(item) for item in payload.get("remediation_actions", [])]
    queue = _cobitchain_enrich_ai_assurance_remediation_queue(payload.get("sample_queue", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in actions]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Assurance Remediation Queue Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "depends_on": payload.get("depends_on", []),
        "remediation_action_count": len(actions),
        "average_action_score": average,
        "remediation_actions": actions,
        "sample_queue": queue
    })


@app.route("/api/platform/ai-assurance-remediation/action/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_remediation_action_demo_api():
    from flask import jsonify, request

    action_id = request.args.get("action_id", "rem_human_approval_evidence")
    payload = _cobitchain_load_ai_assurance_remediation_queue()
    actions = payload.get("remediation_actions", []) or []

    for item in actions:
        if item.get("action_id") == action_id:
            return jsonify(_cobitchain_enrich_ai_assurance_remediation_action(item))

    return jsonify({
        "error": "action_not_found",
        "message": f"No AI Assurance Remediation action found for action_id={action_id}",
        "available_action_ids": [item.get("action_id") for item in actions]
    }), 404


@app.route("/api/platform/ai-assurance-remediation/queue/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_remediation_queue_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_assurance_remediation_queue()
    return jsonify(_cobitchain_enrich_ai_assurance_remediation_queue(payload.get("sample_queue", {})))


@app.route("/api/platform/ai-assurance-remediation/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_remediation_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_remediation_queue()
    actions = [_cobitchain_enrich_ai_assurance_remediation_action(item) for item in payload.get("remediation_actions", [])]
    queue = _cobitchain_enrich_ai_assurance_remediation_queue(payload.get("sample_queue", {}))

    blocking = [
        {
            "action_id": item.get("action_id"),
            "action_name": item.get("action_name"),
            "priority": item.get("priority"),
            "owner_role": item.get("owner_role"),
            "required_evidence": item.get("required_evidence", []),
            "closure_criteria": item.get("closure_criteria", [])
        }
        for item in actions
        if item.get("blocks_operational_approval") is True and item.get("status") != "Closed"
    ]

    return jsonify({
        "service": "COBIT-Chain AI Assurance Remediation Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_queue": queue,
        "blocking_actions": blocking,
        "next_required_actions": queue.get("next_required_actions", []),
        "engineering_principle": "An assurance gap is not closed because it is known. It is closed only when it is assigned, remediated, verified, evidence-bound, and reflected in the operational trust decision."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ASSURANCE_REMEDIATION_QUEUE_V1_ACTIVE
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

Path("platform_ai_assurance_remediation_queue_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-assurance-remediation-queue",
        "http://127.0.0.1:5000/platform/ai-remediation-queue",
        "http://127.0.0.1:5000/platform/assurance-remediation-queue",
        "http://127.0.0.1:5000/api/platform/ai-assurance-remediation/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-remediation/action/demo?action_id=rem_human_approval_evidence",
        "http://127.0.0.1:5000/api/platform/ai-assurance-remediation/action/demo?action_id=rem_runtime_monitoring_signal",
        "http://127.0.0.1:5000/api/platform/ai-assurance-remediation/queue/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-remediation/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Assurance Remediation Queue installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
