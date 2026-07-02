from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ASSURANCE_OPERATIONAL_RELEASE_GATE_V1_ACTIVE"

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
    "/platform/ai-assurance-operational-release-gate",
    "/platform/ai-operational-release-gate",
    "/platform/operational-release-gate",
    "/ai-assurance-operational-release-gate",
    "/api/platform/ai-assurance-release/model/demo",
    "/api/platform/ai-assurance-release/gate/demo",
    "/api/platform/ai-assurance-release/release/demo",
    "/api/platform/ai-assurance-release/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ASSURANCE_OPERATIONAL_RELEASE_GATE_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-assurance-operational-release-gate")
@app.route("/platform/ai-operational-release-gate")
@app.route("/platform/operational-release-gate")
@app.route("/ai-assurance-operational-release-gate")
def cobitchain_platform_ai_assurance_operational_release_gate():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_assurance_operational_release_gate.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_assurance_operational_release_gate():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_assurance_operational_release_gate_seed.json")
    if not path.exists():
        return {"release_gates": [], "sample_release": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"release_gates": [], "sample_release": {}}


def _cobitchain_enrich_ai_assurance_release_gate(gate):
    import uuid
    from datetime import datetime, timezone

    data = dict(gate or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("sample_score", 0) or 0)
    blocks = bool(data.get("blocks_release", False))
    state = data.get("sample_state", "")

    if blocks and (score < 85 or state not in ["PASS", "READY", "ACTIVE", "ISSUED"]):
        data["computed_gate_state"] = "BLOCKING_RELEASE_GATE_NOT_READY"
    elif score >= 85:
        data["computed_gate_state"] = "RELEASE_GATE_READY"
    else:
        data["computed_gate_state"] = "NON_BLOCKING_RELEASE_REVIEW"

    data["platform_rule"] = "An AI-enabled workflow cannot be released into operational use unless all blocking release gates are satisfied."
    data["engineering_principle"] = "Release is not the same as approval. Release is the controlled act of putting an approved AI-enabled workflow into operation under scope, monitoring, rollback, evidence, and accountable ownership."
    return data


def _cobitchain_enrich_ai_assurance_release(release):
    import uuid
    from datetime import datetime, timezone

    data = dict(release or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("release_score", 0) or 0)
    authorized = bool(data.get("release_authorized", False))
    blockers = data.get("blocking_gates", []) or []

    if authorized and score >= 85 and len(blockers) == 0:
        data["computed_release_state"] = "AUTHORIZED_FOR_OPERATIONAL_RELEASE"
    elif len(blockers) > 0:
        data["computed_release_state"] = "OPERATIONAL_RELEASE_BLOCKED_BY_GATES"
    elif score >= 80:
        data["computed_release_state"] = "CONDITIONAL_RELEASE_REVIEW_REQUIRED"
    else:
        data["computed_release_state"] = "NOT_READY_FOR_OPERATIONAL_RELEASE"

    data["platform_rule"] = "Final release requires certificate, approved scope, monitoring, rollback, evidence, accountable owner, and post-release verification."
    data["engineering_principle"] = "Release is not the same as approval. Release is the controlled act of putting an approved AI-enabled workflow into operation under scope, monitoring, rollback, evidence, and accountable ownership."
    return data


@app.route("/api/platform/ai-assurance-release/model/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_release_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_operational_release_gate()
    gates = [_cobitchain_enrich_ai_assurance_release_gate(item) for item in payload.get("release_gates", [])]
    release = _cobitchain_enrich_ai_assurance_release(payload.get("sample_release", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in gates]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Assurance Operational Release Gate Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "depends_on": payload.get("depends_on", []),
        "release_gate_count": len(gates),
        "average_gate_score": average,
        "release_gates": gates,
        "sample_release": release
    })


@app.route("/api/platform/ai-assurance-release/gate/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_release_gate_demo_api():
    from flask import jsonify, request

    gate_id = request.args.get("gate_id", "certificate_issued_gate")
    payload = _cobitchain_load_ai_assurance_operational_release_gate()
    gates = payload.get("release_gates", []) or []

    for item in gates:
        if item.get("gate_id") == gate_id:
            return jsonify(_cobitchain_enrich_ai_assurance_release_gate(item))

    return jsonify({
        "error": "release_gate_not_found",
        "message": f"No AI Assurance Operational Release Gate found for gate_id={gate_id}",
        "available_gate_ids": [item.get("gate_id") for item in gates]
    }), 404


@app.route("/api/platform/ai-assurance-release/release/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_release_release_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_assurance_operational_release_gate()
    return jsonify(_cobitchain_enrich_ai_assurance_release(payload.get("sample_release", {})))


@app.route("/api/platform/ai-assurance-release/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_release_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_operational_release_gate()
    gates = [_cobitchain_enrich_ai_assurance_release_gate(item) for item in payload.get("release_gates", [])]
    release = _cobitchain_enrich_ai_assurance_release(payload.get("sample_release", {}))

    blocking_gates = [
        {
            "gate_id": item.get("gate_id"),
            "gate_name": item.get("gate_name"),
            "sample_state": item.get("sample_state"),
            "sample_score": item.get("sample_score"),
            "source_module": item.get("source_module"),
            "required_state": item.get("required_state")
        }
        for item in gates
        if item.get("computed_gate_state") == "BLOCKING_RELEASE_GATE_NOT_READY"
    ]

    return jsonify({
        "service": "COBIT-Chain AI Assurance Operational Release Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_release": release,
        "blocking_release_gates": blocking_gates,
        "next_required_actions": release.get("next_required_actions", []),
        "engineering_principle": "Release is not the same as approval. Release is the controlled act of putting an approved AI-enabled workflow into operation under scope, monitoring, rollback, evidence, and accountable ownership."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ASSURANCE_OPERATIONAL_RELEASE_GATE_V1_ACTIVE
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

Path("platform_ai_assurance_operational_release_gate_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-assurance-operational-release-gate",
        "http://127.0.0.1:5000/platform/ai-operational-release-gate",
        "http://127.0.0.1:5000/platform/operational-release-gate",
        "http://127.0.0.1:5000/api/platform/ai-assurance-release/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-release/gate/demo?gate_id=certificate_issued_gate",
        "http://127.0.0.1:5000/api/platform/ai-assurance-release/gate/demo?gate_id=monitoring_activation_gate",
        "http://127.0.0.1:5000/api/platform/ai-assurance-release/release/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-release/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Assurance Operational Release Gate installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
