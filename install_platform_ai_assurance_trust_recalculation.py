from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ASSURANCE_TRUST_RECALCULATION_V1_ACTIVE"

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
    "/platform/ai-assurance-trust-recalculation",
    "/platform/ai-trust-recalculation",
    "/platform/assurance-trust-recalculation",
    "/ai-assurance-trust-recalculation",
    "/api/platform/ai-assurance-trust-recalculation/model/demo",
    "/api/platform/ai-assurance-trust-recalculation/input/demo",
    "/api/platform/ai-assurance-trust-recalculation/recalculate/demo",
    "/api/platform/ai-assurance-trust-recalculation/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ASSURANCE_TRUST_RECALCULATION_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-assurance-trust-recalculation")
@app.route("/platform/ai-trust-recalculation")
@app.route("/platform/assurance-trust-recalculation")
@app.route("/ai-assurance-trust-recalculation")
def cobitchain_platform_ai_assurance_trust_recalculation():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_assurance_trust_recalculation.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_assurance_trust_recalculation():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_assurance_trust_recalculation_seed.json")
    if not path.exists():
        return {"trust_inputs": [], "sample_recalculation": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"trust_inputs": [], "sample_recalculation": {}}


def _cobitchain_enrich_ai_assurance_trust_input(item):
    import uuid
    from datetime import datetime, timezone

    data = dict(item or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("sample_score", 0) or 0)
    blocks = bool(data.get("blocks_approval", False))

    if blocks and score < 85:
        data["computed_input_state"] = "BLOCKING_TRUST_INPUT_NOT_READY"
    elif score >= 85:
        data["computed_input_state"] = "TRUST_INPUT_READY"
    else:
        data["computed_input_state"] = "NON_BLOCKING_INPUT_REVIEW"

    data["platform_rule"] = "Operational trust can be recalculated only after blocking remediation actions are verified closed with evidence."
    data["engineering_principle"] = "Trust is not restored by intent. Trust is restored only after verified closure, evidence update, replay readiness, monitoring readiness, and recalculated operational trust."
    return data


def _cobitchain_enrich_ai_assurance_trust_recalculation(calc):
    import uuid
    from datetime import datetime, timezone

    data = dict(calc or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("recalculated_operational_trust_score", 0) or 0)
    approved = bool(data.get("approved_for_operational_use", False))
    blocking = data.get("blocking_inputs", []) or []

    if approved and score >= 85 and len(blocking) == 0:
        data["computed_trust_state"] = "APPROVED_OPERATIONAL_TRUST_RESTORED"
    elif len(blocking) > 0:
        data["computed_trust_state"] = "TRUST_RECALCULATION_BLOCKED_BY_INPUTS"
    elif score >= 80:
        data["computed_trust_state"] = "PASS_WITH_GAPS_REQUIRES_REVIEW"
    else:
        data["computed_trust_state"] = "NOT_READY_FOR_OPERATIONAL_APPROVAL"

    data["platform_rule"] = "Operational approval can be restored only after verified closure and recalculated operational trust."
    data["engineering_principle"] = "Trust is not restored by intent. Trust is restored only after verified closure, evidence update, replay readiness, monitoring readiness, and recalculated operational trust."
    return data


@app.route("/api/platform/ai-assurance-trust-recalculation/model/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_trust_recalculation_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_trust_recalculation()
    inputs = [_cobitchain_enrich_ai_assurance_trust_input(item) for item in payload.get("trust_inputs", [])]
    calc = _cobitchain_enrich_ai_assurance_trust_recalculation(payload.get("sample_recalculation", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in inputs]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Assurance Trust Recalculation Engine Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "depends_on": payload.get("depends_on", []),
        "trust_input_count": len(inputs),
        "average_trust_input_score": average,
        "trust_inputs": inputs,
        "sample_recalculation": calc
    })


@app.route("/api/platform/ai-assurance-trust-recalculation/input/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_trust_recalculation_input_demo_api():
    from flask import jsonify, request

    input_id = request.args.get("input_id", "human_approval_state")
    payload = _cobitchain_load_ai_assurance_trust_recalculation()
    items = payload.get("trust_inputs", []) or []

    for item in items:
        if item.get("input_id") == input_id:
            return jsonify(_cobitchain_enrich_ai_assurance_trust_input(item))

    return jsonify({
        "error": "trust_input_not_found",
        "message": f"No AI Assurance Trust Recalculation input found for input_id={input_id}",
        "available_input_ids": [item.get("input_id") for item in items]
    }), 404


@app.route("/api/platform/ai-assurance-trust-recalculation/recalculate/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_trust_recalculation_recalculate_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_assurance_trust_recalculation()
    return jsonify(_cobitchain_enrich_ai_assurance_trust_recalculation(payload.get("sample_recalculation", {})))


@app.route("/api/platform/ai-assurance-trust-recalculation/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_trust_recalculation_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_trust_recalculation()
    inputs = [_cobitchain_enrich_ai_assurance_trust_input(item) for item in payload.get("trust_inputs", [])]
    calc = _cobitchain_enrich_ai_assurance_trust_recalculation(payload.get("sample_recalculation", {}))

    blockers = [
        {
            "input_id": item.get("input_id"),
            "input_name": item.get("input_name"),
            "sample_state": item.get("sample_state"),
            "sample_score": item.get("sample_score"),
            "source_module": item.get("source_module"),
            "required_state": item.get("required_state")
        }
        for item in inputs
        if item.get("blocks_approval") is True and int(item.get("sample_score", 0) or 0) < 85
    ]

    return jsonify({
        "service": "COBIT-Chain AI Assurance Trust Recalculation Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_recalculation": calc,
        "blocking_trust_inputs": blockers,
        "required_next_steps": calc.get("required_next_steps", []),
        "engineering_principle": "Trust is not restored by intent. Trust is restored only after verified closure, evidence update, replay readiness, monitoring readiness, and recalculated operational trust."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ASSURANCE_TRUST_RECALCULATION_V1_ACTIVE
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

Path("platform_ai_assurance_trust_recalculation_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-assurance-trust-recalculation",
        "http://127.0.0.1:5000/platform/ai-trust-recalculation",
        "http://127.0.0.1:5000/platform/assurance-trust-recalculation",
        "http://127.0.0.1:5000/api/platform/ai-assurance-trust-recalculation/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-trust-recalculation/input/demo?input_id=human_approval_state",
        "http://127.0.0.1:5000/api/platform/ai-assurance-trust-recalculation/input/demo?input_id=evidence_contract_state",
        "http://127.0.0.1:5000/api/platform/ai-assurance-trust-recalculation/recalculate/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-trust-recalculation/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Assurance Trust Recalculation Engine installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
