from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ASSURANCE_EVIDENCE_CONTRACT_V1_ACTIVE"

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
    "/platform/ai-assurance-evidence-contract",
    "/platform/ai-evidence-contract",
    "/platform/assurance-evidence-contract",
    "/ai-assurance-evidence-contract",
    "/api/platform/ai-assurance-evidence-contract/model/demo",
    "/api/platform/ai-assurance-evidence-contract/object/demo",
    "/api/platform/ai-assurance-evidence-contract/contract/demo",
    "/api/platform/ai-assurance-evidence-contract/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ASSURANCE_EVIDENCE_CONTRACT_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-assurance-evidence-contract")
@app.route("/platform/ai-evidence-contract")
@app.route("/platform/assurance-evidence-contract")
@app.route("/ai-assurance-evidence-contract")
def cobitchain_platform_ai_assurance_evidence_contract():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_assurance_evidence_contract.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_assurance_evidence_contract():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_assurance_evidence_contract_seed.json")
    if not path.exists():
        return {"evidence_objects": [], "sample_contract": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"evidence_objects": [], "sample_contract": {}}


def _cobitchain_enrich_ai_assurance_evidence_object(obj):
    import uuid
    from datetime import datetime, timezone

    data = dict(obj or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["platform_rule"] = "Every AI assurance decision must be supported by a standard evidence contract before operational trust can be claimed."
    data["engineering_principle"] = "An AI assurance decision is only defensible when its architecture boundary findings, controls, approvals, tool use, monitoring, outcomes, and regulatory context are bound into a replayable evidence contract."

    score = int(data.get("sample_score", 0) or 0)
    if score >= 85 and not data.get("missing_fields"):
        data["object_readiness"] = "COMPLETE"
    elif score >= 70:
        data["object_readiness"] = "PARTIAL"
    else:
        data["object_readiness"] = "INCOMPLETE"

    return data


def _cobitchain_enrich_ai_assurance_contract(contract):
    import uuid
    from datetime import datetime, timezone

    data = dict(contract or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("overall_evidence_score", 0) or 0)
    approved = bool(data.get("approved_for_operational_use", False))

    if approved and score >= 85:
        data["contract_state"] = "EVIDENCE_READY_FOR_OPERATIONAL_TRUST"
    elif score < 65:
        data["contract_state"] = "EVIDENCE_BLOCK"
    else:
        data["contract_state"] = "EVIDENCE_HOLD"

    data["platform_rule"] = "Operational trust requires replayable evidence, not just a dashboard score."
    data["engineering_principle"] = "An AI assurance decision is only defensible when its architecture boundary findings, controls, approvals, tool use, monitoring, outcomes, and regulatory context are bound into a replayable evidence contract."
    return data


@app.route("/api/platform/ai-assurance-evidence-contract/model/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_evidence_contract_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_evidence_contract()
    objects = [_cobitchain_enrich_ai_assurance_evidence_object(item) for item in payload.get("evidence_objects", [])]
    contract = _cobitchain_enrich_ai_assurance_contract(payload.get("sample_contract", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in objects]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Assurance Evidence Contract Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "depends_on": payload.get("depends_on", []),
        "evidence_object_count": len(objects),
        "average_object_score": average,
        "evidence_objects": objects,
        "sample_contract": contract
    })


@app.route("/api/platform/ai-assurance-evidence-contract/object/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_evidence_contract_object_demo_api():
    from flask import jsonify, request

    object_id = request.args.get("object_id", "tool_authorization_evidence")
    payload = _cobitchain_load_ai_assurance_evidence_contract()
    objects = payload.get("evidence_objects", []) or []

    for item in objects:
        if item.get("object_id") == object_id:
            return jsonify(_cobitchain_enrich_ai_assurance_evidence_object(item))

    return jsonify({
        "error": "object_not_found",
        "message": f"No AI Assurance Evidence Contract object found for object_id={object_id}",
        "available_object_ids": [item.get("object_id") for item in objects]
    }), 404


@app.route("/api/platform/ai-assurance-evidence-contract/contract/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_evidence_contract_contract_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_assurance_evidence_contract()
    return jsonify(_cobitchain_enrich_ai_assurance_contract(payload.get("sample_contract", {})))


@app.route("/api/platform/ai-assurance-evidence-contract/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_evidence_contract_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_evidence_contract()
    objects = [_cobitchain_enrich_ai_assurance_evidence_object(item) for item in payload.get("evidence_objects", [])]
    contract = _cobitchain_enrich_ai_assurance_contract(payload.get("sample_contract", {}))

    weakest = sorted(
        [
            {
                "object_id": item.get("object_id"),
                "object_name": item.get("object_name"),
                "sample_state": item.get("sample_state"),
                "sample_score": item.get("sample_score"),
                "missing_fields": item.get("missing_fields", [])
            }
            for item in objects
        ],
        key=lambda x: int(x.get("sample_score", 0) or 0)
    )[:6]

    return jsonify({
        "service": "COBIT-Chain AI Assurance Evidence Contract Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_contract": contract,
        "weakest_evidence_objects": weakest,
        "required_actions": contract.get("required_actions", []),
        "engineering_principle": "An AI assurance decision is only defensible when its architecture boundary findings, controls, approvals, tool use, monitoring, outcomes, and regulatory context are bound into a replayable evidence contract."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ASSURANCE_EVIDENCE_CONTRACT_V1_ACTIVE
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

Path("platform_ai_assurance_evidence_contract_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-assurance-evidence-contract",
        "http://127.0.0.1:5000/platform/ai-evidence-contract",
        "http://127.0.0.1:5000/platform/assurance-evidence-contract",
        "http://127.0.0.1:5000/api/platform/ai-assurance-evidence-contract/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-evidence-contract/object/demo?object_id=tool_authorization_evidence",
        "http://127.0.0.1:5000/api/platform/ai-assurance-evidence-contract/object/demo?object_id=human_approval_evidence",
        "http://127.0.0.1:5000/api/platform/ai-assurance-evidence-contract/contract/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-evidence-contract/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Assurance Evidence Contract installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
