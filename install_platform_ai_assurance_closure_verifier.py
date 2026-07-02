from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ASSURANCE_CLOSURE_VERIFIER_V1_ACTIVE"

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
    "/platform/ai-assurance-closure-verifier",
    "/platform/ai-closure-verifier",
    "/platform/assurance-closure-verifier",
    "/ai-assurance-closure-verifier",
    "/api/platform/ai-assurance-closure/model/demo",
    "/api/platform/ai-assurance-closure/item/demo",
    "/api/platform/ai-assurance-closure/verification/demo",
    "/api/platform/ai-assurance-closure/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ASSURANCE_CLOSURE_VERIFIER_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-assurance-closure-verifier")
@app.route("/platform/ai-closure-verifier")
@app.route("/platform/assurance-closure-verifier")
@app.route("/ai-assurance-closure-verifier")
def cobitchain_platform_ai_assurance_closure_verifier():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_assurance_closure_verifier.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_assurance_closure_verifier():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_assurance_closure_verifier_seed.json")
    if not path.exists():
        return {"closure_items": [], "sample_verification": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"closure_items": [], "sample_verification": {}}


def _cobitchain_enrich_ai_assurance_closure_item(item):
    import uuid
    from datetime import datetime, timezone

    data = dict(item or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["platform_rule"] = "AI remediation actions are not closed until closure evidence is verified and operational trust is recalculated."
    data["engineering_principle"] = "Closure is not a status label. Closure means the remediation is completed, evidence-bound, independently verified, and reflected in the final assurance decision."

    status = data.get("closure_status", "")
    blocks = bool(data.get("blocks_trust_recalculation", False))

    if status == "Verified Closed":
        data["closure_state"] = "VERIFIED_CLOSED"
    elif blocks and status in ["Open", "Pending Verification"]:
        data["closure_state"] = "BLOCKING_NOT_CLOSED"
    elif status == "Deferred":
        data["closure_state"] = "DEFERRED_NON_BLOCKING"
    else:
        data["closure_state"] = "IN_PROGRESS"

    return data


def _cobitchain_enrich_ai_assurance_closure_verification(verification):
    import uuid
    from datetime import datetime, timezone

    data = dict(verification or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    allowed = bool(data.get("trust_recalculation_allowed", False))
    blocking = int(data.get("blocking_open_items", 0) or 0)

    if allowed and blocking == 0:
        data["verification_state"] = "READY_FOR_TRUST_RECALCULATION"
    elif blocking > 0:
        data["verification_state"] = "TRUST_RECALCULATION_BLOCKED"
    else:
        data["verification_state"] = "CLOSURE_VERIFICATION_IN_PROGRESS"

    data["platform_rule"] = "Trust recalculation can occur only after blocking closure items are verified closed."
    data["engineering_principle"] = "Closure is not a status label. Closure means the remediation is completed, evidence-bound, independently verified, and reflected in the final assurance decision."
    return data


@app.route("/api/platform/ai-assurance-closure/model/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_closure_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_closure_verifier()
    items = [_cobitchain_enrich_ai_assurance_closure_item(item) for item in payload.get("closure_items", [])]
    verification = _cobitchain_enrich_ai_assurance_closure_verification(payload.get("sample_verification", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in items]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Assurance Closure Verifier Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "depends_on": payload.get("depends_on", []),
        "closure_item_count": len(items),
        "average_closure_item_score": average,
        "closure_items": items,
        "sample_verification": verification
    })


@app.route("/api/platform/ai-assurance-closure/item/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_closure_item_demo_api():
    from flask import jsonify, request

    closure_id = request.args.get("closure_id", "close_human_approval_evidence")
    payload = _cobitchain_load_ai_assurance_closure_verifier()
    items = payload.get("closure_items", []) or []

    for item in items:
        if item.get("closure_id") == closure_id:
            return jsonify(_cobitchain_enrich_ai_assurance_closure_item(item))

    return jsonify({
        "error": "closure_item_not_found",
        "message": f"No AI Assurance Closure item found for closure_id={closure_id}",
        "available_closure_ids": [item.get("closure_id") for item in items]
    }), 404


@app.route("/api/platform/ai-assurance-closure/verification/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_closure_verification_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_assurance_closure_verifier()
    return jsonify(_cobitchain_enrich_ai_assurance_closure_verification(payload.get("sample_verification", {})))


@app.route("/api/platform/ai-assurance-closure/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_closure_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_closure_verifier()
    items = [_cobitchain_enrich_ai_assurance_closure_item(item) for item in payload.get("closure_items", [])]
    verification = _cobitchain_enrich_ai_assurance_closure_verification(payload.get("sample_verification", {}))

    blocking = [
        {
            "closure_id": item.get("closure_id"),
            "closure_name": item.get("closure_name"),
            "closure_status": item.get("closure_status"),
            "owner_role": item.get("owner_role"),
            "verification_role": item.get("verification_role"),
            "required_closure_evidence": item.get("required_closure_evidence", [])
        }
        for item in items
        if item.get("blocks_trust_recalculation") is True and item.get("closure_status") != "Verified Closed"
    ]

    return jsonify({
        "service": "COBIT-Chain AI Assurance Closure Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_verification": verification,
        "blocking_closure_items": blocking,
        "required_next_steps": verification.get("required_next_steps", []),
        "engineering_principle": "Closure is not a status label. Closure means the remediation is completed, evidence-bound, independently verified, and reflected in the final assurance decision."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ASSURANCE_CLOSURE_VERIFIER_V1_ACTIVE
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

Path("platform_ai_assurance_closure_verifier_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-assurance-closure-verifier",
        "http://127.0.0.1:5000/platform/ai-closure-verifier",
        "http://127.0.0.1:5000/platform/assurance-closure-verifier",
        "http://127.0.0.1:5000/api/platform/ai-assurance-closure/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-closure/item/demo?closure_id=close_human_approval_evidence",
        "http://127.0.0.1:5000/api/platform/ai-assurance-closure/item/demo?closure_id=close_runtime_monitoring_signal",
        "http://127.0.0.1:5000/api/platform/ai-assurance-closure/verification/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-closure/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Assurance Closure Verifier installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
