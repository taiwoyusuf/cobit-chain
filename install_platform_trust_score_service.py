from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_TRUST_SCORE_SERVICE_V1_ACTIVE"

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
    "/platform/trust-score-service",
    "/platform/trust-score",
    "/trust-score-service",
    "/cobitchain-trust-score-service",
    "/api/platform/trust-score/demo",
    "/api/platform/trust-state/demo"
]

for route in all_routes:
    if f'@app.route("{route}")' in text or f"@app.route('{route}')" in text:
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_TRUST_SCORE_SERVICE_V1_ACTIVE
# ============================================================

@app.route("/platform/trust-score-service")
@app.route("/platform/trust-score")
@app.route("/trust-score-service")
@app.route("/cobitchain-trust-score-service")
def cobitchain_platform_trust_score_service():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_trust_score_service.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_compute_demo_trust_score(payload):
    import uuid
    from datetime import datetime, timezone

    data = dict(payload or {})
    score = 100
    explanation = []

    def bool_value(name, default=False):
        return bool(data.get(name, default))

    owner_confirmed = bool_value("owner_confirmed")
    support_group_confirmed = bool_value("support_group_confirmed")
    access_model_confirmed = bool_value("access_model_confirmed")
    evidence_lineage = bool_value("evidence_lineage")
    mcp_replay_ready = bool_value("mcp_replay_ready")
    observability_ready = bool_value("observability_ready")

    try:
        evidence_freshness_days = int(data.get("evidence_freshness_days", 999))
    except Exception:
        evidence_freshness_days = 999

    try:
        open_critical_gaps = int(data.get("open_critical_gaps", 0))
    except Exception:
        open_critical_gaps = 0

    try:
        open_major_gaps = int(data.get("open_major_gaps", 0))
    except Exception:
        open_major_gaps = 0

    validation_state = str(data.get("validation_state", "unknown")).strip().lower()

    if owner_confirmed:
        explanation.append("Owner confirmed: no ownership penalty.")
    else:
        score -= 14
        explanation.append("Owner not confirmed: -14 trust points.")

    if support_group_confirmed:
        explanation.append("Support group confirmed: operational support is traceable.")
    else:
        score -= 12
        explanation.append("Support group not confirmed: -12 trust points.")

    if access_model_confirmed:
        explanation.append("Access model confirmed: access pathway is understood.")
    else:
        score -= 10
        explanation.append("Access model not confirmed: -10 trust points.")

    if evidence_lineage:
        explanation.append("Evidence lineage available: source basis is traceable.")
    else:
        score -= 14
        explanation.append("Evidence lineage missing: -14 trust points.")

    if evidence_freshness_days <= 30:
        explanation.append("Evidence is fresh within 30 days.")
    elif evidence_freshness_days <= 90:
        score -= 8
        explanation.append("Evidence is aging beyond 30 days: -8 trust points.")
    else:
        score -= 18
        explanation.append("Evidence is stale or missing beyond 90 days: -18 trust points.")

    if validation_state in ["validated", "operational_under_current_controls"]:
        explanation.append("Validation/control state supports operational use.")
    elif validation_state in ["qualified_not_validated", "qualified"]:
        score -= 8
        explanation.append("Qualified but not fully validated: -8 trust points.")
    elif validation_state in ["design_blueprint", "prototype"]:
        score -= 12
        explanation.append("Design/prototype state: -12 trust points.")
    else:
        score -= 16
        explanation.append("Unknown validation/control state: -16 trust points.")

    if open_critical_gaps > 0:
        penalty = min(45, open_critical_gaps * 25)
        score -= penalty
        explanation.append(f"Critical open gaps present: -{penalty} trust points.")
    else:
        explanation.append("No critical open gaps reported.")

    if open_major_gaps > 0:
        penalty = min(30, open_major_gaps * 8)
        score -= penalty
        explanation.append(f"Major open gaps present: -{penalty} trust points.")
    else:
        explanation.append("No major open gaps reported.")

    if mcp_replay_ready:
        explanation.append("MCP replay readiness present: AI tool outputs can be traced.")
    else:
        score -= 5
        explanation.append("MCP replay not ready: -5 trust points.")

    if observability_ready:
        explanation.append("Observability readiness present: telemetry can support replay.")
    else:
        score -= 5
        explanation.append("Observability not ready: -5 trust points.")

    score = max(0, min(100, score))

    if open_critical_gaps > 0:
        decision = "BLOCKED"
        recommended_action = "Resolve critical gaps before relying on this object for operational trust."
    elif score >= 85:
        decision = "READY"
        recommended_action = "Proceed with normal controls and preserve evidence replay."
    elif score >= 65:
        decision = "CAUTION"
        recommended_action = "Proceed only with documented limitations and close evidence gaps."
    elif score >= 40:
        decision = "LIMITED"
        recommended_action = "Use only for controlled demonstration or limited operational context."
    else:
        decision = "BLOCKED"
        recommended_action = "Do not rely on this object until ownership, evidence, and control gaps are resolved."

    if score >= 85 and evidence_lineage and evidence_freshness_days <= 30:
        confidence = "HIGH"
    elif score >= 65:
        confidence = "MEDIUM"
    elif score >= 40:
        confidence = "LOW"
    else:
        confidence = "VERY LOW"

    return {
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "object_id": data.get("object_id", "custom-object"),
        "object_name": data.get("object_name", data.get("object_id", "Custom Object")),
        "object_type": data.get("object_type", "trust_object"),
        "trust_score": score,
        "decision": decision,
        "confidence": confidence,
        "recommended_action": recommended_action,
        "explanation": explanation,
        "input_snapshot": data,
        "service_note": "Demo trust scoring logic. Future version should bind to Evidence Store, rule versioning, and audit replay."
    }


def _cobitchain_load_demo_trust_objects():
    import json
    from pathlib import Path

    seed_path = Path(__file__).with_name("platform_trust_score_seed_objects.json")
    if not seed_path.exists():
        return []

    data = json.loads(seed_path.read_text(encoding="utf-8"))
    return data.get("objects", [])


@app.route("/api/platform/trust-score/demo", methods=["GET", "POST"])
def cobitchain_platform_trust_score_demo_api():
    from flask import jsonify, request

    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        return jsonify(_cobitchain_compute_demo_trust_score(payload))

    object_id = request.args.get("object_id", "niagara-bms-supervisor")
    objects = _cobitchain_load_demo_trust_objects()

    for item in objects:
        if item.get("object_id") == object_id:
            return jsonify(_cobitchain_compute_demo_trust_score(item))

    return jsonify({
        "error": "object_not_found",
        "message": f"No demo trust object found for object_id={object_id}",
        "available_object_ids": [item.get("object_id") for item in objects]
    }), 404


@app.route("/api/platform/trust-state/demo", methods=["GET"])
def cobitchain_platform_trust_state_demo_api():
    from flask import jsonify

    objects = _cobitchain_load_demo_trust_objects()
    scored = [_cobitchain_compute_demo_trust_score(item) for item in objects]

    return jsonify({
        "service": "COBIT-Chain Platform Trust State Demo",
        "count": len(scored),
        "objects": scored
    })

# ============================================================
# END COBITCHAIN_PLATFORM_TRUST_SCORE_SERVICE_V1_ACTIVE
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

Path("platform_trust_score_service_installed_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/trust-score-service",
        "http://127.0.0.1:5000/platform/trust-score",
        "http://127.0.0.1:5000/api/platform/trust-score/demo?object_id=niagara-bms-supervisor",
        "http://127.0.0.1:5000/api/platform/trust-state/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Platform Trust Score Service installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
