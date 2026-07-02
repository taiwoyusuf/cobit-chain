from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_BLUEPRINT_LIBRARY_V1_ACTIVE"

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
    "/platform/blueprints",
    "/blueprints",
    "/platform/blueprints/ai-enabled-cmc",
    "/blueprints/ai-enabled-cmc",
    "/platform/blueprints/agentic-enterprise",
    "/blueprints/agentic-enterprise",
    "/api/platform/blueprints/model/demo",
    "/api/platform/blueprints/ai-enabled-cmc/demo",
    "/api/platform/blueprints/agentic-enterprise/demo",
    "/api/platform/blueprints/validation/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_BLUEPRINT_LIBRARY_V1_ACTIVE
# ============================================================

@app.route("/platform/blueprints")
@app.route("/blueprints")
def cobitchain_platform_blueprint_library():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_blueprint_library.html")
    return html_path.read_text(encoding="utf-8")


@app.route("/platform/blueprints/ai-enabled-cmc")
@app.route("/blueprints/ai-enabled-cmc")
def cobitchain_platform_ai_enabled_cmc_blueprint():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_enabled_cmc_blueprint.html")
    return html_path.read_text(encoding="utf-8")


@app.route("/platform/blueprints/agentic-enterprise")
@app.route("/blueprints/agentic-enterprise")
def cobitchain_platform_agentic_enterprise_blueprint():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_agentic_enterprise_blueprint.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_blueprint_library():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_blueprint_library_seed.json")
    if not path.exists():
        return {"blueprints": []}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"blueprints": []}


def _cobitchain_find_blueprint(blueprint_id):
    payload = _cobitchain_load_blueprint_library()
    for item in payload.get("blueprints", []) or []:
        if item.get("blueprint_id") == blueprint_id:
            return item
    return None


def _cobitchain_enrich_blueprint(blueprint):
    import uuid
    from datetime import datetime, timezone

    data = dict(blueprint or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["architecture_change"] = False
    data["new_platform_capability"] = False
    data["blueprint_layer_only"] = True
    data["implementation_rule"] = "Blueprint uses the existing lifecycle. No new foundational assurance module or architecture is created."
    data["lifecycle_stage_count"] = len(data.get("lifecycle", []) or [])
    data["question_count"] = len(data.get("questions_answered", []) or [])
    data["evidence_output_count"] = sum(len(stage.get("evidence_outputs", []) or []) for stage in data.get("lifecycle", []) or [])

    assessment = data.get("sample_blueprint_assessment", {}) or {}
    score = int(assessment.get("blueprint_score", 0) or 0)
    if score >= 85:
        data["computed_blueprint_state"] = "BLUEPRINT_APPLIED_EXISTING_LIFECYCLE_OPERATIONALLY_STRONG"
    elif score >= 70:
        data["computed_blueprint_state"] = "BLUEPRINT_APPLIED_EXISTING_LIFECYCLE_WITH_OPEN_EVIDENCE_GAPS"
    else:
        data["computed_blueprint_state"] = "BLUEPRINT_APPLICATION_REQUIRES_IMPLEMENTATION_HARDENING"

    return data


@app.route("/api/platform/blueprints/model/demo", methods=["GET"])
def cobitchain_platform_blueprint_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_blueprint_library()
    blueprints = [_cobitchain_enrich_blueprint(item) for item in payload.get("blueprints", []) or []]

    return jsonify({
        "service": "COBIT-Chain Platform Blueprint Library Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "capability_type": payload.get("capability_type"),
        "platform_rule": payload.get("platform_rule"),
        "engineering_principle": payload.get("engineering_principle"),
        "blueprint_count": len(blueprints),
        "architecture_change": False,
        "new_platform_capability": False,
        "blueprints": blueprints
    })


@app.route("/api/platform/blueprints/ai-enabled-cmc/demo", methods=["GET"])
def cobitchain_platform_ai_enabled_cmc_blueprint_demo_api():
    from flask import jsonify

    blueprint = _cobitchain_find_blueprint("ai_enabled_cmc")
    if not blueprint:
        return jsonify({"error": "ai_enabled_cmc_blueprint_not_found"}), 404

    return jsonify(_cobitchain_enrich_blueprint(blueprint))


@app.route("/api/platform/blueprints/agentic-enterprise/demo", methods=["GET"])
def cobitchain_platform_agentic_enterprise_blueprint_demo_api():
    from flask import jsonify

    blueprint = _cobitchain_find_blueprint("agentic_enterprise")
    if not blueprint:
        return jsonify({"error": "agentic_enterprise_blueprint_not_found"}), 404

    return jsonify(_cobitchain_enrich_blueprint(blueprint))


@app.route("/api/platform/blueprints/validation/demo", methods=["GET"])
def cobitchain_platform_blueprint_validation_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_blueprint_library()
    blueprints = [_cobitchain_enrich_blueprint(item) for item in payload.get("blueprints", []) or []]

    return jsonify({
        "service": "COBIT-Chain Blueprint Validation Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "validation_rule": "Blueprints validate and demonstrate the existing lifecycle. They do not create new architecture.",
        "architecture_change": False,
        "new_platform_capability": False,
        "blueprint_count": len(blueprints),
        "validated_blueprints": [
            {
                "blueprint_id": item.get("blueprint_id"),
                "blueprint_name": item.get("blueprint_name"),
                "blueprint_type": item.get("blueprint_type"),
                "uses_existing_lifecycle": item.get("uses_existing_lifecycle"),
                "no_new_architecture": item.get("no_new_architecture"),
                "computed_blueprint_state": item.get("computed_blueprint_state"),
                "route": item.get("route")
            }
            for item in blueprints
        ]
    })

# ============================================================
# END COBITCHAIN_PLATFORM_BLUEPRINT_LIBRARY_V1_ACTIVE
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

Path("platform_blueprint_library_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/blueprints",
        "http://127.0.0.1:5000/platform/blueprints/ai-enabled-cmc",
        "http://127.0.0.1:5000/platform/blueprints/agentic-enterprise",
        "http://127.0.0.1:5000/api/platform/blueprints/model/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/ai-enabled-cmc/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/agentic-enterprise/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/validation/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Platform Blueprint Library installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
