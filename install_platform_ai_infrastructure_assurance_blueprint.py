from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_INFRASTRUCTURE_ASSURANCE_BLUEPRINT_V1_ACTIVE"

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
    "/platform/ai-infrastructure-assurance",
    "/platform/ai-infra-assurance",
    "/platform/infrastructure-assurance-blueprint",
    "/ai-infrastructure-assurance-blueprint",
    "/api/platform/ai-infrastructure/blueprint/demo",
    "/api/platform/ai-infrastructure/stage/demo",
    "/api/platform/ai-infrastructure/readiness/demo"
]

for route in all_routes:
    if f'@app.route("{route}")' in text or f"@app.route('{route}')" in text:
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_INFRASTRUCTURE_ASSURANCE_BLUEPRINT_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-infrastructure-assurance")
@app.route("/platform/ai-infra-assurance")
@app.route("/platform/infrastructure-assurance-blueprint")
@app.route("/ai-infrastructure-assurance-blueprint")
def cobitchain_platform_ai_infrastructure_assurance_blueprint():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_infrastructure_assurance_blueprint.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_infrastructure_assurance_blueprint():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_infrastructure_assurance_seed.json")
    if not path.exists():
        return {"stages": [], "assurance_controls": []}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"stages": [], "assurance_controls": []}


def _cobitchain_enrich_ai_infrastructure_stage(stage):
    import uuid
    from datetime import datetime, timezone

    data = dict(stage or {})
    score = int(data.get("readiness_score", 0) or 0)

    if score >= 85:
        band = "STRONG"
    elif score >= 75:
        band = "GOOD_WITH_REVIEW_GAPS"
    elif score >= 65:
        band = "CAUTION"
    else:
        band = "LIMITED"

    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_band"] = band
    data["azure_role"] = "Generate and deploy enterprise cloud architecture."
    data["cobitchain_role"] = "Evaluate operational trustworthiness before deployment."
    data["engineering_position"] = "Azure generates. COBIT-Chain evaluates. Azure deploys. COBIT-Chain provides evidence for trust."
    data["platform_rule"] = "Do not create a separate cloud architecture product. Strengthen existing Platform A modules."
    data["service_note"] = "AI Infrastructure Assurance Blueprint strengthens Platform A by applying existing Assurance Engineering controls to AI-generated infrastructure."
    return data


@app.route("/api/platform/ai-infrastructure/blueprint/demo", methods=["GET"])
def cobitchain_platform_ai_infrastructure_blueprint_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    blueprint = _cobitchain_load_ai_infrastructure_assurance_blueprint()
    stages = [_cobitchain_enrich_ai_infrastructure_stage(item) for item in blueprint.get("stages", [])]
    controls = blueprint.get("assurance_controls", []) or []

    scores = [int(item.get("readiness_score", 0) or 0) for item in stages]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Infrastructure Assurance Blueprint Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "blueprint_name": blueprint.get("blueprint_name"),
        "platform_rule": blueprint.get("platform_rule"),
        "positioning": blueprint.get("positioning"),
        "stage_count": len(stages),
        "control_count": len(controls),
        "average_readiness_score": average,
        "stages": stages,
        "assurance_controls": controls
    })


@app.route("/api/platform/ai-infrastructure/stage/demo", methods=["GET"])
def cobitchain_platform_ai_infrastructure_stage_demo_api():
    from flask import jsonify, request

    stage_id = request.args.get("stage_id", "business_intent")
    blueprint = _cobitchain_load_ai_infrastructure_assurance_blueprint()
    stages = blueprint.get("stages", []) or []

    for item in stages:
        if item.get("stage_id") == stage_id:
            return jsonify(_cobitchain_enrich_ai_infrastructure_stage(item))

    return jsonify({
        "error": "stage_not_found",
        "message": f"No AI infrastructure stage found for stage_id={stage_id}",
        "available_stage_ids": [item.get("stage_id") for item in stages]
    }), 404


@app.route("/api/platform/ai-infrastructure/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_infrastructure_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    blueprint = _cobitchain_load_ai_infrastructure_assurance_blueprint()
    stages = [_cobitchain_enrich_ai_infrastructure_stage(item) for item in blueprint.get("stages", [])]

    scores = [int(item.get("readiness_score", 0) or 0) for item in stages]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    weakest = sorted(
        [
            {
                "stage_id": item.get("stage_id"),
                "stage_name": item.get("stage_name"),
                "readiness_score": item.get("readiness_score"),
                "gaps_to_watch": item.get("gaps_to_watch", [])
            }
            for item in stages
        ],
        key=lambda x: int(x.get("readiness_score", 0) or 0)
    )[:3]

    required_actions = [
        "Bind AI-generated architecture recommendations to Evidence Vault packages.",
        "Require human architect review before deployment.",
        "Connect IaC outputs to Change Control and Deployment Pipeline evidence.",
        "Map policy and security validation to Operational Trust and Inspection Readiness.",
        "Connect operational monitoring to Observability and Audit Replay."
    ]

    return jsonify({
        "service": "COBIT-Chain AI Infrastructure Assurance Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "average_readiness_score": average,
        "stage_count": len(stages),
        "weakest_stages": weakest,
        "required_actions": required_actions,
        "platform_rule": "Azure generates. COBIT-Chain evaluates. Azure deploys. COBIT-Chain provides evidence for trust."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_INFRASTRUCTURE_ASSURANCE_BLUEPRINT_V1_ACTIVE
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

Path("platform_ai_infrastructure_assurance_blueprint_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-infrastructure-assurance",
        "http://127.0.0.1:5000/platform/ai-infra-assurance",
        "http://127.0.0.1:5000/platform/infrastructure-assurance-blueprint",
        "http://127.0.0.1:5000/api/platform/ai-infrastructure/blueprint/demo",
        "http://127.0.0.1:5000/api/platform/ai-infrastructure/stage/demo?stage_id=infrastructure_as_code",
        "http://127.0.0.1:5000/api/platform/ai-infrastructure/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Infrastructure Assurance Blueprint installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
