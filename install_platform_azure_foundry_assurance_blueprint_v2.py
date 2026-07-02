from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

markers = [
    "COBITCHAIN_PLATFORM_AZURE_FOUNDRY_ASSURANCE_BLUEPRINT_V1_ACTIVE",
    "COBITCHAIN_PLATFORM_AZURE_FOUNDRY_ASSURANCE_BLUEPRINT_V2_ACTIVE"
]

for marker in markers:
    pattern = (
        r"\n?# ============================================================\n"
        r"# " + re.escape(marker) + r"\n"
        r"# ============================================================\n"
        r".*?"
        r"# ============================================================\n"
        r"# END " + re.escape(marker) + r"\n"
        r"# ============================================================\n?"
    )
    text = re.sub(pattern, "\n", text, flags=re.DOTALL)

MARKER = "COBITCHAIN_PLATFORM_AZURE_FOUNDRY_ASSURANCE_BLUEPRINT_V2_ACTIVE"

all_routes = [
    "/platform/azure-foundry-assurance",
    "/platform/azure-foundry-blueprint",
    "/platform/foundry-assurance-blueprint",
    "/azure-foundry-assurance-blueprint",
    "/api/platform/azure-foundry/blueprint/demo",
    "/api/platform/azure-foundry/component/demo",
    "/api/platform/azure-foundry/readiness/demo",
    "/api/platform/azure-foundry/lifecycle/demo",
    "/api/platform/azure-foundry/object/demo",
    "/api/platform/azure-foundry/objects/demo"
]

for route in all_routes:
    if f'@app.route("{route}")' in text or f"@app.route('{route}')" in text:
        raise SystemExit(f"Route already exists outside known Azure Foundry marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AZURE_FOUNDRY_ASSURANCE_BLUEPRINT_V2_ACTIVE
# ============================================================

@app.route("/platform/azure-foundry-assurance")
@app.route("/platform/azure-foundry-blueprint")
@app.route("/platform/foundry-assurance-blueprint")
@app.route("/azure-foundry-assurance-blueprint")
def cobitchain_platform_azure_foundry_assurance_blueprint_v2():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_azure_foundry_assurance_blueprint.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_azure_foundry_assurance_blueprint_v2():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_azure_foundry_assurance_seed.json")
    if not path.exists():
        return {"components": [], "lifecycle": [], "governed_objects": [], "assurance_controls": []}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"components": [], "lifecycle": [], "governed_objects": [], "assurance_controls": []}


def _cobitchain_readiness_band_v2(score):
    score = int(score or 0)
    if score >= 85:
        return "STRONG"
    if score >= 75:
        return "GOOD_WITH_EVIDENCE_GAPS"
    if score >= 65:
        return "CAUTION"
    return "LIMITED"


def _cobitchain_enrich_azure_foundry_component_v2(component):
    import uuid
    from datetime import datetime, timezone

    data = dict(component or {})
    score = int(data.get("readiness_score", 0) or 0)
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_band"] = _cobitchain_readiness_band_v2(score)
    data["azure_role"] = "Execution platform"
    data["cobitchain_role"] = "Assurance Engineering overlay"
    data["implementation_position"] = "Do not redesign COBIT-Chain around Azure. Treat Azure AI Foundry lifecycle elements as governed objects inside the existing Platform A architecture."
    data["platform_rule"] = "Azure provides the execution platform. COBIT-Chain provides the assurance overlay."
    data["service_note"] = "Azure Foundry Assurance Blueprint v2 strengthens Platform A by adding Prompt Governance, Model Abstraction, and lifecycle-governed objects."
    return data


def _cobitchain_enrich_azure_foundry_lifecycle_stage_v2(stage):
    import uuid
    from datetime import datetime, timezone

    data = dict(stage or {})
    score = int(data.get("readiness_score", 0) or 0)
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_band"] = _cobitchain_readiness_band_v2(score)
    data["platform_rule"] = "Design -> Develop -> Evaluate -> Govern -> Approve -> Deploy -> Monitor -> Continuously Assure must be governed inside Platform A."
    data["service_note"] = "Lifecycle stage is treated as a governed assurance boundary, not as a separate product module."
    return data


def _cobitchain_enrich_azure_foundry_governed_object_v2(obj):
    import uuid
    from datetime import datetime, timezone

    data = dict(obj or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["platform_rule"] = "Governed objects bind Azure Foundry execution to COBIT-Chain evidence, trust, review, and operational readiness."
    data["service_note"] = "This governed object can later connect to Evidence Vault, Operational Trust Twin, MCP Tool Registry, Observability, and Governance Vision."
    return data


@app.route("/api/platform/azure-foundry/blueprint/demo", methods=["GET"])
def cobitchain_platform_azure_foundry_blueprint_demo_api_v2():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    blueprint = _cobitchain_load_azure_foundry_assurance_blueprint_v2()
    components = [_cobitchain_enrich_azure_foundry_component_v2(item) for item in blueprint.get("components", [])]
    lifecycle = [_cobitchain_enrich_azure_foundry_lifecycle_stage_v2(item) for item in blueprint.get("lifecycle", [])]
    governed_objects = [_cobitchain_enrich_azure_foundry_governed_object_v2(item) for item in blueprint.get("governed_objects", [])]
    controls = blueprint.get("assurance_controls", []) or []

    scores = [int(item.get("readiness_score", 0) or 0) for item in components + lifecycle]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain Azure Foundry Assurance Blueprint v2 Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "blueprint_name": blueprint.get("blueprint_name"),
        "platform_rule": blueprint.get("platform_rule"),
        "positioning": blueprint.get("positioning"),
        "component_count": len(components),
        "lifecycle_stage_count": len(lifecycle),
        "governed_object_count": len(governed_objects),
        "control_count": len(controls),
        "average_readiness_score": average,
        "components": components,
        "lifecycle": lifecycle,
        "governed_objects": governed_objects,
        "assurance_controls": controls
    })


@app.route("/api/platform/azure-foundry/component/demo", methods=["GET"])
def cobitchain_platform_azure_foundry_component_demo_api_v2():
    from flask import jsonify, request

    component_id = request.args.get("component_id", "prompt_governance")
    blueprint = _cobitchain_load_azure_foundry_assurance_blueprint_v2()
    components = blueprint.get("components", []) or []

    for item in components:
        if item.get("component_id") == component_id:
            return jsonify(_cobitchain_enrich_azure_foundry_component_v2(item))

    return jsonify({
        "error": "component_not_found",
        "message": f"No Azure Foundry component found for component_id={component_id}",
        "available_component_ids": [item.get("component_id") for item in components]
    }), 404


@app.route("/api/platform/azure-foundry/lifecycle/demo", methods=["GET"])
def cobitchain_platform_azure_foundry_lifecycle_demo_api_v2():
    from flask import jsonify, request

    stage_id = request.args.get("stage_id", "")
    blueprint = _cobitchain_load_azure_foundry_assurance_blueprint_v2()
    lifecycle = blueprint.get("lifecycle", []) or []

    if stage_id:
        for item in lifecycle:
            if item.get("stage_id") == stage_id:
                return jsonify(_cobitchain_enrich_azure_foundry_lifecycle_stage_v2(item))
        return jsonify({
            "error": "lifecycle_stage_not_found",
            "message": f"No Azure Foundry lifecycle stage found for stage_id={stage_id}",
            "available_stage_ids": [item.get("stage_id") for item in lifecycle]
        }), 404

    return jsonify({
        "service": "COBIT-Chain Azure Foundry Lifecycle Demo",
        "count": len(lifecycle),
        "lifecycle": [_cobitchain_enrich_azure_foundry_lifecycle_stage_v2(item) for item in lifecycle]
    })


@app.route("/api/platform/azure-foundry/object/demo", methods=["GET"])
def cobitchain_platform_azure_foundry_object_demo_api_v2():
    from flask import jsonify, request

    object_id = request.args.get("object_id", "azf-prompt-version")
    blueprint = _cobitchain_load_azure_foundry_assurance_blueprint_v2()
    objects = blueprint.get("governed_objects", []) or []

    for item in objects:
        if item.get("object_id") == object_id:
            return jsonify(_cobitchain_enrich_azure_foundry_governed_object_v2(item))

    return jsonify({
        "error": "governed_object_not_found",
        "message": f"No Azure Foundry governed object found for object_id={object_id}",
        "available_object_ids": [item.get("object_id") for item in objects]
    }), 404


@app.route("/api/platform/azure-foundry/objects/demo", methods=["GET"])
def cobitchain_platform_azure_foundry_objects_demo_api_v2():
    from flask import jsonify

    blueprint = _cobitchain_load_azure_foundry_assurance_blueprint_v2()
    objects = blueprint.get("governed_objects", []) or []
    return jsonify({
        "service": "COBIT-Chain Azure Foundry Governed Objects Demo",
        "count": len(objects),
        "governed_objects": [_cobitchain_enrich_azure_foundry_governed_object_v2(item) for item in objects]
    })


@app.route("/api/platform/azure-foundry/readiness/demo", methods=["GET"])
def cobitchain_platform_azure_foundry_readiness_demo_api_v2():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    blueprint = _cobitchain_load_azure_foundry_assurance_blueprint_v2()
    components = [_cobitchain_enrich_azure_foundry_component_v2(item) for item in blueprint.get("components", [])]
    lifecycle = [_cobitchain_enrich_azure_foundry_lifecycle_stage_v2(item) for item in blueprint.get("lifecycle", [])]

    all_scored = components + lifecycle
    scores = [int(item.get("readiness_score", 0) or 0) for item in all_scored]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    weakest = sorted(
        [
            {
                "id": item.get("component_id") or item.get("stage_id"),
                "name": item.get("component_name") or item.get("stage_name"),
                "readiness_score": item.get("readiness_score"),
                "gaps_to_watch": item.get("gaps_to_watch", [])
            }
            for item in all_scored
        ],
        key=lambda x: int(x.get("readiness_score", 0) or 0)
    )[:5]

    required_actions = [
        "Treat Prompt Governance as a governed versioned object with owner, evaluation, approval, and rollback evidence.",
        "Treat Model Abstraction as a governed object with model version, selection rationale, approved use, fallback rule, and limitation evidence.",
        "Bind lifecycle stages to Evidence Vault packages.",
        "Connect MCP tool calls to Tool Call Evidence and Observability traces.",
        "Use Continuous Assurance to monitor trust score change, prompt drift, model change, outcome metrics, and audit replay."
    ]

    return jsonify({
        "service": "COBIT-Chain Azure Foundry Assurance Readiness v2 Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "average_readiness_score": average,
        "component_count": len(components),
        "lifecycle_stage_count": len(lifecycle),
        "weakest_items": weakest,
        "required_actions": required_actions,
        "platform_rule": "Azure provides the execution platform. COBIT-Chain provides the assurance overlay."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AZURE_FOUNDRY_ASSURANCE_BLUEPRINT_V2_ACTIVE
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

Path("platform_azure_foundry_assurance_blueprint_v2_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/azure-foundry-assurance",
        "http://127.0.0.1:5000/platform/azure-foundry-blueprint",
        "http://127.0.0.1:5000/platform/foundry-assurance-blueprint",
        "http://127.0.0.1:5000/api/platform/azure-foundry/blueprint/demo",
        "http://127.0.0.1:5000/api/platform/azure-foundry/component/demo?component_id=prompt_governance",
        "http://127.0.0.1:5000/api/platform/azure-foundry/component/demo?component_id=model_abstraction",
        "http://127.0.0.1:5000/api/platform/azure-foundry/lifecycle/demo?stage_id=evaluate",
        "http://127.0.0.1:5000/api/platform/azure-foundry/object/demo?object_id=azf-prompt-version",
        "http://127.0.0.1:5000/api/platform/azure-foundry/objects/demo",
        "http://127.0.0.1:5000/api/platform/azure-foundry/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Azure Foundry Assurance Blueprint v2 installed.")
print("Routes installed or refreshed:")
for route in all_routes:
    print("  " + route)
