from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AZURE_FOUNDRY_ASSURANCE_BLUEPRINT_V1_ACTIVE"

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
    "/platform/azure-foundry-assurance",
    "/platform/azure-foundry-blueprint",
    "/platform/foundry-assurance-blueprint",
    "/azure-foundry-assurance-blueprint",
    "/api/platform/azure-foundry/blueprint/demo",
    "/api/platform/azure-foundry/component/demo",
    "/api/platform/azure-foundry/readiness/demo"
]

for route in all_routes:
    if f'@app.route("{route}")' in text or f"@app.route('{route}')" in text:
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AZURE_FOUNDRY_ASSURANCE_BLUEPRINT_V1_ACTIVE
# ============================================================

@app.route("/platform/azure-foundry-assurance")
@app.route("/platform/azure-foundry-blueprint")
@app.route("/platform/foundry-assurance-blueprint")
@app.route("/azure-foundry-assurance-blueprint")
def cobitchain_platform_azure_foundry_assurance_blueprint():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_azure_foundry_assurance_blueprint.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_azure_foundry_assurance_blueprint():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_azure_foundry_assurance_seed.json")
    if not path.exists():
        return {"components": [], "assurance_controls": []}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"components": [], "assurance_controls": []}


def _cobitchain_enrich_azure_foundry_component(component):
    import uuid
    from datetime import datetime, timezone

    data = dict(component or {})
    score = int(data.get("readiness_score", 0) or 0)

    if score >= 85:
        band = "STRONG"
    elif score >= 75:
        band = "GOOD_WITH_INTEGRATION_GAPS"
    elif score >= 65:
        band = "CAUTION"
    else:
        band = "LIMITED"

    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["readiness_band"] = band
    data["azure_role"] = "Execution platform"
    data["cobitchain_role"] = "Assurance Engineering overlay"
    data["implementation_position"] = "Do not redesign COBIT-Chain around Azure. Integrate Azure AI Foundry capabilities into the existing Platform A architecture."
    data["platform_rule"] = "Azure provides the execution platform. COBIT-Chain provides the assurance overlay."
    data["service_note"] = "Azure Foundry Assurance Blueprint strengthens Platform A implementation and preserves Platform B cloud-neutral architecture."
    return data


@app.route("/api/platform/azure-foundry/blueprint/demo", methods=["GET"])
def cobitchain_platform_azure_foundry_blueprint_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    blueprint = _cobitchain_load_azure_foundry_assurance_blueprint()
    components = [_cobitchain_enrich_azure_foundry_component(item) for item in blueprint.get("components", [])]
    controls = blueprint.get("assurance_controls", []) or []

    scores = [int(item.get("readiness_score", 0) or 0) for item in components]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain Azure Foundry Assurance Blueprint Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "blueprint_name": blueprint.get("blueprint_name"),
        "platform_rule": blueprint.get("platform_rule"),
        "positioning": blueprint.get("positioning"),
        "component_count": len(components),
        "control_count": len(controls),
        "average_readiness_score": average,
        "components": components,
        "assurance_controls": controls
    })


@app.route("/api/platform/azure-foundry/component/demo", methods=["GET"])
def cobitchain_platform_azure_foundry_component_demo_api():
    from flask import jsonify, request

    component_id = request.args.get("component_id", "foundry_workspace")
    blueprint = _cobitchain_load_azure_foundry_assurance_blueprint()
    components = blueprint.get("components", []) or []

    for item in components:
        if item.get("component_id") == component_id:
            return jsonify(_cobitchain_enrich_azure_foundry_component(item))

    return jsonify({
        "error": "component_not_found",
        "message": f"No Azure Foundry component found for component_id={component_id}",
        "available_component_ids": [item.get("component_id") for item in components]
    }), 404


@app.route("/api/platform/azure-foundry/readiness/demo", methods=["GET"])
def cobitchain_platform_azure_foundry_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    blueprint = _cobitchain_load_azure_foundry_assurance_blueprint()
    components = [_cobitchain_enrich_azure_foundry_component(item) for item in blueprint.get("components", [])]

    scores = [int(item.get("readiness_score", 0) or 0) for item in components]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    weakest = sorted(
        [
            {
                "component_id": item.get("component_id"),
                "component_name": item.get("component_name"),
                "readiness_score": item.get("readiness_score"),
                "gaps_to_watch": item.get("gaps_to_watch", [])
            }
            for item in components
        ],
        key=lambda x: int(x.get("readiness_score", 0) or 0)
    )[:3]

    required_actions = [
        "Bind Foundry components to Evidence Vault packages.",
        "Connect MCP servers to Tool Call Evidence and Action Guard controls.",
        "Map monitoring traces to Observability and Audit Replay.",
        "Define human approval gates for regulated workflow actions.",
        "Preserve cloud-neutral assurance models while implementing Azure-first."
    ]

    return jsonify({
        "service": "COBIT-Chain Azure Foundry Assurance Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "average_readiness_score": average,
        "component_count": len(components),
        "weakest_components": weakest,
        "required_actions": required_actions,
        "platform_rule": "Azure provides the execution platform. COBIT-Chain provides the assurance overlay."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AZURE_FOUNDRY_ASSURANCE_BLUEPRINT_V1_ACTIVE
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

Path("platform_azure_foundry_assurance_blueprint_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/azure-foundry-assurance",
        "http://127.0.0.1:5000/platform/azure-foundry-blueprint",
        "http://127.0.0.1:5000/platform/foundry-assurance-blueprint",
        "http://127.0.0.1:5000/api/platform/azure-foundry/blueprint/demo",
        "http://127.0.0.1:5000/api/platform/azure-foundry/component/demo?component_id=mcp_servers",
        "http://127.0.0.1:5000/api/platform/azure-foundry/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Azure Foundry Assurance Blueprint installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
