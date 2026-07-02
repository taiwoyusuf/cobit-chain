from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_CLOUD_ASSURANCE_MATRIX_V1_ACTIVE"

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
    "/platform/cloud-assurance-matrix",
    "/platform/cloud-matrix",
    "/platform/cloud-agentic-assurance",
    "/cloud-assurance-matrix",
    "/api/platform/cloud-assurance/matrix/demo",
    "/api/platform/cloud-assurance/provider/demo"
]

for route in all_routes:
    if f'@app.route("{route}")' in text or f"@app.route('{route}')" in text:
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_CLOUD_ASSURANCE_MATRIX_V1_ACTIVE
# ============================================================

@app.route("/platform/cloud-assurance-matrix")
@app.route("/platform/cloud-matrix")
@app.route("/platform/cloud-agentic-assurance")
@app.route("/cloud-assurance-matrix")
def cobitchain_platform_cloud_assurance_matrix():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_cloud_assurance_matrix.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_cloud_assurance_matrix():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_cloud_assurance_matrix_seed.json")
    if not path.exists():
        return {"providers": [], "assurance_controls": []}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"providers": [], "assurance_controls": []}


def _cobitchain_enrich_cloud_provider(provider):
    import uuid
    from datetime import datetime, timezone

    data = dict(provider or {})
    focus = data.get("cobitchain_overlay_focus", []) or []

    base = 60
    base += min(25, len(focus) * 3)

    if data.get("provider_id") == "azure":
        base += 8

    score = max(0, min(100, base))

    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["assurance_fit_score"] = score
    data["cloud_role"] = "Execution stack"
    data["cobitchain_role"] = "Assurance Engineering overlay"
    data["platform_rule"] = "Cloud providers execute. COBIT-Chain helps prove operational trustworthiness."
    data["architecture_decision"] = "Do not build separate cloud products. Use one Azure-first platform with cloud-neutral assurance architecture."
    data["service_note"] = "Cloud Assurance Matrix strengthens existing Platform A/B architecture. It does not introduce a new foundational concept."
    return data


@app.route("/api/platform/cloud-assurance/matrix/demo", methods=["GET"])
def cobitchain_platform_cloud_assurance_matrix_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    matrix = _cobitchain_load_cloud_assurance_matrix()
    providers = [_cobitchain_enrich_cloud_provider(item) for item in matrix.get("providers", [])]
    controls = matrix.get("assurance_controls", []) or []

    return jsonify({
        "service": "COBIT-Chain Cloud Assurance Matrix Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cloud_layers": [
            "Agent Runtime and Orchestration",
            "Compute and Tool Execution",
            "Memory, State and Data",
            "Security, Governance and Observability"
        ],
        "platform_positioning": "Platform A is Azure-first. Platform B is cloud-neutral assurance evolution. Cloud providers execute. COBIT-Chain proves.",
        "provider_count": len(providers),
        "control_count": len(controls),
        "providers": providers,
        "assurance_controls": controls
    })


@app.route("/api/platform/cloud-assurance/provider/demo", methods=["GET"])
def cobitchain_platform_cloud_assurance_provider_demo_api():
    from flask import jsonify, request

    provider_id = request.args.get("provider_id", "azure")
    matrix = _cobitchain_load_cloud_assurance_matrix()
    providers = matrix.get("providers", []) or []

    for item in providers:
        if item.get("provider_id") == provider_id:
            return jsonify(_cobitchain_enrich_cloud_provider(item))

    return jsonify({
        "error": "provider_not_found",
        "message": f"No cloud provider found for provider_id={provider_id}",
        "available_provider_ids": [item.get("provider_id") for item in providers]
    }), 404

# ============================================================
# END COBITCHAIN_PLATFORM_CLOUD_ASSURANCE_MATRIX_V1_ACTIVE
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

Path("platform_cloud_assurance_matrix_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/cloud-assurance-matrix",
        "http://127.0.0.1:5000/platform/cloud-matrix",
        "http://127.0.0.1:5000/platform/cloud-agentic-assurance",
        "http://127.0.0.1:5000/api/platform/cloud-assurance/matrix/demo",
        "http://127.0.0.1:5000/api/platform/cloud-assurance/provider/demo?provider_id=azure"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Cloud Assurance Matrix installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
