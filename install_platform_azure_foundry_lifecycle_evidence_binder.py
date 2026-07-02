from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AZURE_FOUNDRY_LIFECYCLE_EVIDENCE_BINDER_V1_ACTIVE"

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
    "/platform/azure-foundry-evidence-binder",
    "/platform/foundry-lifecycle-evidence",
    "/platform/azure-foundry-lifecycle-evidence",
    "/azure-foundry-evidence-binder",
    "/api/platform/azure-foundry/evidence-bindings/demo",
    "/api/platform/azure-foundry/evidence-binding/demo",
    "/api/platform/azure-foundry/evidence-readiness/demo"
]

for route in all_routes:
    if f'@app.route("{route}")' in text or f"@app.route('{route}')" in text:
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AZURE_FOUNDRY_LIFECYCLE_EVIDENCE_BINDER_V1_ACTIVE
# ============================================================

@app.route("/platform/azure-foundry-evidence-binder")
@app.route("/platform/foundry-lifecycle-evidence")
@app.route("/platform/azure-foundry-lifecycle-evidence")
@app.route("/azure-foundry-evidence-binder")
def cobitchain_platform_azure_foundry_lifecycle_evidence_binder():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_azure_foundry_lifecycle_evidence_binder.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_azure_foundry_lifecycle_evidence_binder():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_azure_foundry_lifecycle_evidence_seed.json")
    if not path.exists():
        return {"lifecycle_evidence_bindings": [], "evidence_controls": []}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"lifecycle_evidence_bindings": [], "evidence_controls": []}


def _cobitchain_enrich_azure_foundry_evidence_binding(binding):
    import uuid
    from datetime import datetime, timezone

    data = dict(binding or {})
    required = data.get("required_evidence", []) or []
    available = data.get("available_evidence", []) or []
    missing = data.get("missing_evidence", []) or []
    score = int(data.get("trust_score", 0) or 0)

    if score >= 85 and not missing:
        readiness = "READY"
    elif score >= 80:
        readiness = "GOOD_WITH_MINOR_GAPS"
    elif score >= 70:
        readiness = "CAUTION_EVIDENCE_GAPS"
    else:
        readiness = "LIMITED"

    coverage = round((len(available) / len(required)) * 100, 1) if required else 0

    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["evidence_coverage_percent"] = coverage
    data["missing_evidence_count"] = len(missing)
    data["readiness_state"] = readiness
    data["platform_rule"] = "Azure executes the AI lifecycle. COBIT-Chain binds each lifecycle stage to evidence required for operational trust."
    data["service_note"] = "This is an Azure Foundry Assurance Blueprint v2 enhancement, not a new foundational module."
    return data


@app.route("/api/platform/azure-foundry/evidence-bindings/demo", methods=["GET"])
def cobitchain_platform_azure_foundry_evidence_bindings_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    binder = _cobitchain_load_azure_foundry_lifecycle_evidence_binder()
    bindings = [_cobitchain_enrich_azure_foundry_evidence_binding(item) for item in binder.get("lifecycle_evidence_bindings", [])]
    scores = [int(item.get("trust_score", 0) or 0) for item in bindings]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain Azure Foundry Lifecycle Evidence Binder Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "binder_name": binder.get("binder_name"),
        "platform_rule": binder.get("platform_rule"),
        "positioning": binder.get("positioning"),
        "binding_count": len(bindings),
        "average_trust_score": average,
        "evidence_controls": binder.get("evidence_controls", []),
        "lifecycle_evidence_bindings": bindings
    })


@app.route("/api/platform/azure-foundry/evidence-binding/demo", methods=["GET"])
def cobitchain_platform_azure_foundry_evidence_binding_demo_api():
    from flask import jsonify, request

    stage_id = request.args.get("stage_id", "develop")
    binder = _cobitchain_load_azure_foundry_lifecycle_evidence_binder()
    bindings = binder.get("lifecycle_evidence_bindings", []) or []

    for item in bindings:
        if item.get("stage_id") == stage_id or item.get("binding_id") == stage_id:
            return jsonify(_cobitchain_enrich_azure_foundry_evidence_binding(item))

    return jsonify({
        "error": "evidence_binding_not_found",
        "message": f"No Azure Foundry lifecycle evidence binding found for stage_id={stage_id}",
        "available_stage_ids": [item.get("stage_id") for item in bindings]
    }), 404


@app.route("/api/platform/azure-foundry/evidence-readiness/demo", methods=["GET"])
def cobitchain_platform_azure_foundry_evidence_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    binder = _cobitchain_load_azure_foundry_lifecycle_evidence_binder()
    bindings = [_cobitchain_enrich_azure_foundry_evidence_binding(item) for item in binder.get("lifecycle_evidence_bindings", [])]

    scores = [int(item.get("trust_score", 0) or 0) for item in bindings]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    weakest = sorted(
        [
            {
                "stage_id": item.get("stage_id"),
                "stage_name": item.get("stage_name"),
                "trust_score": item.get("trust_score"),
                "missing_evidence": item.get("missing_evidence", []),
                "evidence_coverage_percent": item.get("evidence_coverage_percent")
            }
            for item in bindings
        ],
        key=lambda x: int(x.get("trust_score", 0) or 0)
    )[:4]

    required_actions = [
        "Bind Design stage to workflow boundary and data source inventory evidence.",
        "Bind Develop stage to prompt owner, tool schema, and retrieval configuration evidence.",
        "Bind Evaluate stage to grounding evidence, failure cases, and reviewer notes.",
        "Bind Monitor stage to tool-call records, quality metrics, and incident signals.",
        "Bind Continuously Assure stage to prompt drift, model change, and audit replay evidence."
    ]

    return jsonify({
        "service": "COBIT-Chain Azure Foundry Lifecycle Evidence Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "average_trust_score": average,
        "binding_count": len(bindings),
        "weakest_bindings": weakest,
        "required_actions": required_actions,
        "platform_rule": "Azure executes the AI lifecycle. COBIT-Chain binds each lifecycle stage to evidence required for operational trust."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AZURE_FOUNDRY_LIFECYCLE_EVIDENCE_BINDER_V1_ACTIVE
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

Path("platform_azure_foundry_lifecycle_evidence_binder_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/azure-foundry-evidence-binder",
        "http://127.0.0.1:5000/platform/foundry-lifecycle-evidence",
        "http://127.0.0.1:5000/platform/azure-foundry-lifecycle-evidence",
        "http://127.0.0.1:5000/api/platform/azure-foundry/evidence-bindings/demo",
        "http://127.0.0.1:5000/api/platform/azure-foundry/evidence-binding/demo?stage_id=develop",
        "http://127.0.0.1:5000/api/platform/azure-foundry/evidence-readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Azure Foundry Lifecycle Evidence Binder installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
