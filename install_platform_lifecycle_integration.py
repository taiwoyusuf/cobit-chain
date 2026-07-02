from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_LIFECYCLE_INTEGRATION_ENGINE_V1_ACTIVE"

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
    "/platform/lifecycle-integration",
    "/platform/end-to-end-assurance",
    "/platform/assurance-lifecycle-workflow",
    "/platform/integration-layer",
    "/api/platform/lifecycle-integration/model/demo",
    "/api/platform/lifecycle-integration/workflow/demo",
    "/api/platform/lifecycle-integration/stage/demo",
    "/api/platform/lifecycle-integration/assessment/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_LIFECYCLE_INTEGRATION_ENGINE_V1_ACTIVE
# ============================================================

@app.route("/platform/lifecycle-integration")
@app.route("/platform/end-to-end-assurance")
@app.route("/platform/assurance-lifecycle-workflow")
@app.route("/platform/integration-layer")
def cobitchain_platform_lifecycle_integration():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_lifecycle_integration.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_lifecycle_integration():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_lifecycle_integration_seed.json")
    if not path.exists():
        return {"integration_flow": [], "sample_integration_assessment": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"integration_flow": [], "sample_integration_assessment": {}}


def _cobitchain_current_route_rules():
    try:
        return set(str(rule.rule) for rule in app.url_map.iter_rules())
    except Exception:
        return set()


def _cobitchain_enrich_lifecycle_stage(stage):
    import uuid
    from datetime import datetime, timezone

    data = dict(stage or {})
    rules = _cobitchain_current_route_rules()
    candidates = [data.get("primary_route")] + list(data.get("alternative_routes", []) or [])
    candidates = [item for item in candidates if item]

    active_route = None
    for route in candidates:
        if route in rules:
            active_route = route
            break

    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["route_active"] = active_route is not None
    data["active_route"] = active_route
    data["candidate_routes_checked"] = candidates

    if data["route_active"]:
        data["implementation_state"] = "LIFECYCLE_STAGE_ROUTE_ACTIVE"
        data["next_integration_action"] = "Connect this stage to shared evidence IDs, upstream/downstream API calls, and lifecycle progress state."
    else:
        data["implementation_state"] = "LIFECYCLE_STAGE_IMPLEMENTATION_GAP"
        data["next_integration_action"] = "Create executable page and APIs only if this stage extends the existing lifecycle and is needed for implementation."

    return data


def _cobitchain_lifecycle_workflow_payload():
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_lifecycle_integration()
    stages = [_cobitchain_enrich_lifecycle_stage(item) for item in payload.get("integration_flow", [])]
    active = [item for item in stages if item.get("route_active")]
    missing = [item for item in stages if not item.get("route_active")]

    return {
        "service": "COBIT-Chain Platform Lifecycle Integration Engine Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "capability_type": payload.get("capability_type"),
        "platform_rule": payload.get("platform_rule"),
        "engineering_question": payload.get("engineering_question"),
        "engineering_principle": payload.get("engineering_principle"),
        "total_stage_count": len(stages),
        "active_route_count": len(active),
        "implementation_gap_count": len(missing),
        "implementation_gaps": [item.get("stage_name") for item in missing],
        "integration_flow": stages
    }


@app.route("/api/platform/lifecycle-integration/model/demo", methods=["GET"])
def cobitchain_platform_lifecycle_integration_model_demo_api():
    from flask import jsonify

    workflow = _cobitchain_lifecycle_workflow_payload()
    payload = _cobitchain_load_lifecycle_integration()
    workflow["sample_integration_assessment"] = payload.get("sample_integration_assessment", {})
    return jsonify(workflow)


@app.route("/api/platform/lifecycle-integration/workflow/demo", methods=["GET"])
def cobitchain_platform_lifecycle_integration_workflow_demo_api():
    from flask import jsonify

    return jsonify(_cobitchain_lifecycle_workflow_payload())


@app.route("/api/platform/lifecycle-integration/stage/demo", methods=["GET"])
def cobitchain_platform_lifecycle_integration_stage_demo_api():
    from flask import jsonify, request

    stage_id = request.args.get("stage_id", "workflow_intake")
    payload = _cobitchain_load_lifecycle_integration()
    stages = payload.get("integration_flow", []) or []

    for item in stages:
        if item.get("stage_id") == stage_id:
            return jsonify(_cobitchain_enrich_lifecycle_stage(item))

    return jsonify({
        "error": "lifecycle_stage_not_found",
        "message": f"No lifecycle integration stage found for stage_id={stage_id}",
        "available_stage_ids": [item.get("stage_id") for item in stages]
    }), 404


@app.route("/api/platform/lifecycle-integration/assessment/demo", methods=["GET"])
def cobitchain_platform_lifecycle_integration_assessment_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    workflow = _cobitchain_lifecycle_workflow_payload()
    payload = _cobitchain_load_lifecycle_integration()
    assessment = dict(payload.get("sample_integration_assessment", {}) or {})

    total = int(workflow.get("total_stage_count", 0) or 0)
    active = int(workflow.get("active_route_count", 0) or 0)
    coverage = round((active / total) * 100, 1) if total else 0

    score = int(assessment.get("integration_score", 0) or 0)
    if coverage >= 90 and score >= 85:
        computed_state = "LIFECYCLE_INTEGRATED_AND_EXECUTION_READY"
    elif coverage >= 60:
        computed_state = "LIFECYCLE_PARTIALLY_INTEGRATED_IMPLEMENTATION_GAPS_OPEN"
    else:
        computed_state = "LIFECYCLE_INTEGRATION_FOUNDATION_READY_BUT_EXECUTION_GAPS_HIGH"

    assessment["request_id"] = str(uuid.uuid4())
    assessment["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    assessment["total_stage_count"] = total
    assessment["active_route_count"] = active
    assessment["route_coverage_percent"] = coverage
    assessment["implementation_gaps"] = workflow.get("implementation_gaps", [])
    assessment["computed_integration_state"] = computed_state
    assessment["platform_rule"] = payload.get("platform_rule")
    assessment["engineering_principle"] = payload.get("engineering_principle")
    return jsonify(assessment)

# ============================================================
# END COBITCHAIN_PLATFORM_LIFECYCLE_INTEGRATION_ENGINE_V1_ACTIVE
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

Path("platform_lifecycle_integration_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/lifecycle-integration",
        "http://127.0.0.1:5000/platform/end-to-end-assurance",
        "http://127.0.0.1:5000/platform/assurance-lifecycle-workflow",
        "http://127.0.0.1:5000/platform/integration-layer",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/model/demo",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/workflow/demo",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/stage/demo?stage_id=intelligence_validation",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/assessment/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Platform Lifecycle Integration Engine installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
