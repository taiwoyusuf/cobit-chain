from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ASSURANCE_KNOWLEDGE_REUSE_REGISTRY_V1_ACTIVE"

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
    "/platform/ai-assurance-knowledge-reuse",
    "/platform/ai-knowledge-reuse-registry",
    "/platform/assurance-knowledge-registry",
    "/ai-assurance-knowledge-reuse",
    "/api/platform/ai-knowledge-reuse/model/demo",
    "/api/platform/ai-knowledge-reuse/object/demo",
    "/api/platform/ai-knowledge-reuse/registry/demo",
    "/api/platform/ai-knowledge-reuse/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ASSURANCE_KNOWLEDGE_REUSE_REGISTRY_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-assurance-knowledge-reuse")
@app.route("/platform/ai-knowledge-reuse-registry")
@app.route("/platform/assurance-knowledge-registry")
@app.route("/ai-assurance-knowledge-reuse")
def cobitchain_platform_ai_assurance_knowledge_reuse_registry():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_assurance_knowledge_reuse_registry.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_assurance_knowledge_reuse_registry():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_assurance_knowledge_reuse_registry_seed.json")
    if not path.exists():
        return {"knowledge_objects": [], "sample_registry": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"knowledge_objects": [], "sample_registry": {}}


def _cobitchain_enrich_ai_knowledge_object(obj):
    import uuid
    from datetime import datetime, timezone

    data = dict(obj or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("sample_score", 0) or 0)
    approval = data.get("approval_state", "")

    if approval == "Approved" and score >= 85:
        data["computed_reuse_state"] = "APPROVED_FOR_GOVERNED_REUSE"
    elif approval in ["Open", "Incomplete", "Triggered"] or score < 70:
        data["computed_reuse_state"] = "REUSE_BLOCKED_PENDING_REMEDIATION"
    elif approval in ["Pending Approval", "Pending Review", "Review Required"]:
        data["computed_reuse_state"] = "REUSE_REQUIRES_APPROVAL"
    else:
        data["computed_reuse_state"] = "REUSE_REVIEW_REQUIRED"

    data["platform_rule"] = "Outcome learning can be reused only when converted into governed, versioned, evidence-linked, owner-approved knowledge objects."
    data["engineering_principle"] = "Organizational intelligence is not memory alone. It is reusable operational knowledge with owner, evidence, context, boundary, version, approval state, and traceable reuse conditions."
    return data


def _cobitchain_enrich_ai_knowledge_registry(registry):
    import uuid
    from datetime import datetime, timezone

    data = dict(registry or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("registry_score", 0) or 0)
    approved = bool(data.get("approved_for_reuse", False))
    approved_objects = int(data.get("approved_objects", 0) or 0)
    object_count = int(data.get("knowledge_object_count", 0) or 0)

    if approved and score >= 85 and approved_objects == object_count and object_count > 0:
        data["computed_registry_state"] = "REGISTRY_APPROVED_FOR_ORGANIZATIONAL_REUSE"
    elif score < 75 or approved_objects < object_count:
        data["computed_registry_state"] = "REGISTRY_NOT_READY_FOR_REUSE"
    else:
        data["computed_registry_state"] = "REGISTRY_REVIEW_REQUIRED"

    data["platform_rule"] = "Reusable knowledge must be owner-approved, evidence-bound, context-limited, and traceable."
    data["engineering_principle"] = "Organizational intelligence is not memory alone. It is reusable operational knowledge with owner, evidence, context, boundary, version, approval state, and traceable reuse conditions."
    return data


@app.route("/api/platform/ai-knowledge-reuse/model/demo", methods=["GET"])
def cobitchain_platform_ai_knowledge_reuse_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_knowledge_reuse_registry()
    objects = [_cobitchain_enrich_ai_knowledge_object(item) for item in payload.get("knowledge_objects", [])]
    registry = _cobitchain_enrich_ai_knowledge_registry(payload.get("sample_registry", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in objects]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Assurance Knowledge Reuse Registry Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "depends_on": payload.get("depends_on", []),
        "knowledge_object_count": len(objects),
        "average_object_score": average,
        "knowledge_objects": objects,
        "sample_registry": registry
    })


@app.route("/api/platform/ai-knowledge-reuse/object/demo", methods=["GET"])
def cobitchain_platform_ai_knowledge_reuse_object_demo_api():
    from flask import jsonify, request

    object_id = request.args.get("object_id", "ko_outcome_lesson_001")
    payload = _cobitchain_load_ai_assurance_knowledge_reuse_registry()
    objects = payload.get("knowledge_objects", []) or []

    for item in objects:
        if item.get("object_id") == object_id:
            return jsonify(_cobitchain_enrich_ai_knowledge_object(item))

    return jsonify({
        "error": "knowledge_object_not_found",
        "message": f"No AI Assurance Knowledge object found for object_id={object_id}",
        "available_object_ids": [item.get("object_id") for item in objects]
    }), 404


@app.route("/api/platform/ai-knowledge-reuse/registry/demo", methods=["GET"])
def cobitchain_platform_ai_knowledge_reuse_registry_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_assurance_knowledge_reuse_registry()
    return jsonify(_cobitchain_enrich_ai_knowledge_registry(payload.get("sample_registry", {})))


@app.route("/api/platform/ai-knowledge-reuse/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_knowledge_reuse_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_knowledge_reuse_registry()
    objects = [_cobitchain_enrich_ai_knowledge_object(item) for item in payload.get("knowledge_objects", [])]
    registry = _cobitchain_enrich_ai_knowledge_registry(payload.get("sample_registry", {}))

    blocked_objects = [
        {
            "object_id": item.get("object_id"),
            "object_name": item.get("object_name"),
            "approval_state": item.get("approval_state"),
            "sample_score": item.get("sample_score"),
            "computed_reuse_state": item.get("computed_reuse_state"),
            "owner_role": item.get("owner_role")
        }
        for item in objects
        if item.get("computed_reuse_state") != "APPROVED_FOR_GOVERNED_REUSE"
    ]

    return jsonify({
        "service": "COBIT-Chain AI Assurance Knowledge Reuse Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_registry": registry,
        "blocked_knowledge_objects": blocked_objects,
        "required_next_actions": registry.get("required_next_actions", []),
        "engineering_principle": "Organizational intelligence is not memory alone. It is reusable operational knowledge with owner, evidence, context, boundary, version, approval state, and traceable reuse conditions."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ASSURANCE_KNOWLEDGE_REUSE_REGISTRY_V1_ACTIVE
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

Path("platform_ai_assurance_knowledge_reuse_registry_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-assurance-knowledge-reuse",
        "http://127.0.0.1:5000/platform/ai-knowledge-reuse-registry",
        "http://127.0.0.1:5000/platform/assurance-knowledge-registry",
        "http://127.0.0.1:5000/api/platform/ai-knowledge-reuse/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-knowledge-reuse/object/demo?object_id=ko_outcome_lesson_001",
        "http://127.0.0.1:5000/api/platform/ai-knowledge-reuse/object/demo?object_id=ko_lifecycle_change_001",
        "http://127.0.0.1:5000/api/platform/ai-knowledge-reuse/registry/demo",
        "http://127.0.0.1:5000/api/platform/ai-knowledge-reuse/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Assurance Knowledge Reuse Registry installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
