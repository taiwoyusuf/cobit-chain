from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ARCHITECTURE_BOUNDARY_GATE_V1_ACTIVE"

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
    "/platform/ai-architecture-boundary-gate",
    "/platform/ai-boundary-gate",
    "/platform/architecture-boundary-gate",
    "/ai-architecture-boundary-gate",
    "/api/platform/ai-architecture-gate/model/demo",
    "/api/platform/ai-architecture-gate/policy/demo",
    "/api/platform/ai-architecture-gate/boundary/demo",
    "/api/platform/ai-architecture-gate/evaluate/demo",
    "/api/platform/ai-architecture-gate/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ARCHITECTURE_BOUNDARY_GATE_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-architecture-boundary-gate")
@app.route("/platform/ai-boundary-gate")
@app.route("/platform/architecture-boundary-gate")
@app.route("/ai-architecture-boundary-gate")
def cobitchain_platform_ai_architecture_boundary_gate():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_architecture_boundary_gate.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_architecture_boundary_gate():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_architecture_boundary_gate_seed.json")
    if not path.exists():
        return {"boundary_gates": [], "gate_policy": {}, "sample_gate_evaluation": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"boundary_gates": [], "gate_policy": {}, "sample_gate_evaluation": {}}


def _cobitchain_boundary_gate_status(score, policy):
    score = int(score or 0)
    block_below = int(policy.get("automatic_block_if_any_boundary_below", 60))
    hold_below = int(policy.get("automatic_hold_if_any_boundary_below", 75))
    pass_min = int(policy.get("minimum_boundary_score_for_approval", 80))

    if score < block_below:
        return "BLOCK"
    if score < hold_below:
        return "HOLD"
    if score < pass_min:
        return "PASS_WITH_GAPS"
    return "PASS"


def _cobitchain_enrich_boundary_gate(boundary, policy):
    import uuid
    from datetime import datetime, timezone

    data = dict(boundary or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["computed_gate_status"] = _cobitchain_boundary_gate_status(data.get("sample_score", 0), policy)
    data["platform_rule"] = "Every AI-enabled workflow should pass Knowledge, Tool, Autonomy, and Evidence boundary checks before operational approval."
    data["engineering_principle"] = "Modern AI systems combine knowledge, tools and autonomous decision making. Platform A should independently evaluate each assurance boundary before determining overall operational trust."
    return data


def _cobitchain_evaluate_architecture_gate(evaluation, policy):
    import uuid
    from datetime import datetime, timezone

    data = dict(evaluation or {})

    scores = [
        int(data.get("knowledge_score", 0) or 0),
        int(data.get("tool_score", 0) or 0),
        int(data.get("autonomy_score", 0) or 0),
        int(data.get("evidence_score", 0) or 0)
    ]

    overall = int(round(sum(scores) / len(scores), 0)) if scores else 0
    data["overall_score"] = overall

    min_overall = int(policy.get("minimum_overall_score_for_approval", 85))
    min_boundary = int(policy.get("minimum_boundary_score_for_approval", 80))
    hold_below = int(policy.get("automatic_hold_if_any_boundary_below", 75))
    block_below = int(policy.get("automatic_block_if_any_boundary_below", 60))

    if any(score < block_below for score in scores):
        gate_decision = "BLOCK_FOR_CRITICAL_BOUNDARY_FAILURE"
        approved = False
    elif any(score < hold_below for score in scores):
        gate_decision = "HOLD_FOR_BOUNDARY_REMEDIATION"
        approved = False
    elif overall < min_overall or any(score < min_boundary for score in scores):
        gate_decision = "PASS_WITH_GAPS_REQUIRES_REVIEW"
        approved = False
    else:
        gate_decision = "APPROVED_FOR_OPERATIONAL_USE"
        approved = True

    data["gate_decision"] = gate_decision
    data["approved_for_operational_use"] = approved
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["gate_policy"] = policy
    data["platform_rule"] = "Overall operational trust must be derived from independent Knowledge, Tool, Autonomy, and Evidence boundary gate results."
    data["engineering_principle"] = "Modern AI systems combine knowledge, tools and autonomous decision making. Platform A should independently evaluate each assurance boundary before determining overall operational trust."
    return data


@app.route("/api/platform/ai-architecture-gate/model/demo", methods=["GET"])
def cobitchain_platform_ai_architecture_gate_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_architecture_boundary_gate()
    policy = payload.get("gate_policy", {}) or {}
    boundaries = [_cobitchain_enrich_boundary_gate(item, policy) for item in payload.get("boundary_gates", [])]
    evaluation = _cobitchain_evaluate_architecture_gate(payload.get("sample_gate_evaluation", {}), policy)

    scores = [int(item.get("sample_score", 0) or 0) for item in boundaries]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Architecture Boundary Gate Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "gate_policy": policy,
        "boundary_count": len(boundaries),
        "average_boundary_score": average,
        "boundary_gates": boundaries,
        "sample_gate_evaluation": evaluation
    })


@app.route("/api/platform/ai-architecture-gate/policy/demo", methods=["GET"])
def cobitchain_platform_ai_architecture_gate_policy_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_architecture_boundary_gate()

    return jsonify({
        "service": "COBIT-Chain AI Architecture Boundary Gate Policy Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "gate_policy": payload.get("gate_policy", {}),
        "engineering_principle": payload.get("engineering_principle")
    })


@app.route("/api/platform/ai-architecture-gate/boundary/demo", methods=["GET"])
def cobitchain_platform_ai_architecture_gate_boundary_demo_api():
    from flask import jsonify, request

    boundary_id = request.args.get("boundary_id", "knowledge_assurance")
    payload = _cobitchain_load_ai_architecture_boundary_gate()
    policy = payload.get("gate_policy", {}) or {}
    boundaries = payload.get("boundary_gates", []) or []

    for item in boundaries:
        if item.get("boundary_id") == boundary_id:
            return jsonify(_cobitchain_enrich_boundary_gate(item, policy))

    return jsonify({
        "error": "boundary_not_found",
        "message": f"No AI Architecture Boundary Gate found for boundary_id={boundary_id}",
        "available_boundary_ids": [item.get("boundary_id") for item in boundaries]
    }), 404


@app.route("/api/platform/ai-architecture-gate/evaluate/demo", methods=["GET"])
def cobitchain_platform_ai_architecture_gate_evaluate_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_architecture_boundary_gate()
    return jsonify(_cobitchain_evaluate_architecture_gate(payload.get("sample_gate_evaluation", {}), payload.get("gate_policy", {}) or {}))


@app.route("/api/platform/ai-architecture-gate/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_architecture_gate_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_architecture_boundary_gate()
    policy = payload.get("gate_policy", {}) or {}
    boundaries = [_cobitchain_enrich_boundary_gate(item, policy) for item in payload.get("boundary_gates", [])]
    evaluation = _cobitchain_evaluate_architecture_gate(payload.get("sample_gate_evaluation", {}), policy)

    weakest = sorted(
        [
            {
                "boundary_id": item.get("boundary_id"),
                "boundary_name": item.get("boundary_name"),
                "score": item.get("sample_score"),
                "status": item.get("computed_gate_status"),
                "sample_gaps": item.get("sample_gaps", [])
            }
            for item in boundaries
        ],
        key=lambda x: int(x.get("score", 0) or 0)
    )

    return jsonify({
        "service": "COBIT-Chain AI Architecture Boundary Gate Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_gate_evaluation": evaluation,
        "weakest_boundaries": weakest,
        "required_actions": evaluation.get("required_actions", []),
        "engineering_principle": payload.get("engineering_principle")
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ARCHITECTURE_BOUNDARY_GATE_V1_ACTIVE
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

Path("platform_ai_architecture_boundary_gate_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-architecture-boundary-gate",
        "http://127.0.0.1:5000/platform/ai-boundary-gate",
        "http://127.0.0.1:5000/platform/architecture-boundary-gate",
        "http://127.0.0.1:5000/api/platform/ai-architecture-gate/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-architecture-gate/policy/demo",
        "http://127.0.0.1:5000/api/platform/ai-architecture-gate/boundary/demo?boundary_id=knowledge_assurance",
        "http://127.0.0.1:5000/api/platform/ai-architecture-gate/boundary/demo?boundary_id=tool_assurance",
        "http://127.0.0.1:5000/api/platform/ai-architecture-gate/boundary/demo?boundary_id=autonomy_assurance",
        "http://127.0.0.1:5000/api/platform/ai-architecture-gate/boundary/demo?boundary_id=evidence_assurance",
        "http://127.0.0.1:5000/api/platform/ai-architecture-gate/evaluate/demo",
        "http://127.0.0.1:5000/api/platform/ai-architecture-gate/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Architecture Boundary Gate API installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
