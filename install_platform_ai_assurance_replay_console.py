from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_AI_ASSURANCE_REPLAY_CONSOLE_V1_ACTIVE"

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
    "/platform/ai-assurance-replay-console",
    "/platform/ai-assurance-replay",
    "/platform/ai-replay-console",
    "/ai-assurance-replay-console",
    "/api/platform/ai-assurance-replay/model/demo",
    "/api/platform/ai-assurance-replay/section/demo",
    "/api/platform/ai-assurance-replay/replay/demo",
    "/api/platform/ai-assurance-replay/readiness/demo"
]

for route in all_routes:
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    if re.search(pattern, text):
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_AI_ASSURANCE_REPLAY_CONSOLE_V1_ACTIVE
# ============================================================

@app.route("/platform/ai-assurance-replay-console")
@app.route("/platform/ai-assurance-replay")
@app.route("/platform/ai-replay-console")
@app.route("/ai-assurance-replay-console")
def cobitchain_platform_ai_assurance_replay_console():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ai_assurance_replay_console.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_ai_assurance_replay_console():
    import json
    from pathlib import Path

    path = Path(__file__).with_name("platform_ai_assurance_replay_console_seed.json")
    if not path.exists():
        return {"replay_sections": [], "sample_replay": {}}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"replay_sections": [], "sample_replay": {}}


def _cobitchain_enrich_ai_assurance_replay_section(section):
    import uuid
    from datetime import datetime, timezone

    data = dict(section or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["platform_rule"] = "Every AI assurance decision must be replayable from evidence, controls, approvals, runtime signals, and operational trust state."
    data["engineering_principle"] = "A trusted AI decision is not only approved; it must be replayable, explainable, evidence-linked, and defensible after the fact."
    return data


def _cobitchain_enrich_ai_assurance_replay(replay):
    import uuid
    from datetime import datetime, timezone

    data = dict(replay or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    score = int(data.get("replay_readiness_score", 0) or 0)
    replayable = bool(data.get("replayable_for_audit", False))

    if replayable and score >= 85:
        data["replay_state"] = "AUDIT_READY"
    elif score < 65:
        data["replay_state"] = "REPLAY_BLOCKED"
    else:
        data["replay_state"] = "REPLAY_INCOMPLETE"

    data["platform_rule"] = "AI assurance replay converts evidence contract records into audit-ready decision reconstruction."
    data["engineering_principle"] = "A trusted AI decision is not only approved; it must be replayable, explainable, evidence-linked, and defensible after the fact."
    return data


@app.route("/api/platform/ai-assurance-replay/model/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_replay_model_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_replay_console()
    sections = [_cobitchain_enrich_ai_assurance_replay_section(item) for item in payload.get("replay_sections", [])]
    replay = _cobitchain_enrich_ai_assurance_replay(payload.get("sample_replay", {}))

    scores = [int(item.get("sample_score", 0) or 0) for item in sections]
    average = round(sum(scores) / len(scores), 1) if scores else 0

    return jsonify({
        "service": "COBIT-Chain AI Assurance Replay Console Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capability_name": payload.get("capability_name"),
        "platform_rule": payload.get("platform_rule"),
        "platform_position": payload.get("platform_position"),
        "engineering_principle": payload.get("engineering_principle"),
        "depends_on": payload.get("depends_on", []),
        "replay_section_count": len(sections),
        "average_replay_section_score": average,
        "replay_sections": sections,
        "sample_replay": replay
    })


@app.route("/api/platform/ai-assurance-replay/section/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_replay_section_demo_api():
    from flask import jsonify, request

    section_id = request.args.get("section_id", "evidence_contract_replay")
    payload = _cobitchain_load_ai_assurance_replay_console()
    sections = payload.get("replay_sections", []) or []

    for item in sections:
        if item.get("section_id") == section_id:
            return jsonify(_cobitchain_enrich_ai_assurance_replay_section(item))

    return jsonify({
        "error": "section_not_found",
        "message": f"No AI Assurance Replay section found for section_id={section_id}",
        "available_section_ids": [item.get("section_id") for item in sections]
    }), 404


@app.route("/api/platform/ai-assurance-replay/replay/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_replay_replay_demo_api():
    from flask import jsonify

    payload = _cobitchain_load_ai_assurance_replay_console()
    return jsonify(_cobitchain_enrich_ai_assurance_replay(payload.get("sample_replay", {})))


@app.route("/api/platform/ai-assurance-replay/readiness/demo", methods=["GET"])
def cobitchain_platform_ai_assurance_replay_readiness_demo_api():
    from flask import jsonify
    import uuid
    from datetime import datetime, timezone

    payload = _cobitchain_load_ai_assurance_replay_console()
    sections = [_cobitchain_enrich_ai_assurance_replay_section(item) for item in payload.get("replay_sections", [])]
    replay = _cobitchain_enrich_ai_assurance_replay(payload.get("sample_replay", {}))

    weakest = sorted(
        [
            {
                "section_id": item.get("section_id"),
                "section_name": item.get("section_name"),
                "sample_state": item.get("sample_state"),
                "sample_score": item.get("sample_score"),
                "missing_evidence": item.get("missing_evidence", [])
            }
            for item in sections
        ],
        key=lambda x: int(x.get("sample_score", 0) or 0)
    )[:5]

    return jsonify({
        "service": "COBIT-Chain AI Assurance Replay Readiness Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_replay": replay,
        "weakest_replay_sections": weakest,
        "required_actions": replay.get("required_actions", []),
        "engineering_principle": "A trusted AI decision is not only approved; it must be replayable, explainable, evidence-linked, and defensible after the fact."
    })

# ============================================================
# END COBITCHAIN_PLATFORM_AI_ASSURANCE_REPLAY_CONSOLE_V1_ACTIVE
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

Path("platform_ai_assurance_replay_console_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/ai-assurance-replay-console",
        "http://127.0.0.1:5000/platform/ai-assurance-replay",
        "http://127.0.0.1:5000/platform/ai-replay-console",
        "http://127.0.0.1:5000/api/platform/ai-assurance-replay/model/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-replay/section/demo?section_id=evidence_contract_replay",
        "http://127.0.0.1:5000/api/platform/ai-assurance-replay/section/demo?section_id=human_approval_replay",
        "http://127.0.0.1:5000/api/platform/ai-assurance-replay/replay/demo",
        "http://127.0.0.1:5000/api/platform/ai-assurance-replay/readiness/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain AI Assurance Replay Console installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
