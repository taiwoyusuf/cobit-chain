from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_OPERATIONAL_TRUST_TWIN_V1_ACTIVE"

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
    "/platform/operational-trust-twin",
    "/platform/trust-twin",
    "/operational-trust-twin",
    "/cobitchain-operational-trust-twin",
    "/api/platform/twin/demo",
    "/api/platform/twin-state/demo"
]

for route in all_routes:
    if f'@app.route("{route}")' in text or f"@app.route('{route}')" in text:
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_OPERATIONAL_TRUST_TWIN_V1_ACTIVE
# ============================================================

@app.route("/platform/operational-trust-twin")
@app.route("/platform/trust-twin")
@app.route("/operational-trust-twin")
@app.route("/cobitchain-operational-trust-twin")
def cobitchain_platform_operational_trust_twin():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_operational_trust_twin.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_demo_twins():
    import json
    from pathlib import Path

    seed_path = Path(__file__).with_name("platform_operational_trust_twin_seed.json")
    if not seed_path.exists():
        return []

    data = json.loads(seed_path.read_text(encoding="utf-8"))
    return data.get("twins", [])


def _cobitchain_enrich_demo_twin(payload):
    import uuid
    from datetime import datetime, timezone

    data = dict(payload or {})
    score = int(data.get("trust_score", 0))
    gaps = data.get("active_gaps", []) or []
    dependencies = data.get("dependencies", []) or []

    if score >= 85 and len(gaps) == 0:
        twin_health = "strong"
    elif score >= 70:
        twin_health = "usable_with_caution"
    elif score >= 50:
        twin_health = "limited"
    else:
        twin_health = "weak_or_blocked"

    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["twin_health"] = twin_health
    data["gap_count"] = len(gaps)
    data["dependency_count"] = len(dependencies)
    data["service_note"] = "Demo operational trust twin. Future version should bind to Evidence Store, Trust Score Service, Observability, and MCP replay."
    return data


@app.route("/api/platform/twin/demo", methods=["GET"])
def cobitchain_platform_twin_demo_api():
    from flask import jsonify, request

    object_id = request.args.get("object_id", "niagara-bms-supervisor")
    twins = _cobitchain_load_demo_twins()

    for item in twins:
        if item.get("object_id") == object_id:
            return jsonify(_cobitchain_enrich_demo_twin(item))

    return jsonify({
        "error": "twin_not_found",
        "message": f"No demo operational trust twin found for object_id={object_id}",
        "available_object_ids": [item.get("object_id") for item in twins]
    }), 404


@app.route("/api/platform/twin-state/demo", methods=["GET"])
def cobitchain_platform_twin_state_demo_api():
    from flask import jsonify

    twins = _cobitchain_load_demo_twins()
    enriched = [_cobitchain_enrich_demo_twin(item) for item in twins]

    return jsonify({
        "service": "COBIT-Chain Operational Trust Twin Demo",
        "count": len(enriched),
        "twins": enriched
    })

# ============================================================
# END COBITCHAIN_PLATFORM_OPERATIONAL_TRUST_TWIN_V1_ACTIVE
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

Path("platform_operational_trust_twin_installed_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/operational-trust-twin",
        "http://127.0.0.1:5000/platform/trust-twin",
        "http://127.0.0.1:5000/api/platform/twin/demo?object_id=niagara-bms-supervisor",
        "http://127.0.0.1:5000/api/platform/twin-state/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Operational Trust Twin installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
