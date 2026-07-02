from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_GOVERNANCE_VISION_LOOKUP_SERVICE_V1_ACTIVE"

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
    "/platform/vision-lookup",
    "/platform/qr-lookup",
    "/governance-vision-lookup",
    "/cobitchain-vision-lookup",
    "/api/platform/vision/lookup/demo",
    "/api/platform/vision/hud/demo"
]

for route in all_routes:
    if f'@app.route("{route}")' in text or f"@app.route('{route}')" in text:
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_GOVERNANCE_VISION_LOOKUP_SERVICE_V1_ACTIVE
# ============================================================

@app.route("/platform/vision-lookup")
@app.route("/platform/qr-lookup")
@app.route("/governance-vision-lookup")
@app.route("/cobitchain-vision-lookup")
def cobitchain_platform_governance_vision_lookup_service():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_vision_lookup_service.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_demo_vision_assets():
    import json
    from pathlib import Path

    seed_path = Path(__file__).with_name("platform_vision_lookup_seed.json")
    if not seed_path.exists():
        return []

    data = json.loads(seed_path.read_text(encoding="utf-8"))
    return data.get("assets", [])


def _cobitchain_enrich_vision_asset(payload):
    import uuid
    from datetime import datetime, timezone

    data = dict(payload or {})
    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["action_mode"] = "READ_ONLY"
    data["record_modification_allowed"] = False
    data["approval_allowed"] = False
    data["hud_rule"] = "Show only status, trust score, confidence, evidence summary, limitations, and next action."
    data["service_note"] = "Demo Governance Vision lookup. Future version should bind to Trust Score Service, Operational Trust Twin, Evidence Store, Identity, and Observability."
    return data


def _cobitchain_find_vision_asset(asset_id):
    normalized = str(asset_id or "").strip().upper()
    assets = _cobitchain_load_demo_vision_assets()

    for item in assets:
        if str(item.get("asset_id", "")).strip().upper() == normalized:
            return item

    for item in assets:
        if str(item.get("object_id", "")).strip().upper() == normalized:
            return item

    return None


@app.route("/api/platform/vision/lookup/demo", methods=["GET"])
def cobitchain_platform_vision_lookup_demo_api():
    from flask import jsonify, request

    asset_id = request.args.get("asset_id", "NIAGARA-BMS-SUPERVISOR")
    item = _cobitchain_find_vision_asset(asset_id)

    if item:
        return jsonify(_cobitchain_enrich_vision_asset(item))

    assets = _cobitchain_load_demo_vision_assets()
    return jsonify({
        "error": "asset_not_found",
        "message": f"No demo Governance Vision asset found for asset_id={asset_id}",
        "available_asset_ids": [item.get("asset_id") for item in assets]
    }), 404


@app.route("/api/platform/vision/hud/demo", methods=["GET"])
def cobitchain_platform_vision_hud_demo_api():
    from flask import jsonify, request

    asset_id = request.args.get("asset_id", "NIAGARA-BMS-SUPERVISOR")
    item = _cobitchain_find_vision_asset(asset_id)

    if not item:
        assets = _cobitchain_load_demo_vision_assets()
        return jsonify({
            "error": "asset_not_found",
            "message": f"No demo Governance Vision asset found for asset_id={asset_id}",
            "available_asset_ids": [item.get("asset_id") for item in assets]
        }), 404

    enriched = _cobitchain_enrich_vision_asset(item)

    hud = {
        "request_id": enriched.get("request_id"),
        "generated_at_utc": enriched.get("generated_at_utc"),
        "asset_id": enriched.get("asset_id"),
        "object_name": enriched.get("object_name"),
        "status": enriched.get("status"),
        "trust_score": enriched.get("trust_score"),
        "confidence": enriched.get("confidence"),
        "evidence_confidence": enriched.get("evidence_confidence"),
        "evidence_summary": enriched.get("evidence_summary"),
        "next_action": enriched.get("next_action"),
        "limitations": enriched.get("limitations"),
        "privacy_mode": enriched.get("privacy_mode"),
        "action_mode": "READ_ONLY",
        "record_modification_allowed": False,
        "approval_allowed": False
    }

    return jsonify(hud)

# ============================================================
# END COBITCHAIN_PLATFORM_GOVERNANCE_VISION_LOOKUP_SERVICE_V1_ACTIVE
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

Path("platform_vision_lookup_service_installed_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/vision-lookup",
        "http://127.0.0.1:5000/platform/qr-lookup",
        "http://127.0.0.1:5000/api/platform/vision/lookup/demo?asset_id=NIAGARA-BMS-SUPERVISOR",
        "http://127.0.0.1:5000/api/platform/vision/hud/demo?asset_id=SPEEDY-GLOVE-1803"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Governance Vision Lookup Service installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
