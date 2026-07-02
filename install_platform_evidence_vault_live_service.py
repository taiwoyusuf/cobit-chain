from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_EVIDENCE_VAULT_LIVE_SERVICE_V1_ACTIVE"

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
    "/platform/evidence-packages",
    "/platform/evidence-vault-live",
    "/evidence-packages",
    "/cobitchain-evidence-packages",
    "/api/platform/evidence/package/demo",
    "/api/platform/evidence/object/demo",
    "/api/platform/evidence/state/demo"
]

for route in all_routes:
    if f'@app.route("{route}")' in text or f"@app.route('{route}')" in text:
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_EVIDENCE_VAULT_LIVE_SERVICE_V1_ACTIVE
# ============================================================

@app.route("/platform/evidence-packages")
@app.route("/platform/evidence-vault-live")
@app.route("/evidence-packages")
@app.route("/cobitchain-evidence-packages")
def cobitchain_platform_evidence_vault_live_service():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_evidence_vault_live_service.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_load_demo_evidence_packages():
    import json
    from pathlib import Path

    seed_path = Path(__file__).with_name("platform_evidence_vault_seed_packages.json")
    if not seed_path.exists():
        return []

    data = json.loads(seed_path.read_text(encoding="utf-8"))
    return data.get("packages", [])


def _cobitchain_enrich_evidence_package(payload):
    import uuid
    from datetime import datetime, timezone

    data = dict(payload or {})
    records = data.get("evidence_records", []) or []
    gaps = data.get("open_gaps", []) or []

    available_records = 0
    gap_records = 0

    for record in records:
        status = str(record.get("status", "")).lower()
        if status == "available":
            available_records += 1
        if status == "gap":
            gap_records += 1

    total_records = max(1, len(records))
    base_quality = int((available_records / total_records) * 100)

    try:
        freshness_days = int(data.get("freshness_days", 999))
    except Exception:
        freshness_days = 999

    freshness_penalty = 0
    if freshness_days > 90:
        freshness_penalty = 20
    elif freshness_days > 30:
        freshness_penalty = 10

    gap_penalty = min(35, len(gaps) * 7)
    record_gap_penalty = min(25, gap_records * 8)

    package_quality_score = max(0, min(100, base_quality - freshness_penalty - gap_penalty - record_gap_penalty + 20))

    if package_quality_score >= 85:
        package_confidence = "HIGH"
    elif package_quality_score >= 65:
        package_confidence = "MEDIUM"
    elif package_quality_score >= 40:
        package_confidence = "LOW"
    else:
        package_confidence = "VERY LOW"

    data["request_id"] = str(uuid.uuid4())
    data["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["record_count"] = len(records)
    data["available_record_count"] = available_records
    data["gap_record_count"] = gap_records
    data["open_gap_count"] = len(gaps)
    data["package_quality_score"] = package_quality_score
    data["package_confidence"] = package_confidence
    data["replay_ready"] = package_quality_score >= 65 and available_records > 0
    data["service_note"] = "Demo evidence package service. Future version should bind to Blob Storage, Cosmos DB, Azure AI Search, Trust Score, Operational Twin, MCP, and audit replay."
    return data


@app.route("/api/platform/evidence/package/demo", methods=["GET"])
def cobitchain_platform_evidence_package_demo_api():
    from flask import jsonify, request

    package_id = request.args.get("package_id", "EVP-NIAGARA-READINESS-001")
    packages = _cobitchain_load_demo_evidence_packages()

    for item in packages:
        if item.get("package_id") == package_id:
            return jsonify(_cobitchain_enrich_evidence_package(item))

    return jsonify({
        "error": "package_not_found",
        "message": f"No demo evidence package found for package_id={package_id}",
        "available_package_ids": [item.get("package_id") for item in packages]
    }), 404


@app.route("/api/platform/evidence/object/demo", methods=["GET"])
def cobitchain_platform_evidence_object_demo_api():
    from flask import jsonify, request

    object_id = request.args.get("object_id", "niagara-bms-supervisor")
    packages = _cobitchain_load_demo_evidence_packages()

    matched = [
        _cobitchain_enrich_evidence_package(item)
        for item in packages
        if item.get("object_id") == object_id
    ]

    return jsonify({
        "service": "COBIT-Chain Evidence Vault Object Evidence Demo",
        "object_id": object_id,
        "count": len(matched),
        "packages": matched
    })


@app.route("/api/platform/evidence/state/demo", methods=["GET"])
def cobitchain_platform_evidence_state_demo_api():
    from flask import jsonify

    packages = _cobitchain_load_demo_evidence_packages()
    enriched = [_cobitchain_enrich_evidence_package(item) for item in packages]

    return jsonify({
        "service": "COBIT-Chain Evidence Vault Live Package Demo",
        "count": len(enriched),
        "packages": enriched
    })

# ============================================================
# END COBITCHAIN_PLATFORM_EVIDENCE_VAULT_LIVE_SERVICE_V1_ACTIVE
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

Path("platform_evidence_vault_live_service_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/evidence-packages",
        "http://127.0.0.1:5000/platform/evidence-vault-live",
        "http://127.0.0.1:5000/api/platform/evidence/package/demo?package_id=EVP-NIAGARA-READINESS-001",
        "http://127.0.0.1:5000/api/platform/evidence/object/demo?object_id=niagara-bms-supervisor",
        "http://127.0.0.1:5000/api/platform/evidence/state/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Evidence Vault Live Package Service installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
