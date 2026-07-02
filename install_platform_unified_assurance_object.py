from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_UNIFIED_ASSURANCE_OBJECT_V1_ACTIVE"

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
    "/platform/object-assurance",
    "/platform/assurance-object",
    "/platform/unified-assurance",
    "/api/platform/assurance/object/demo",
    "/api/platform/assurance/state/demo"
]

for route in all_routes:
    if f'@app.route("{route}")' in text or f"@app.route('{route}')" in text:
        raise SystemExit(f"Route already exists outside this installer marker: {route}. No changes made.")

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_UNIFIED_ASSURANCE_OBJECT_V1_ACTIVE
# ============================================================

@app.route("/platform/object-assurance")
@app.route("/platform/assurance-object")
@app.route("/platform/unified-assurance")
def cobitchain_platform_unified_assurance_object():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_unified_assurance_object.html")
    return html_path.read_text(encoding="utf-8")


def _cobitchain_unified_load_json(filename, root_key):
    import json
    from pathlib import Path

    path = Path(__file__).with_name(filename)
    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get(root_key, [])
    except Exception:
        return []


def _cobitchain_unified_find_by_object(items, object_id):
    wanted = str(object_id or "").strip().lower()
    for item in items:
        if str(item.get("object_id", "")).strip().lower() == wanted:
            return item
    return None


def _cobitchain_unified_compute_trust_score(data):
    import uuid
    from datetime import datetime, timezone

    item = dict(data or {})
    score = 100
    explanation = []

    def b(name):
        return bool(item.get(name, False))

    if not b("owner_confirmed"):
        score -= 14
        explanation.append("Owner not confirmed.")
    if not b("support_group_confirmed"):
        score -= 12
        explanation.append("Support group not confirmed.")
    if not b("access_model_confirmed"):
        score -= 10
        explanation.append("Access model not confirmed.")
    if not b("evidence_lineage"):
        score -= 14
        explanation.append("Evidence lineage missing.")

    try:
        freshness = int(item.get("evidence_freshness_days", 999))
    except Exception:
        freshness = 999

    if freshness > 90:
        score -= 18
        explanation.append("Evidence stale beyond 90 days.")
    elif freshness > 30:
        score -= 8
        explanation.append("Evidence aging beyond 30 days.")

    validation_state = str(item.get("validation_state", "unknown")).lower()
    if validation_state in ["qualified_not_validated", "qualified"]:
        score -= 8
        explanation.append("Qualified but not fully validated.")
    elif validation_state in ["design_blueprint", "prototype"]:
        score -= 12
        explanation.append("Design or prototype state.")
    elif validation_state not in ["validated", "operational_under_current_controls"]:
        score -= 16
        explanation.append("Unknown validation or control state.")

    try:
        critical = int(item.get("open_critical_gaps", 0))
    except Exception:
        critical = 0

    try:
        major = int(item.get("open_major_gaps", 0))
    except Exception:
        major = 0

    if critical > 0:
        score -= min(45, critical * 25)
        explanation.append("Critical gaps present.")

    if major > 0:
        score -= min(30, major * 8)
        explanation.append("Major gaps present.")

    if not b("mcp_replay_ready"):
        score -= 5
        explanation.append("MCP replay not ready.")
    if not b("observability_ready"):
        score -= 5
        explanation.append("Observability not ready.")

    score = max(0, min(100, score))

    if critical > 0 or score < 40:
        decision = "BLOCKED"
    elif score >= 85:
        decision = "READY"
    elif score >= 65:
        decision = "CAUTION"
    else:
        decision = "LIMITED"

    if score >= 85:
        confidence = "HIGH"
    elif score >= 65:
        confidence = "MEDIUM"
    elif score >= 40:
        confidence = "LOW"
    else:
        confidence = "VERY LOW"

    if not explanation:
        explanation.append("No major trust-score issues identified from seed data.")

    return {
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "object_id": item.get("object_id"),
        "object_name": item.get("object_name"),
        "object_type": item.get("object_type"),
        "trust_score": score,
        "decision": decision,
        "confidence": confidence,
        "explanation": explanation
    }


def _cobitchain_unified_enrich_twin(data):
    item = dict(data or {})
    score = int(item.get("trust_score", 0) or 0)
    gaps = item.get("active_gaps", []) or []

    if score >= 85 and not gaps:
        health = "strong"
    elif score >= 70:
        health = "usable_with_caution"
    elif score >= 50:
        health = "limited"
    else:
        health = "weak_or_blocked"

    item["twin_health"] = health
    item["gap_count"] = len(gaps)
    return item


def _cobitchain_unified_enrich_evidence(data):
    item = dict(data or {})
    records = item.get("evidence_records", []) or []
    gaps = item.get("open_gaps", []) or []

    available = 0
    record_gaps = 0
    for record in records:
        status = str(record.get("status", "")).lower()
        if status == "available":
            available += 1
        if status == "gap":
            record_gaps += 1

    total = max(1, len(records))
    base = int((available / total) * 100)

    try:
        freshness = int(item.get("freshness_days", 999))
    except Exception:
        freshness = 999

    freshness_penalty = 20 if freshness > 90 else 10 if freshness > 30 else 0
    gap_penalty = min(35, len(gaps) * 7)
    record_gap_penalty = min(25, record_gaps * 8)

    quality = max(0, min(100, base - freshness_penalty - gap_penalty - record_gap_penalty + 20))

    if quality >= 85:
        confidence = "HIGH"
    elif quality >= 65:
        confidence = "MEDIUM"
    elif quality >= 40:
        confidence = "LOW"
    else:
        confidence = "VERY LOW"

    item["package_quality_score"] = quality
    item["package_confidence"] = confidence
    item["record_count"] = len(records)
    item["open_gap_count"] = len(gaps)
    return item


def _cobitchain_unified_find_vision_by_object(assets, object_id):
    wanted = str(object_id or "").strip().lower()
    for item in assets:
        if str(item.get("object_id", "")).strip().lower() == wanted:
            return item
    return None


def _cobitchain_build_unified_assurance_object(object_id):
    import uuid
    from datetime import datetime, timezone

    trust_objects = _cobitchain_unified_load_json("platform_trust_score_seed_objects.json", "objects")
    twins = _cobitchain_unified_load_json("platform_operational_trust_twin_seed.json", "twins")
    packages = _cobitchain_unified_load_json("platform_evidence_vault_seed_packages.json", "packages")
    vision_assets = _cobitchain_unified_load_json("platform_vision_lookup_seed.json", "assets")

    trust_seed = _cobitchain_unified_find_by_object(trust_objects, object_id)
    twin_seed = _cobitchain_unified_find_by_object(twins, object_id)
    evidence_seed = _cobitchain_unified_find_by_object(packages, object_id)
    vision_seed = _cobitchain_unified_find_vision_by_object(vision_assets, object_id)

    if not trust_seed and not twin_seed and not evidence_seed and not vision_seed:
        return None

    trust = _cobitchain_unified_compute_trust_score(trust_seed or {
        "object_id": object_id,
        "object_name": object_id,
        "object_type": "unknown",
        "owner_confirmed": False,
        "support_group_confirmed": False,
        "access_model_confirmed": False,
        "evidence_lineage": False,
        "evidence_freshness_days": 999,
        "validation_state": "unknown",
        "open_critical_gaps": 0,
        "open_major_gaps": 1,
        "mcp_replay_ready": False,
        "observability_ready": False
    })

    twin = _cobitchain_unified_enrich_twin(twin_seed or {})
    evidence = _cobitchain_unified_enrich_evidence(evidence_seed or {})
    vision = dict(vision_seed or {})

    object_name = (
        trust.get("object_name")
        or twin.get("object_name")
        or evidence.get("object_name")
        or vision.get("object_name")
        or object_id
    )

    object_type = (
        trust.get("object_type")
        or twin.get("twin_type")
        or evidence.get("object_type")
        or vision.get("asset_type")
        or "governed_object"
    )

    open_gaps = []
    for source in [
        twin.get("active_gaps", []),
        evidence.get("open_gaps", []),
        vision.get("limitations", [])
    ]:
        for item in source or []:
            if item not in open_gaps:
                open_gaps.append(item)

    limitations = []
    for source in [
        evidence.get("limitations", []),
        vision.get("limitations", [])
    ]:
        for item in source or []:
            if item not in limitations:
                limitations.append(item)

    score = int(trust.get("trust_score", 0) or 0)
    evidence_quality = int(evidence.get("package_quality_score", 0) or 0)

    if trust.get("decision") == "BLOCKED" or score < 40:
        integrated_state = "BLOCKED"
    elif score >= 85 and evidence_quality >= 75:
        integrated_state = "READY"
    elif score >= 65:
        integrated_state = "CAUTION"
    else:
        integrated_state = "LIMITED"

    if evidence_quality >= 85 and trust.get("confidence") == "HIGH":
        integrated_confidence = "HIGH"
    elif evidence_quality >= 65 and trust.get("confidence") in ["HIGH", "MEDIUM"]:
        integrated_confidence = "MEDIUM"
    elif evidence_quality >= 40:
        integrated_confidence = "LOW"
    else:
        integrated_confidence = "VERY LOW"

    if integrated_state == "READY":
        action = "Proceed under current controls and preserve evidence replay."
    elif integrated_state == "CAUTION":
        action = "Proceed only with documented limitations and close open evidence or operational gaps."
    elif integrated_state == "LIMITED":
        action = "Use only in controlled context until trust, evidence, and operational gaps are improved."
    else:
        action = "Do not rely on this object until blocking trust or evidence gaps are resolved."

    decision_basis = "Integrated from Trust Score, Operational Trust Twin, Evidence Vault package, and Governance Vision lookup seed data."

    return {
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "object_id": object_id,
        "object_name": object_name,
        "object_type": object_type,
        "integrated_state": integrated_state,
        "integrated_confidence": integrated_confidence,
        "integrated_recommended_action": action,
        "decision_basis": decision_basis,
        "open_gaps": open_gaps,
        "limitations": limitations,
        "trust_score": trust,
        "operational_twin": twin,
        "evidence_package": evidence,
        "vision_lookup": vision,
        "service_note": "Unified assurance object view strengthens existing Platform A/B modules. It does not create a new foundational concept."
    }


@app.route("/api/platform/assurance/object/demo", methods=["GET"])
def cobitchain_platform_assurance_object_demo_api():
    from flask import jsonify, request

    object_id = request.args.get("object_id", "niagara-bms-supervisor")
    result = _cobitchain_build_unified_assurance_object(object_id)

    if result:
        return jsonify(result)

    known = []
    for filename, key in [
        ("platform_trust_score_seed_objects.json", "objects"),
        ("platform_operational_trust_twin_seed.json", "twins"),
        ("platform_evidence_vault_seed_packages.json", "packages"),
        ("platform_vision_lookup_seed.json", "assets")
    ]:
        for item in _cobitchain_unified_load_json(filename, key):
            oid = item.get("object_id")
            if oid and oid not in known:
                known.append(oid)

    return jsonify({
        "error": "object_not_found",
        "message": f"No unified assurance object found for object_id={object_id}",
        "available_object_ids": known
    }), 404


@app.route("/api/platform/assurance/state/demo", methods=["GET"])
def cobitchain_platform_assurance_state_demo_api():
    from flask import jsonify

    known = []
    for filename, key in [
        ("platform_trust_score_seed_objects.json", "objects"),
        ("platform_operational_trust_twin_seed.json", "twins"),
        ("platform_evidence_vault_seed_packages.json", "packages"),
        ("platform_vision_lookup_seed.json", "assets")
    ]:
        for item in _cobitchain_unified_load_json(filename, key):
            oid = item.get("object_id")
            if oid and oid not in known:
                known.append(oid)

    objects = []
    for object_id in known:
        result = _cobitchain_build_unified_assurance_object(object_id)
        if result:
            objects.append(result)

    return jsonify({
        "service": "COBIT-Chain Unified Assurance Object Demo",
        "count": len(objects),
        "objects": objects
    })

# ============================================================
# END COBITCHAIN_PLATFORM_UNIFIED_ASSURANCE_OBJECT_V1_ACTIVE
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

Path("platform_unified_assurance_object_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/object-assurance",
        "http://127.0.0.1:5000/platform/assurance-object",
        "http://127.0.0.1:5000/platform/unified-assurance",
        "http://127.0.0.1:5000/api/platform/assurance/object/demo?object_id=niagara-bms-supervisor",
        "http://127.0.0.1:5000/api/platform/assurance/state/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Unified Assurance Object View installed.")
print("Routes installed:")
for route in all_routes:
    print("  " + route)
