from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_SPINE_REFRESH_V16_VERIFICATION_ACTIVE"

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

def route_exists(source, route):
    pattern = r"@app\.route\(\s*['\"]" + re.escape(route) + r"['\"]"
    return re.search(pattern, source) is not None

block_parts = []

block_parts.append(r'''
# ============================================================
# COBITCHAIN_PLATFORM_SPINE_REFRESH_V16_VERIFICATION_ACTIVE
# ============================================================
''')

if not route_exists(text, "/platform"):
    block_parts.append(r'''
@app.route("/platform")
def cobitchain_platform_command_center_v16():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ab_command_center.html")
    return html_path.read_text(encoding="utf-8")
''')

route_registry_group = [
    "/platform/routes",
    "/platform/route-registry",
    "/platform/module-map",
    "/cobitchain-route-registry"
]

if not any(route_exists(text, route) for route in route_registry_group):
    block_parts.append(r'''
@app.route("/platform/routes")
@app.route("/platform/route-registry")
@app.route("/platform/module-map")
@app.route("/cobitchain-route-registry")
def cobitchain_platform_route_registry_v16():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_route_registry_command_center.html")
    return html_path.read_text(encoding="utf-8")
''')

if not route_exists(text, "/api/platform/spine-refresh/v16/demo"):
    block_parts.append(r'''
@app.route("/api/platform/spine-refresh/v16/demo", methods=["GET"])
@app.route("/api/platform/spine/v16/demo", methods=["GET"])
def cobitchain_platform_spine_refresh_v16_demo_api():
    from flask import jsonify
    from datetime import datetime, timezone
    import uuid

    intelligence_validation_layer = [
        {"name": "Intelligence Validation Console", "route": "/platform/intelligence-validation"},
        {"name": "AI Lifecycle Change Assurance", "route": "/platform/ai-lifecycle-change-assurance"},
        {"name": "AI Operational Readiness", "route": "/platform/ai-operational-readiness"},
        {"name": "AI Assurance Evidence Contract", "route": "/platform/ai-assurance-evidence-contract"},
        {"name": "Evidence Vault Live Packages", "route": "/platform/evidence-packages"}
    ]

    validation_domains = [
        "intended use definition",
        "risk profile",
        "functional validation",
        "operational performance",
        "explainability",
        "prompt traceability",
        "model version traceability",
        "data lineage",
        "human approval",
        "drift monitoring",
        "revalidation triggers",
        "continuous monitoring",
        "evidence completeness"
    ]

    evidence_records = [
        "intended use record",
        "AI risk profile",
        "functional validation summary",
        "operational performance record",
        "explainability record",
        "prompt traceability record",
        "model version traceability record",
        "data lineage record",
        "human approval record",
        "drift monitoring record",
        "revalidation trigger catalog",
        "continuous monitoring plan",
        "validation evidence package"
    ]

    strengthened_modules = [
        "AI Lifecycle Change Assurance",
        "Decision Confidence",
        "AI Output Clearance",
        "Evidence Vault",
        "AI Operational Readiness",
        "Post-Release Monitoring",
        "Exception and Drift Response",
        "Approval Certificate",
        "Operational Release Gate"
    ]

    full_trust_chain = [
        "AI Assurance New Workflow Intake Engine",
        "AI Team Assurance Console",
        "AI Accountability RACI Matrix Engine",
        "AI Assurance Reuse Applicability Engine",
        "Intelligence Validation Console",
        "AI Architecture Assurance",
        "AI Architecture Boundary Gate",
        "AI Assurance Control Router",
        "AI Assurance Decision Orchestrator",
        "AI Assurance Evidence Contract",
        "AI Assurance Replay Console",
        "AI Assurance Remediation Queue",
        "AI Assurance Closure Verifier",
        "AI Assurance Trust Recalculation Engine",
        "AI Assurance Approval Certificate",
        "AI Assurance Operational Release Gate",
        "AI Assurance Post-Release Monitoring Console",
        "AI Assurance Exception and Drift Response Engine",
        "AI Assurance Outcome Learning Engine",
        "AI Assurance Knowledge Reuse Registry",
        "Next Workflow Intelligence Reuse"
    ]

    return jsonify({
        "service": "COBIT-Chain Platform Spine Refresh v16 Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform_rule": "Azure executes. COBIT-Chain proves.",
        "refresh": "v16",
        "intelligence_validation_layer": intelligence_validation_layer,
        "validation_domains": validation_domains,
        "validation_evidence_records_to_bind": evidence_records,
        "strengthened_modules": strengthened_modules,
        "full_ai_assurance_intelligence_validated_trust_chain": full_trust_chain,
        "engineering_principle": "Operational trust depends upon continuous validation of intelligence rather than one-time validation of software.",
        "status": "PLATFORM_SPINE_REFRESHED_V16"
    })
''')

block_parts.append(r'''
# ============================================================
# END COBITCHAIN_PLATFORM_SPINE_REFRESH_V16_VERIFICATION_ACTIVE
# ============================================================
''')

block = "\n".join(block_parts)

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

text = text[:idx] + "\n" + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

Path("platform_spine_refresh_v16_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/intelligence-validation",
        "http://127.0.0.1:5000/platform/ai-lifecycle-change-assurance",
        "http://127.0.0.1:5000/platform/ai-operational-readiness",
        "http://127.0.0.1:5000/platform/ai-assurance-evidence-contract",
        "http://127.0.0.1:5000/api/platform/spine-refresh/v16/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Platform Spine Refresh v16 installed.")
print("Updated files:")
print("  platform_ab_command_center.html")
print("  platform_route_registry_command_center.html")
print("  platform_spine_refresh_v16_urls.txt")
print("Verification marker:")
print("  COBITCHAIN_PLATFORM_SPINE_REFRESH_V16_VERIFICATION_ACTIVE")
