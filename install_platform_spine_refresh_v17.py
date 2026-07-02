from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_SPINE_REFRESH_V17_VERIFICATION_ACTIVE"

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
# COBITCHAIN_PLATFORM_SPINE_REFRESH_V17_VERIFICATION_ACTIVE
# ============================================================
''')

if not route_exists(text, "/platform"):
    block_parts.append(r'''
@app.route("/platform")
def cobitchain_platform_command_center_v17():
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
def cobitchain_platform_route_registry_v17():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_route_registry_command_center.html")
    return html_path.read_text(encoding="utf-8")
''')

if not route_exists(text, "/api/platform/spine-refresh/v17/demo"):
    block_parts.append(r'''
@app.route("/api/platform/spine-refresh/v17/demo", methods=["GET"])
@app.route("/api/platform/spine/v17/demo", methods=["GET"])
def cobitchain_platform_spine_refresh_v17_demo_api():
    from flask import jsonify
    from datetime import datetime, timezone
    import uuid

    output_clearance_layer = [
        {"name": "AI Output Clearance Console", "route": "/platform/ai-output-clearance"},
        {"name": "Intelligence Validation Console", "route": "/platform/intelligence-validation"},
        {"name": "AI Assurance Decision Orchestrator", "route": "/platform/ai-assurance-decision-orchestrator"},
        {"name": "Evidence Vault Live Packages", "route": "/platform/evidence-packages"},
        {"name": "AI Assurance Replay Console", "route": "/platform/ai-assurance-replay-console"}
    ]

    clearance_domains = [
        "intended use alignment",
        "risk profile alignment",
        "source traceability",
        "prompt and model lineage",
        "explainability clearance",
        "confidence threshold",
        "human review and approval",
        "regulated workflow fit",
        "evidence completeness",
        "downstream impact",
        "exception and escalation",
        "clearance decision record"
    ]

    clearance_decisions = [
        "cleared for workflow use",
        "cleared with conditions",
        "human review required",
        "corrected output required",
        "blocked from workflow entry",
        "escalated to accountable owner",
        "revalidation required"
    ]

    evidence_records = [
        "output clearance record",
        "intended use alignment record",
        "risk profile alignment record",
        "source traceability record",
        "prompt and model lineage record",
        "explainability record",
        "confidence threshold record",
        "human approval record",
        "regulated workflow fit record",
        "downstream impact record",
        "exception and escalation record",
        "final clearance decision record"
    ]

    strengthened_modules = [
        "Intelligence Validation",
        "AI Lifecycle Change Assurance",
        "Decision Confidence",
        "Evidence Vault",
        "AI Operational Readiness",
        "AI Assurance Replay Console",
        "AI Assurance Decision Orchestrator",
        "Operational Release Gate",
        "Exception and Drift Response"
    ]

    full_trust_chain = [
        "AI Assurance New Workflow Intake Engine",
        "AI Team Assurance Console",
        "AI Accountability RACI Matrix Engine",
        "AI Assurance Reuse Applicability Engine",
        "Intelligence Validation Console",
        "AI Output Clearance Console",
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
        "service": "COBIT-Chain Platform Spine Refresh v17 Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform_rule": "Azure executes. COBIT-Chain proves.",
        "refresh": "v17",
        "output_clearance_layer": output_clearance_layer,
        "clearance_domains": clearance_domains,
        "clearance_decisions": clearance_decisions,
        "clearance_evidence_records_to_bind": evidence_records,
        "strengthened_modules": strengthened_modules,
        "full_ai_assurance_output_cleared_trust_chain": full_trust_chain,
        "engineering_principle": "An AI output is not operationally trusted because it was generated. It becomes trusted only when context, lineage, risk, evidence, human approval, and clearance conditions are satisfied.",
        "status": "PLATFORM_SPINE_REFRESHED_V17"
    })
''')

block_parts.append(r'''
# ============================================================
# END COBITCHAIN_PLATFORM_SPINE_REFRESH_V17_VERIFICATION_ACTIVE
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

Path("platform_spine_refresh_v17_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/ai-output-clearance",
        "http://127.0.0.1:5000/platform/intelligence-validation",
        "http://127.0.0.1:5000/platform/ai-assurance-decision-orchestrator",
        "http://127.0.0.1:5000/platform/evidence-packages",
        "http://127.0.0.1:5000/api/platform/spine-refresh/v17/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Platform Spine Refresh v17 installed.")
print("Updated files:")
print("  platform_ab_command_center.html")
print("  platform_route_registry_command_center.html")
print("  platform_spine_refresh_v17_urls.txt")
print("Verification marker:")
print("  COBITCHAIN_PLATFORM_SPINE_REFRESH_V17_VERIFICATION_ACTIVE")
