from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_SPINE_REFRESH_V13_VERIFICATION_ACTIVE"

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
# COBITCHAIN_PLATFORM_SPINE_REFRESH_V13_VERIFICATION_ACTIVE
# ============================================================
''')

if not route_exists(text, "/platform"):
    block_parts.append(r'''
@app.route("/platform")
def cobitchain_platform_command_center_v13():
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
def cobitchain_platform_route_registry_v13():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_route_registry_command_center.html")
    return html_path.read_text(encoding="utf-8")
''')

if not route_exists(text, "/api/platform/spine-refresh/v13/demo"):
    block_parts.append(r'''
@app.route("/api/platform/spine-refresh/v13/demo", methods=["GET"])
@app.route("/api/platform/spine/v13/demo", methods=["GET"])
def cobitchain_platform_spine_refresh_v13_demo_api():
    from flask import jsonify
    from datetime import datetime, timezone
    import uuid

    new_workflow_intake_layer = [
        {"name": "AI Assurance New Workflow Intake Engine", "route": "/platform/ai-assurance-new-workflow-intake"},
        {"name": "AI Assurance Reuse Applicability Engine", "route": "/platform/ai-assurance-reuse-applicability"},
        {"name": "AI Architecture Assurance", "route": "/platform/ai-architecture-assurance"},
        {"name": "AI Assurance Evidence Contract", "route": "/platform/ai-assurance-evidence-contract"},
        {"name": "AI Assurance Control Router", "route": "/platform/ai-assurance-control-router"}
    ]

    intake_checks = [
        "workflow identity",
        "context of use",
        "regulated context",
        "AI capability profile",
        "autonomy level",
        "tool and data access",
        "reuse applicability",
        "evidence contract precheck",
        "owner accountability",
        "assurance path routing"
    ]

    assurance_paths = [
        "full AI assurance path",
        "accelerated assurance path",
        "advisory reuse path",
        "lifecycle change assurance path",
        "blocked intake path"
    ]

    full_trust_chain = [
        "AI Assurance New Workflow Intake Engine",
        "AI Assurance Reuse Applicability Engine",
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
        "service": "COBIT-Chain Platform Spine Refresh v13 Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform_rule": "Azure executes. COBIT-Chain proves.",
        "refresh": "v13",
        "new_workflow_intake_layer": new_workflow_intake_layer,
        "intake_checks": intake_checks,
        "assurance_paths": assurance_paths,
        "full_ai_assurance_closed_loop_trust_chain": full_trust_chain,
        "engineering_principle": "A new AI workflow should not begin with tools, prompts, or deployment. It should begin with a governed intake record that defines context, autonomy, tools, data, evidence, owners, risk, reuse eligibility, and assurance path.",
        "status": "PLATFORM_SPINE_REFRESHED_V13"
    })
''')

block_parts.append(r'''
# ============================================================
# END COBITCHAIN_PLATFORM_SPINE_REFRESH_V13_VERIFICATION_ACTIVE
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

Path("platform_spine_refresh_v13_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/ai-assurance-new-workflow-intake",
        "http://127.0.0.1:5000/platform/ai-assurance-reuse-applicability",
        "http://127.0.0.1:5000/platform/ai-architecture-assurance",
        "http://127.0.0.1:5000/platform/ai-assurance-evidence-contract",
        "http://127.0.0.1:5000/api/platform/spine-refresh/v13/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Platform Spine Refresh v13 installed.")
print("Updated files:")
print("  platform_ab_command_center.html")
print("  platform_route_registry_command_center.html")
print("  platform_spine_refresh_v13_urls.txt")
print("Verification marker:")
print("  COBITCHAIN_PLATFORM_SPINE_REFRESH_V13_VERIFICATION_ACTIVE")
