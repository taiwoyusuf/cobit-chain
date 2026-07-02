from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_SPINE_REFRESH_V4_VERIFICATION_ACTIVE"

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
# COBITCHAIN_PLATFORM_SPINE_REFRESH_V4_VERIFICATION_ACTIVE
# ============================================================
''')

if not route_exists(text, "/platform"):
    block_parts.append(r'''
@app.route("/platform")
def cobitchain_platform_command_center_v4():
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
def cobitchain_platform_route_registry_v4():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_route_registry_command_center.html")
    return html_path.read_text(encoding="utf-8")
''')

if not route_exists(text, "/api/platform/spine-refresh/v4/demo"):
    block_parts.append(r'''
@app.route("/api/platform/spine-refresh/v4/demo", methods=["GET"])
@app.route("/api/platform/spine/v4/demo", methods=["GET"])
def cobitchain_platform_spine_refresh_v4_demo_api():
    from flask import jsonify
    from datetime import datetime, timezone
    import uuid

    newest_modules = [
        {"name": "AI Architecture Assurance", "route": "/platform/ai-architecture-assurance"},
        {"name": "AI Lifecycle Change Assurance", "route": "/platform/ai-lifecycle-change-assurance"},
        {"name": "AI Operational Readiness", "route": "/platform/ai-operational-readiness"},
        {"name": "Organizational Intelligence Assurance", "route": "/platform/organizational-intelligence-assurance"},
        {"name": "AI Autonomy Assurance Model", "route": "/platform/ai-autonomy-assurance-model"},
        {"name": "Data-to-Decision Assurance", "route": "/platform/data-to-decision-assurance"},
        {"name": "Jurisdictional AI Assurance", "route": "/platform/jurisdictional-ai-assurance"},
        {"name": "Action Assurance Workflow", "route": "/platform/action-assurance-workflow"}
    ]

    core_modules = [
        {"name": "Azure Foundry Assurance Blueprint", "route": "/platform/azure-foundry-assurance"},
        {"name": "Azure Foundry Lifecycle Evidence Binder", "route": "/platform/azure-foundry-evidence-binder"},
        {"name": "AI Infrastructure Assurance Blueprint", "route": "/platform/ai-infrastructure-assurance"},
        {"name": "Cloud Assurance Matrix", "route": "/platform/cloud-assurance-matrix"},
        {"name": "MCP Tool Registry", "route": "/platform/mcp-tools"},
        {"name": "Evidence Vault Live Packages", "route": "/platform/evidence-packages"},
        {"name": "Unified Assurance Object", "route": "/platform/object-assurance"},
        {"name": "Operational Trust Twin", "route": "/platform/operational-trust-twin"}
    ]

    return jsonify({
        "service": "COBIT-Chain Platform Spine Refresh v4 Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform_rule": "Azure executes. COBIT-Chain proves.",
        "refresh": "v4",
        "newest_modules": newest_modules,
        "core_modules": core_modules,
        "trust_chain": [
            "Trusted Architecture",
            "Trusted Data and Context",
            "Trusted Action",
            "Trusted Change",
            "Trusted Evidence"
        ],
        "status": "PLATFORM_SPINE_REFRESHED"
    })
''')

block_parts.append(r'''
# ============================================================
# END COBITCHAIN_PLATFORM_SPINE_REFRESH_V4_VERIFICATION_ACTIVE
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

Path("platform_spine_refresh_v4_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/ai-architecture-assurance",
        "http://127.0.0.1:5000/platform/ai-lifecycle-change-assurance",
        "http://127.0.0.1:5000/platform/ai-operational-readiness",
        "http://127.0.0.1:5000/platform/organizational-intelligence-assurance",
        "http://127.0.0.1:5000/platform/ai-autonomy-assurance-model",
        "http://127.0.0.1:5000/platform/data-to-decision-assurance",
        "http://127.0.0.1:5000/platform/jurisdictional-ai-assurance",
        "http://127.0.0.1:5000/api/platform/spine-refresh/v4/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Platform Spine Refresh v4 installed.")
print("Updated files:")
print("  platform_ab_command_center.html")
print("  platform_route_registry_command_center.html")
print("  platform_spine_refresh_v4_urls.txt")
print("Verification marker:")
print("  COBITCHAIN_PLATFORM_SPINE_REFRESH_V4_VERIFICATION_ACTIVE")
