from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_SPINE_REFRESH_V8_VERIFICATION_ACTIVE"

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
# COBITCHAIN_PLATFORM_SPINE_REFRESH_V8_VERIFICATION_ACTIVE
# ============================================================
''')

if not route_exists(text, "/platform"):
    block_parts.append(r'''
@app.route("/platform")
def cobitchain_platform_command_center_v8():
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
def cobitchain_platform_route_registry_v8():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_route_registry_command_center.html")
    return html_path.read_text(encoding="utf-8")
''')

if not route_exists(text, "/api/platform/spine-refresh/v8/demo"):
    block_parts.append(r'''
@app.route("/api/platform/spine-refresh/v8/demo", methods=["GET"])
@app.route("/api/platform/spine/v8/demo", methods=["GET"])
def cobitchain_platform_spine_refresh_v8_demo_api():
    from flask import jsonify
    from datetime import datetime, timezone
    import uuid

    approval_release_layer = [
        {"name": "AI Assurance Approval Certificate", "route": "/platform/ai-assurance-approval-certificate"},
        {"name": "AI Assurance Operational Release Gate", "route": "/platform/ai-assurance-operational-release-gate"},
        {"name": "Operational Trust Twin", "route": "/platform/operational-trust-twin"},
        {"name": "Observability and Audit Replay", "route": "/platform/observability"}
    ]

    full_trust_chain = [
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
        "Operational Trust Monitoring"
    ]

    return jsonify({
        "service": "COBIT-Chain Platform Spine Refresh v8 Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform_rule": "Azure executes. COBIT-Chain proves.",
        "refresh": "v8",
        "approval_release_layer": approval_release_layer,
        "full_ai_assurance_to_operational_release_trust_chain": full_trust_chain,
        "engineering_principle": "AI operational trust is complete only when approval is certified, release is gated, monitoring is active, rollback is ready, and evidence is bound.",
        "status": "PLATFORM_SPINE_REFRESHED_V8"
    })
''')

block_parts.append(r'''
# ============================================================
# END COBITCHAIN_PLATFORM_SPINE_REFRESH_V8_VERIFICATION_ACTIVE
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

Path("platform_spine_refresh_v8_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/ai-assurance-approval-certificate",
        "http://127.0.0.1:5000/platform/ai-assurance-operational-release-gate",
        "http://127.0.0.1:5000/platform/ai-assurance-trust-recalculation",
        "http://127.0.0.1:5000/platform/operational-trust-twin",
        "http://127.0.0.1:5000/api/platform/spine-refresh/v8/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Platform Spine Refresh v8 installed.")
print("Updated files:")
print("  platform_ab_command_center.html")
print("  platform_route_registry_command_center.html")
print("  platform_spine_refresh_v8_urls.txt")
print("Verification marker:")
print("  COBITCHAIN_PLATFORM_SPINE_REFRESH_V8_VERIFICATION_ACTIVE")
