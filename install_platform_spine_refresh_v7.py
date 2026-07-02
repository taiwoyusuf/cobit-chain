from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_SPINE_REFRESH_V7_VERIFICATION_ACTIVE"

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
# COBITCHAIN_PLATFORM_SPINE_REFRESH_V7_VERIFICATION_ACTIVE
# ============================================================
''')

if not route_exists(text, "/platform"):
    block_parts.append(r'''
@app.route("/platform")
def cobitchain_platform_command_center_v7():
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
def cobitchain_platform_route_registry_v7():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_route_registry_command_center.html")
    return html_path.read_text(encoding="utf-8")
''')

if not route_exists(text, "/api/platform/spine-refresh/v7/demo"):
    block_parts.append(r'''
@app.route("/api/platform/spine-refresh/v7/demo", methods=["GET"])
@app.route("/api/platform/spine/v7/demo", methods=["GET"])
def cobitchain_platform_spine_refresh_v7_demo_api():
    from flask import jsonify
    from datetime import datetime, timezone
    import uuid

    recovery_layer = [
        {"name": "AI Assurance Remediation Queue", "route": "/platform/ai-assurance-remediation-queue"},
        {"name": "AI Assurance Closure Verifier", "route": "/platform/ai-assurance-closure-verifier"},
        {"name": "AI Assurance Trust Recalculation Engine", "route": "/platform/ai-assurance-trust-recalculation"},
        {"name": "Operational Trust Twin", "route": "/platform/operational-trust-twin"}
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
        "Operational Trust"
    ]

    return jsonify({
        "service": "COBIT-Chain Platform Spine Refresh v7 Demo",
        "request_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform_rule": "Azure executes. COBIT-Chain proves.",
        "refresh": "v7",
        "recovery_layer": recovery_layer,
        "full_assurance_to_recalculation_trust_chain": full_trust_chain,
        "engineering_principle": "Operational trust is restored only after remediation is owned, closed, verified, evidence-bound, replay-ready, and recalculated.",
        "status": "PLATFORM_SPINE_REFRESHED_V7"
    })
''')

block_parts.append(r'''
# ============================================================
# END COBITCHAIN_PLATFORM_SPINE_REFRESH_V7_VERIFICATION_ACTIVE
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

Path("platform_spine_refresh_v7_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/ai-assurance-remediation-queue",
        "http://127.0.0.1:5000/platform/ai-assurance-closure-verifier",
        "http://127.0.0.1:5000/platform/ai-assurance-trust-recalculation",
        "http://127.0.0.1:5000/platform/operational-trust-twin",
        "http://127.0.0.1:5000/api/platform/spine-refresh/v7/demo"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Platform Spine Refresh v7 installed.")
print("Updated files:")
print("  platform_ab_command_center.html")
print("  platform_route_registry_command_center.html")
print("  platform_spine_refresh_v7_urls.txt")
print("Verification marker:")
print("  COBITCHAIN_PLATFORM_SPINE_REFRESH_V7_VERIFICATION_ACTIVE")
