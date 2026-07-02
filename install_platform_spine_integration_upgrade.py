from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_SPINE_INTEGRATION_UPGRADE_V1_ACTIVE"

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

def has_route(route):
    return f'@app.route("{route}")' in text or f"@app.route('{route}')" in text

blocks = []

if not has_route("/platform"):
    blocks.append('''
@app.route("/platform")
def cobitchain_platform_command_center_integrated():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ab_command_center.html")
    return html_path.read_text(encoding="utf-8")
''')

if not has_route("/platform/routes"):
    blocks.append('''
@app.route("/platform/routes")
@app.route("/platform/route-registry")
@app.route("/platform/module-map")
def cobitchain_platform_route_registry_integrated():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_route_registry_command_center.html")
    return html_path.read_text(encoding="utf-8")
''')

if blocks:
    block = f'''

# ============================================================
# {MARKER}
# ============================================================

''' + "\n".join(blocks) + f'''

# ============================================================
# END {MARKER}
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
    print("Fallback routes were added because one or more primary routes were missing.")
else:
    APP.write_text(text, encoding="utf-8")
    print("Primary routes already exist. app.py route structure preserved.")

Path("platform_spine_integration_upgrade_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/trust-score-service",
        "http://127.0.0.1:5000/platform/operational-trust-twin",
        "http://127.0.0.1:5000/platform/vision-lookup"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Platform Spine Integration Upgrade complete.")
