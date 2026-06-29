from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

NEW_MARKER = "COBITCHAIN_PLATFORM_AB_PREMIUM_ORANGE_COMMAND_CENTER_V2_ACTIVE"
OLD_MARKERS = [
    "COBITCHAIN_UNIFIED_PLATFORM_AB_COMMAND_CENTER_V1_ACTIVE",
    "COBITCHAIN_PLATFORM_AB_PREMIUM_ORANGE_COMMAND_CENTER_V2_ACTIVE",
]

# Remove earlier complete Platform A/B blocks if they exist.
for marker in OLD_MARKERS:
    pattern = (
        r"\n?# ============================================================\n"
        r"# " + re.escape(marker) + r"\n"
        r"# ============================================================\n"
        r".*?"
        r"# ============================================================\n"
        r"# END " + re.escape(marker) + r"\n"
        r"# ============================================================\n?"
    )
    text = re.sub(pattern, "\n", text, flags=re.DOTALL)

desired_routes = ["/platform", "/platform-ab", "/cobitchain-platform"]
fallback_routes = ["/platform-command-center", "/platform-ab-command-center", "/cobitchain-platform-command-center"]

routes_to_add = []

for route in desired_routes:
    double = f'@app.route("{route}")'
    single = f"@app.route('{route}')"
    if double not in text and single not in text:
        routes_to_add.append(route)

if not routes_to_add:
    for route in fallback_routes:
        double = f'@app.route("{route}")'
        single = f"@app.route('{route}')"
        if double not in text and single not in text:
            routes_to_add.append(route)

if not routes_to_add:
    raise SystemExit("No safe route available. Existing platform routes may already exist. No changes made.")

route_lines = "\n".join([f'@app.route("{route}")' for route in routes_to_add])

block = f'''

# ============================================================
# {NEW_MARKER}
# ============================================================

{route_lines}
def cobitchain_platform_ab_premium_orange_command_center():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_ab_command_center.html")
    return html_path.read_text(encoding="utf-8")

# ============================================================
# END {NEW_MARKER}
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

Path("platform_ab_installed_urls.txt").write_text(
    "\n".join([f"http://127.0.0.1:5000{route}" for route in routes_to_add]),
    encoding="utf-8"
)

print("COBIT-Chain Platform A/B Premium Orange Command Center installed.")
print("Routes installed:")
for route in routes_to_add:
    print(f"  {route}")
