from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_OBSERVABILITY_COMMAND_CENTER_V1_ACTIVE"

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

desired_routes = [
    "/platform/observability",
    "/platform/audit-replay",
    "/observability",
    "/cobitchain-observability"
]

routes_to_add = []
for route in desired_routes:
    if f'@app.route("{route}")' not in text and f"@app.route('{route}')" not in text:
        routes_to_add.append(route)

if not routes_to_add:
    raise SystemExit("All desired Observability routes already exist. No changes made.")

route_lines = "\n".join([f'@app.route("{route}")' for route in routes_to_add])

block = f'''

# ============================================================
# {MARKER}
# ============================================================

{route_lines}
def cobitchain_platform_observability_command_center():
    from pathlib import Path
    html_path = Path(__file__).with_name("platform_observability_command_center.html")
    return html_path.read_text(encoding="utf-8")

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

Path("platform_observability_installed_urls.txt").write_text(
    "\n".join([f"http://127.0.0.1:5000{route}" for route in routes_to_add]),
    encoding="utf-8"
)

print("COBIT-Chain Platform Observability and Audit Replay Command Center installed.")
print("Routes installed:")
for route in routes_to_add:
    print("  " + route)
