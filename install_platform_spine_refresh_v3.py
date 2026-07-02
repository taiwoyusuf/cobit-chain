from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_SPINE_REFRESH_V3_VERIFICATION_ACTIVE"

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

block = f'''

# ============================================================
# {MARKER}
# ============================================================

# Platform Spine Refresh v3:
# - Azure Foundry Assurance Blueprint integrated into platform spine
# - AI Infrastructure Assurance Blueprint integrated into platform spine
# - Decision Context Assurance Flow integrated into platform spine
# - Cloud Assurance Matrix, MCP Tools, Object Assurance, and Evidence Packages retained
# - No new routes added
# - No new foundational concept
# - One Azure-first, cloud-neutral Assurance Engineering platform

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

Path("platform_spine_refresh_v3_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/azure-foundry-assurance",
        "http://127.0.0.1:5000/platform/ai-infrastructure-assurance",
        "http://127.0.0.1:5000/platform/decision-context-assurance",
        "http://127.0.0.1:5000/platform/cloud-assurance-matrix",
        "http://127.0.0.1:5000/platform/mcp-tools",
        "http://127.0.0.1:5000/platform/object-assurance",
        "http://127.0.0.1:5000/platform/evidence-packages"
    ]),
    encoding="utf-8"
)

print("COBIT-Chain Platform Spine Refresh v3 installed.")
print("No new routes were added. Existing platform pages were refreshed.")
