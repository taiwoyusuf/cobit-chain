from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "ENTERPRISE_HUB_INTELLIGENCE_LINKS_ACTIVE"

if MARKER in text:
    print("Enterprise hub intelligence links already added.")
    raise SystemExit(0)

required_anchor = 'href="/enterprise-workspaces"'

if required_anchor not in text:
    raise SystemExit("ERROR: Could not locate enterprise workspace hub section.")

new_block = r'''

# ============================================================
# ENTERPRISE_HUB_INTELLIGENCE_LINKS_ACTIVE
# Safe additive registry entries for enterprise intelligence modules
# ============================================================

register_workspace(
    name="Role-Based Enterprise Views",
    route="/role-based-views",
    status="ACTIVE",
    tag="ACCESS GOVERNANCE"
)

register_workspace(
    name="Shift Overlap Intelligence",
    route="/shift-overlap-intelligence",
    status="ACTIVE",
    tag="OPERATIONS"
)

register_workspace(
    name="Governance Confidence Engine",
    route="/governance-confidence-engine",
    status="ACTIVE",
    tag="EXECUTIVE TRUST"
)

register_workspace(
    name="Governance Blast Radius",
    route="/governance-blast-radius",
    status="ACTIVE",
    tag="RISK INTELLIGENCE"
)

register_workspace(
    name="Audit Simulation Engine",
    route="/audit-simulation-engine",
    status="ACTIVE",
    tag="AUDIT READINESS"
)

register_workspace(
    name="ServiceNow Governance Overlay",
    route="/servicenow-governance-overlay",
    status="ACTIVE",
    tag="SERVICENOW"
)

register_workspace(
    name="Governance Digital Twin",
    route="/governance-digital-twin",
    status="ACTIVE",
    tag="DIGITAL TWIN"
)

'''

insert_before = '\n@app.route("/enterprise-workspaces")'

idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not locate enterprise workspace route.")

updated = text[:idx] + new_block + text[idx:]

APP.write_text(updated, encoding="utf-8")

checks = [
    "ENTERPRISE_HUB_INTELLIGENCE_LINKS_ACTIVE",
    "Governance Confidence Engine",
    "Governance Blast Radius",
    "Audit Simulation Engine",
    "ServiceNow Governance Overlay",
    "Governance Digital Twin"
]

missing = [c for c in checks if c not in updated]

if missing:
    raise SystemExit("ERROR missing entries: " + ", ".join(missing))

print("SUCCESS: Enterprise workspace hub updated with intelligence modules.")
