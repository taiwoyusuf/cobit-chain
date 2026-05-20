from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

# Remove the broken register_workspace block
start_marker = "# ENTERPRISE_HUB_INTELLIGENCE_LINKS_ACTIVE"
start = text.find(start_marker)

if start != -1:
    block_start = text.rfind("# ============================================================", 0, start)
    route_start = text.find('\n@app.route("/enterprise-workspaces")', start)
    if block_start == -1 or route_start == -1:
        raise SystemExit("ERROR: Could not safely locate broken register block.")
    text = text[:block_start] + text[route_start:]
    print("Removed broken register_workspace block.")
else:
    print("Broken register block not found; continuing.")

# Add intelligence modules directly into existing enterprise workspace hub list
if "Governance Intelligence & Trust Layer" not in text:
    anchor = '''        {
            "group": "Future Clean Executive Demo Spaces",'''
    
    if anchor not in text:
        raise SystemExit("ERROR: Could not find Future Clean Executive Demo Spaces anchor.")

    intelligence_group = '''        {
            "group": "Governance Intelligence & Trust Layer",
            "description": "Advanced intelligence routes for role-based views, overlap continuity, confidence scoring, blast radius, audit simulation, ServiceNow overlay, and digital twin governance.",
            "items": [
                {
                    "name": "Role-Based Enterprise Views",
                    "route": "/role-based-views",
                    "status": "LIVE",
                    "tag": "ROLE VIEWS",
                    "summary": "Executive, supervisor, technician, QA/audit, and platform admin views of the governance platform."
                },
                {
                    "name": "Shift Overlap Intelligence",
                    "route": "/shift-overlap-intelligence",
                    "status": "LIVE",
                    "tag": "SHIFT",
                    "summary": "Chris' overlap shift model converted into continuity, handoff, evidence, and pre-deviation governance intelligence."
                },
                {
                    "name": "Governance Confidence Engine",
                    "route": "/governance-confidence-engine",
                    "status": "LIVE",
                    "tag": "TRUST SCORE",
                    "summary": "Executive trust score across overlap integrity, evidence completeness, escalation ownership, audit readiness, and lineage."
                },
                {
                    "name": "Governance Blast Radius",
                    "route": "/governance-blast-radius",
                    "status": "LIVE",
                    "tag": "RISK",
                    "summary": "Shows downstream impact when one governance weakness affects shift, equipment, evidence, review, audit, and CAPA exposure."
                },
                {
                    "name": "Audit Simulation Engine",
                    "route": "/audit-simulation-engine",
                    "status": "LIVE",
                    "tag": "AUDIT",
                    "summary": "Simulates what an auditor may ask and what would fail first if inspected today."
                },
                {
                    "name": "ServiceNow Governance Overlay",
                    "route": "/servicenow-governance-overlay",
                    "status": "LIVE",
                    "tag": "SERVICENOW",
                    "summary": "Shows ServiceNow workflow state versus COBIT-Chain governance trust state."
                },
                {
                    "name": "Governance Digital Twin",
                    "route": "/governance-digital-twin",
                    "status": "LIVE",
                    "tag": "DIGITAL TWIN",
                    "summary": "Connected governance model across ticket, shift, technician, equipment, evidence, review, confidence, and audit state."
                },
            ],
        },
'''
    text = text.replace(anchor, intelligence_group + anchor)

APP.write_text(text, encoding="utf-8")

checks = [
    "Governance Intelligence & Trust Layer",
    "/shift-overlap-intelligence",
    "/governance-confidence-engine",
    "/governance-blast-radius",
    "/audit-simulation-engine",
    "/servicenow-governance-overlay",
    "/governance-digital-twin"
]

missing = [c for c in checks if c not in text]
if missing:
    raise SystemExit("ERROR missing expected hub links: " + ", ".join(missing))

print("SUCCESS: Fixed hub and added intelligence links safely.")
