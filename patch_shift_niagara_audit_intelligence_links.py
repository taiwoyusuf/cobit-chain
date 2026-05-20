from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_NIAGARA_AUDIT_INTELLIGENCE_LINKS_ACTIVE"

if MARKER in text:
    print("Niagara Audit Intelligence links already exist.")
    raise SystemExit(0)

if "SHIFT_NIAGARA_AUDIT_INTELLIGENCE_ACTIVE" not in text:
    raise RuntimeError("Niagara Audit Intelligence marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-niagara-governance-hub">Niagara Governance Hub</a>'

insert1 = '''<!-- SHIFT_NIAGARA_AUDIT_INTELLIGENCE_LINKS_ACTIVE -->
            <a href="/shift-niagara-governance-hub">Niagara Governance Hub</a>
            <a href="/shift-niagara-audit-intelligence">Niagara Audit Intelligence</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Niagara Governance Hub nav
# ------------------------------------------------------------

target2 = '<a href="/shift-operational-data-fabric">Operational Data Fabric</a>'

insert2 = '''<a href="/shift-operational-data-fabric">Operational Data Fabric</a>
            <a href="/shift-niagara-audit-intelligence">Niagara Audit Intelligence</a>'''

if target2 not in text:
    raise RuntimeError("Niagara Governance Hub insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Niagara Governance Hub™</td><td>Ingests Niagara audit telemetry, access governance evidence, backup lineage, and operational trust intelligence.</td><td><a href="/shift-niagara-governance-hub">Open</a></td></tr>'

insert3 = '''
            <tr><td>Niagara Audit Intelligence™</td><td>Provides governance defensibility analytics, anomaly detection, audit lineage reasoning, and operational trust scoring.</td><td><a href="/shift-niagara-audit-intelligence">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>31</td><td><a href="/shift-niagara-governance-hub">Niagara Governance Hub</a></td><td>This ingests real Niagara governance evidence into the enterprise operational intelligence ecosystem.</td></tr>'

insert4 = '''
            <tr><td>32</td><td><a href="/shift-niagara-audit-intelligence">Niagara Audit Intelligence</a></td><td>This transforms operational audit reviews into governance defensibility intelligence and anomaly analytics.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-niagara-governance-hub">Niagara Governance Hub</a>'

insert5 = '''<a href="/shift-niagara-governance-hub">Niagara Governance Hub</a>
            <a href="/shift-niagara-audit-intelligence">Niagara Audit Intelligence</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Niagara Audit Intelligence links added.")
