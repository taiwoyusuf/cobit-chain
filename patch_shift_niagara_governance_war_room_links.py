from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_NIAGARA_GOVERNANCE_WAR_ROOM_LINKS_ACTIVE"

if MARKER in text:
    print("Governance War Room links already exist.")
    raise SystemExit(0)

if "SHIFT_NIAGARA_GOVERNANCE_WAR_ROOM_ACTIVE" not in text:
    raise RuntimeError("Governance War Room marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-niagara-governance-mesh-federation">Governance Mesh Federation</a>'

insert1 = '''<!-- SHIFT_NIAGARA_GOVERNANCE_WAR_ROOM_LINKS_ACTIVE -->
            <a href="/shift-niagara-governance-mesh-federation">Governance Mesh Federation</a>
            <a href="/shift-niagara-governance-war-room">Governance War Room</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Governance Mesh Federation nav
# ------------------------------------------------------------

target2 = '<a href="/shift-niagara-drift-federation">Drift Federation</a>'

insert2 = '''<a href="/shift-niagara-drift-federation">Drift Federation</a>
            <a href="/shift-niagara-governance-war-room">Governance War Room</a>'''

if target2 not in text:
    raise RuntimeError("Governance Mesh Federation insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Governance Mesh Federation™</td><td>Provides enterprise governance topology federation, survivability orchestration, governance telemetry correlation, and resilience federation analytics.</td><td><a href="/shift-niagara-governance-mesh-federation">Open</a></td></tr>'

insert3 = '''
            <tr><td>Governance War Room™</td><td>Provides executive governance coordination, survivability telemetry orchestration, operational trust federation, and resilience escalation analytics.</td><td><a href="/shift-niagara-governance-war-room">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>40</td><td><a href="/shift-niagara-governance-mesh-federation">Governance Mesh Federation</a></td><td>This federates enterprise governance topology into continuously orchestrated resilience intelligence.</td></tr>'

insert4 = '''
            <tr><td>41</td><td><a href="/shift-niagara-governance-war-room">Governance War Room</a></td><td>This orchestrates enterprise governance telemetry into executive resilience coordination intelligence.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-niagara-governance-mesh-federation">Governance Mesh Federation</a>'

insert5 = '''<a href="/shift-niagara-governance-mesh-federation">Governance Mesh Federation</a>
            <a href="/shift-niagara-governance-war-room">Governance War Room</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Governance War Room links added.")
