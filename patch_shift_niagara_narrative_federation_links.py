from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_NIAGARA_NARRATIVE_FEDERATION_LINKS_ACTIVE"

if MARKER in text:
    print("Narrative Federation links already exist.")
    raise SystemExit(0)

if "SHIFT_NIAGARA_NARRATIVE_FEDERATION_ACTIVE" not in text:
    raise RuntimeError("Narrative Federation marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-niagara-governance-war-room">Governance War Room</a>'

insert1 = '''<!-- SHIFT_NIAGARA_NARRATIVE_FEDERATION_LINKS_ACTIVE -->
            <a href="/shift-niagara-governance-war-room">Governance War Room</a>
            <a href="/shift-niagara-narrative-federation">Narrative Federation</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Governance War Room nav
# ------------------------------------------------------------

target2 = '<a href="/shift-niagara-governance-mesh-federation">Governance Mesh Federation</a>'

insert2 = '''<a href="/shift-niagara-governance-mesh-federation">Governance Mesh Federation</a>
            <a href="/shift-niagara-narrative-federation">Narrative Federation</a>'''

if target2 not in text:
    raise RuntimeError("Governance War Room insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Governance War Room™</td><td>Provides executive governance coordination, survivability telemetry orchestration, operational trust federation, and resilience escalation analytics.</td><td><a href="/shift-niagara-governance-war-room">Open</a></td></tr>'

insert3 = '''
            <tr><td>Narrative Federation™</td><td>Provides executive storytelling federation, governance telemetry orchestration, survivability communication intelligence, and operational narrative correlation.</td><td><a href="/shift-niagara-narrative-federation">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>41</td><td><a href="/shift-niagara-governance-war-room">Governance War Room</a></td><td>This orchestrates enterprise governance telemetry into executive resilience coordination intelligence.</td></tr>'

insert4 = '''
            <tr><td>42</td><td><a href="/shift-niagara-narrative-federation">Narrative Federation</a></td><td>This federates governance telemetry into continuously orchestrated executive storytelling intelligence.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-niagara-governance-war-room">Governance War Room</a>'

insert5 = '''<a href="/shift-niagara-governance-war-room">Governance War Room</a>
            <a href="/shift-niagara-narrative-federation">Narrative Federation</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Narrative Federation links added.")
