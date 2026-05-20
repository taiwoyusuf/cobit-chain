from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_OPERATIONAL_DATA_FABRIC_LINKS_ACTIVE"

if MARKER in text:
    print("Operational Data Fabric links already exist.")
    raise SystemExit(0)

if "SHIFT_OPERATIONAL_DATA_FABRIC_ACTIVE" not in text:
    raise RuntimeError("Operational Data Fabric marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-ai-copilot">Executive AI Copilot</a>'

insert1 = '''<!-- SHIFT_OPERATIONAL_DATA_FABRIC_LINKS_ACTIVE -->
            <a href="/shift-ai-copilot">Executive AI Copilot</a>
            <a href="/shift-operational-data-fabric">Operational Data Fabric</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# AI Copilot nav
# ------------------------------------------------------------

target2 = '<a href="/shift-executive-stability-fabric">Stability Fabric</a>'

insert2 = '''<a href="/shift-executive-stability-fabric">Stability Fabric</a>
            <a href="/shift-operational-data-fabric">Operational Data Fabric</a>'''

if target2 not in text:
    raise RuntimeError("AI Copilot insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Executive AI Copilot™</td><td>Provides governance reasoning, survivability simulation, continuity intervention guidance, and executive operational intelligence assistance.</td><td><a href="/shift-ai-copilot">Open</a></td></tr>'

insert3 = '''
            <tr><td>Operational Data Fabric™</td><td>Federates audit telemetry, operational lineage, governance evidence, survivability signals, and continuity intelligence.</td><td><a href="/shift-operational-data-fabric">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>29</td><td><a href="/shift-ai-copilot">Executive AI Copilot</a></td><td>This provides interactive governance reasoning and executive operational intelligence guidance.</td></tr>'

insert4 = '''
            <tr><td>30</td><td><a href="/shift-operational-data-fabric">Operational Data Fabric</a></td><td>This federates operational governance evidence into a unified enterprise intelligence fabric.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-ai-copilot">Executive AI Copilot</a>'

insert5 = '''<a href="/shift-ai-copilot">Executive AI Copilot</a>
            <a href="/shift-operational-data-fabric">Operational Data Fabric</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Operational Data Fabric links added.")
