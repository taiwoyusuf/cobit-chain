from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_AUTONOMOUS_GOVERNANCE_LINKS_ACTIVE"

if MARKER in text:
    print("Autonomous Governance links already exist.")
    raise SystemExit(0)

if "SHIFT_AUTONOMOUS_GOVERNANCE_ENGINE_ACTIVE" not in text:
    raise RuntimeError("Autonomous Governance Engine marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-executive-narrative-generator">Executive Narrative Generator</a>'

insert1 = '''<!-- SHIFT_AUTONOMOUS_GOVERNANCE_LINKS_ACTIVE -->
            <a href="/shift-executive-narrative-generator">Executive Narrative Generator</a>
            <a href="/shift-autonomous-governance-engine">Autonomous Governance Engine</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Operational Collapse nav
# ------------------------------------------------------------

target2 = '<a href="/shift-executive-narrative-generator">Executive Narrative Generator</a>'

insert2 = '''<a href="/shift-executive-narrative-generator">Executive Narrative Generator</a>
            <a href="/shift-autonomous-governance-engine">Autonomous Governance Engine</a>'''

if target2 not in text:
    raise RuntimeError("Operational Collapse insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Executive Narrative Generator™</td><td>Automatically converts survivability intelligence into leadership-ready governance narratives and executive talking points.</td><td><a href="/shift-executive-narrative-generator">Open</a></td></tr>'

insert3 = '''
            <tr><td>Autonomous Governance Engine™</td><td>Autonomously adjusts governance pressure, survivability weighting, escalation intelligence, and continuity stabilization.</td><td><a href="/shift-autonomous-governance-engine">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>15</td><td><a href="/shift-executive-narrative-generator">Executive Narrative Generator</a></td><td>This automatically creates leadership-ready continuity and governance narratives.</td></tr>'

insert4 = '''
            <tr><td>16</td><td><a href="/shift-autonomous-governance-engine">Autonomous Governance Engine</a></td><td>This adaptively adjusts survivability governance and continuity intelligence in real time.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-executive-narrative-generator">Executive Narrative Generator</a>'

insert5 = '''<a href="/shift-executive-narrative-generator">Executive Narrative Generator</a>
            <a href="/shift-autonomous-governance-engine">Autonomous Governance Engine</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Autonomous Governance links added.")
