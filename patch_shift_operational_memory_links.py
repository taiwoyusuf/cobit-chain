from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_OPERATIONAL_MEMORY_LINKS_ACTIVE"

if MARKER in text:
    print("Operational Memory links already exist.")
    raise SystemExit(0)

if "SHIFT_OPERATIONAL_MEMORY_ENGINE_ACTIVE" not in text:
    raise RuntimeError("Operational Memory Engine marker missing.")

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target1 = '<tr><td>Operational Gravity Engine™</td><td>Which unresolved issue is pulling the whole operation toward instability.</td><td><a href="/shift-operational-gravity">Open</a></td></tr>'

insert1 = '''
            <!-- SHIFT_OPERATIONAL_MEMORY_LINKS_ACTIVE -->
            <tr><td>Operational Memory Engine™</td><td>Protects escalation lineage, inherited context, unresolved issue continuity, and operational knowledge persistence.</td><td><a href="/shift-operational-memory">Open</a></td></tr>'''

if target1 not in text:
    raise RuntimeError("Mission Control capability insertion point not found.")

text = text.replace(target1, target1 + insert1, 1)

# ------------------------------------------------------------
# Executive Summary demo flow
# ------------------------------------------------------------

target2 = '<tr><td>6</td><td><a href="/shift-executive-narrative">Executive Narrative Engine</a></td><td>This converts governance telemetry into leadership-ready operational storytelling.</td></tr>'

insert2 = '''
            <tr><td>7</td><td><a href="/shift-operational-memory">Operational Memory Engine</a></td><td>This proves continuity intelligence and escalation inheritance survive shift handoff.</td></tr>'''

if target2 not in text:
    raise RuntimeError("Executive Summary flow insertion point not found.")

text = text.replace(target2, target2 + insert2, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target3 = '<a href="/shift-operational-gravity">Operational Gravity</a>'

insert3 = '''<a href="/shift-operational-gravity">Operational Gravity</a>
            <a href="/shift-operational-memory">Operational Memory</a>'''

if target3 not in text:
    raise RuntimeError("Advanced Launcher nav insertion point not found.")

text = text.replace(target3, insert3, 1)

APP.write_text(text, encoding="utf-8")

print("Operational Memory links added.")
