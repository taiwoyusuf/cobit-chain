from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_ESCALATION_LINEAGE_LINKS_ACTIVE"

if MARKER in text:
    print("Escalation Lineage links already exist.")
    raise SystemExit(0)

if "SHIFT_ESCALATION_LINEAGE_ENGINE_ACTIVE" not in text:
    raise RuntimeError("Escalation Lineage Engine marker missing.")

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target1 = '<tr><td>Operational Memory Engine™</td><td>Protects escalation lineage, inherited context, unresolved issue continuity, and operational knowledge persistence.</td><td><a href="/shift-operational-memory">Open</a></td></tr>'

insert1 = '''
            <!-- SHIFT_ESCALATION_LINEAGE_LINKS_ACTIVE -->
            <tr><td>Escalation Lineage Engine™</td><td>Tracks escalation inheritance, ownership continuity, orphaned escalation risk, and governance accountability across shifts.</td><td><a href="/shift-escalation-lineage">Open</a></td></tr>'''

if target1 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target1, target1 + insert1, 1)

# ------------------------------------------------------------
# Executive Summary demo flow
# ------------------------------------------------------------

target2 = '<tr><td>7</td><td><a href="/shift-operational-memory">Operational Memory Engine</a></td><td>This proves continuity intelligence and escalation inheritance survive shift handoff.</td></tr>'

insert2 = '''
            <tr><td>8</td><td><a href="/shift-escalation-lineage">Escalation Lineage Engine</a></td><td>This proves escalation ownership and accountability survive permanent shift handoff.</td></tr>'''

if target2 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target2, target2 + insert2, 1)

# ------------------------------------------------------------
# Advanced launcher navigation
# ------------------------------------------------------------

target3 = '<a href="/shift-operational-memory">Operational Memory</a>'

insert3 = '''<a href="/shift-operational-memory">Operational Memory</a>
            <a href="/shift-escalation-lineage">Escalation Lineage</a>'''

if target3 not in text:
    raise RuntimeError("Advanced Launcher nav insertion point not found.")

text = text.replace(target3, insert3, 1)

APP.write_text(text, encoding="utf-8")

print("Escalation Lineage links added.")
