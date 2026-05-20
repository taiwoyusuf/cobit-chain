from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_GOVERNANCE_DRIFT_INTELLIGENCE_LINKS_ACTIVE"

if MARKER in text:
    print("Governance Drift Intelligence links already exist.")
    raise SystemExit(0)

if "SHIFT_GOVERNANCE_DRIFT_INTELLIGENCE_ACTIVE" not in text:
    raise RuntimeError("Governance Drift Intelligence marker missing.")

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target1 = '<tr><td>Escalation Lineage Engine™</td><td>Tracks escalation inheritance, ownership continuity, orphaned escalation risk, and governance accountability across shifts.</td><td><a href="/shift-escalation-lineage">Open</a></td></tr>'

insert1 = '''
            <!-- SHIFT_GOVERNANCE_DRIFT_INTELLIGENCE_LINKS_ACTIVE -->
            <tr><td>Governance Drift Intelligence™</td><td>Detects when temporary workarounds slowly become normalized operational behavior.</td><td><a href="/shift-governance-drift-intelligence">Open</a></td></tr>'''

if target1 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target1, target1 + insert1, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target2 = '<tr><td>8</td><td><a href="/shift-escalation-lineage">Escalation Lineage Engine</a></td><td>This proves escalation ownership and accountability survive permanent shift handoff.</td></tr>'

insert2 = '''
            <tr><td>9</td><td><a href="/shift-governance-drift-intelligence">Governance Drift Intelligence</a></td><td>This detects hidden governance erosion before operational instability becomes visible.</td></tr>'''

if target2 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target2, target2 + insert2, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target3 = '<a href="/shift-escalation-lineage">Escalation Lineage</a>'

insert3 = '''<a href="/shift-escalation-lineage">Escalation Lineage</a>
            <a href="/shift-governance-drift-intelligence">Governance Drift</a>'''

if target3 not in text:
    raise RuntimeError("Advanced Launcher nav insertion point not found.")

text = text.replace(target3, insert3, 1)

# ------------------------------------------------------------
# Executive Narrative nav
# ------------------------------------------------------------

target4 = '<a href="/shift-advanced">Advanced Launcher</a>'

insert4 = '''<a href="/shift-advanced">Advanced Launcher</a>
            <a href="/shift-governance-drift-intelligence">Governance Drift</a>'''

if target4 not in text:
    raise RuntimeError("Executive Narrative nav insertion point not found.")

text = text.replace(target4, insert4, 1)

APP.write_text(text, encoding="utf-8")

print("Governance Drift Intelligence links added.")
