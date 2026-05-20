from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_HUMAN_DEPENDENCY_LINKS_ACTIVE"

if MARKER in text:
    print("Human Dependency links already exist.")
    raise SystemExit(0)

if "SHIFT_HUMAN_DEPENDENCY_CONCENTRATION_ENGINE_ACTIVE" not in text:
    raise RuntimeError("Human Dependency Engine marker missing.")

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target1 = '<tr><td>Governance Drift Intelligence™</td><td>Detects when temporary workarounds slowly become normalized operational behavior.</td><td><a href="/shift-governance-drift-intelligence">Open</a></td></tr>'

insert1 = '''
            <!-- SHIFT_HUMAN_DEPENDENCY_LINKS_ACTIVE -->
            <tr><td>Human Dependency Concentration Engine™</td><td>Detects hidden operational dependency on specific individuals, tribal knowledge, and fragile recovery ownership.</td><td><a href="/shift-human-dependency">Open</a></td></tr>'''

if target1 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target1, target1 + insert1, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target2 = '<tr><td>9</td><td><a href="/shift-governance-drift-intelligence">Governance Drift Intelligence</a></td><td>This detects hidden governance erosion before operational instability becomes visible.</td></tr>'

insert2 = '''
            <tr><td>10</td><td><a href="/shift-human-dependency">Human Dependency Engine</a></td><td>This identifies fragile operational dependency on specific individuals and hidden tribal knowledge.</td></tr>'''

if target2 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target2, target2 + insert2, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target3 = '<a href="/shift-governance-drift-intelligence">Governance Drift</a>'

insert3 = '''<a href="/shift-governance-drift-intelligence">Governance Drift</a>
            <a href="/shift-human-dependency">Human Dependency</a>'''

if target3 not in text:
    raise RuntimeError("Advanced Launcher nav insertion point not found.")

text = text.replace(target3, insert3, 1)

# ------------------------------------------------------------
# Governance Drift nav
# ------------------------------------------------------------

target4 = '<a href="/shift-advanced">Advanced Launcher</a>'

insert4 = '''<a href="/shift-advanced">Advanced Launcher</a>
            <a href="/shift-human-dependency">Human Dependency</a>'''

if target4 not in text:
    raise RuntimeError("Governance Drift nav insertion point not found.")

text = text.replace(target4, insert4, 1)

APP.write_text(text, encoding="utf-8")

print("Human Dependency links added.")
