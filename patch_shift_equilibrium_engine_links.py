from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_EXECUTIVE_EQUILIBRIUM_ENGINE_LINKS_ACTIVE"

if MARKER in text:
    print("Executive Equilibrium Engine links already exist.")
    raise SystemExit(0)

if "SHIFT_EXECUTIVE_EQUILIBRIUM_ENGINE_ACTIVE" not in text:
    raise RuntimeError("Executive Equilibrium Engine marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-executive-governance-pulse">Executive Governance Pulse</a>'

insert1 = '''<!-- SHIFT_EXECUTIVE_EQUILIBRIUM_ENGINE_LINKS_ACTIVE -->
            <a href="/shift-executive-governance-pulse">Executive Governance Pulse</a>
            <a href="/shift-executive-equilibrium-engine">Executive Equilibrium Engine</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Governance Pulse nav
# ------------------------------------------------------------

target2 = '<a href="/shift-executive-continuity-mesh">Continuity Mesh</a>'

insert2 = '''<a href="/shift-executive-continuity-mesh">Continuity Mesh</a>
            <a href="/shift-executive-equilibrium-engine">Executive Equilibrium Engine</a>'''

if target2 not in text:
    raise RuntimeError("Governance Pulse insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Executive Governance Pulse™</td><td>Monitors governance heartbeat, survivability pressure, operational assurance health, and resilience trajectory in real time.</td><td><a href="/shift-executive-governance-pulse">Open</a></td></tr>'

insert3 = '''
            <tr><td>Executive Equilibrium Engine™</td><td>Forecasts governance balance, survivability stabilization, continuity harmony, and enterprise operational equilibrium.</td><td><a href="/shift-executive-equilibrium-engine">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>26</td><td><a href="/shift-executive-governance-pulse">Executive Governance Pulse</a></td><td>This monitors governance heartbeat and enterprise resilience pressure in real time.</td></tr>'

insert4 = '''
            <tr><td>27</td><td><a href="/shift-executive-equilibrium-engine">Executive Equilibrium Engine</a></td><td>This forecasts governance harmony and operational balance equilibrium.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-executive-governance-pulse">Executive Governance Pulse</a>'

insert5 = '''<a href="/shift-executive-governance-pulse">Executive Governance Pulse</a>
            <a href="/shift-executive-equilibrium-engine">Executive Equilibrium Engine</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Executive Equilibrium Engine links added.")
