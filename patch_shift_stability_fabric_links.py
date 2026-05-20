from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_EXECUTIVE_STABILITY_FABRIC_LINKS_ACTIVE"

if MARKER in text:
    print("Executive Stability Fabric links already exist.")
    raise SystemExit(0)

if "SHIFT_EXECUTIVE_STABILITY_FABRIC_ACTIVE" not in text:
    raise RuntimeError("Executive Stability Fabric marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-executive-equilibrium-engine">Executive Equilibrium Engine</a>'

insert1 = '''<!-- SHIFT_EXECUTIVE_STABILITY_FABRIC_LINKS_ACTIVE -->
            <a href="/shift-executive-equilibrium-engine">Executive Equilibrium Engine</a>
            <a href="/shift-executive-stability-fabric">Executive Stability Fabric</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Equilibrium Engine nav
# ------------------------------------------------------------

target2 = '<a href="/shift-executive-governance-pulse">Governance Pulse</a>'

insert2 = '''<a href="/shift-executive-governance-pulse">Governance Pulse</a>
            <a href="/shift-executive-stability-fabric">Executive Stability Fabric</a>'''

if target2 not in text:
    raise RuntimeError("Equilibrium Engine insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Executive Equilibrium Engine™</td><td>Forecasts governance balance, survivability stabilization, continuity harmony, and enterprise operational equilibrium.</td><td><a href="/shift-executive-equilibrium-engine">Open</a></td></tr>'

insert3 = '''
            <tr><td>Executive Stability Fabric™</td><td>Orchestrates governance harmony, survivability stabilization, resilience balance, and enterprise continuity equilibrium.</td><td><a href="/shift-executive-stability-fabric">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>27</td><td><a href="/shift-executive-equilibrium-engine">Executive Equilibrium Engine</a></td><td>This forecasts governance harmony and operational balance equilibrium.</td></tr>'

insert4 = '''
            <tr><td>28</td><td><a href="/shift-executive-stability-fabric">Executive Stability Fabric</a></td><td>This orchestrates survivability balance and enterprise continuity stabilization.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-executive-equilibrium-engine">Executive Equilibrium Engine</a>'

insert5 = '''<a href="/shift-executive-equilibrium-engine">Executive Equilibrium Engine</a>
            <a href="/shift-executive-stability-fabric">Executive Stability Fabric</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Executive Stability Fabric links added.")
