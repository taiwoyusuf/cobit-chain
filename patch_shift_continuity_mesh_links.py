from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_EXECUTIVE_CONTINUITY_MESH_LINKS_ACTIVE"

if MARKER in text:
    print("Executive Continuity Mesh links already exist.")
    raise SystemExit(0)

if "SHIFT_EXECUTIVE_CONTINUITY_MESH_ACTIVE" not in text:
    raise RuntimeError("Executive Continuity Mesh marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-executive-trust-dynamics">Executive Trust Dynamics</a>'

insert1 = '''<!-- SHIFT_EXECUTIVE_CONTINUITY_MESH_LINKS_ACTIVE -->
            <a href="/shift-executive-trust-dynamics">Executive Trust Dynamics</a>
            <a href="/shift-executive-continuity-mesh">Executive Continuity Mesh</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Trust Dynamics nav
# ------------------------------------------------------------

target2 = '<a href="/shift-executive-recovery-intelligence">Recovery Intelligence</a>'

insert2 = '''<a href="/shift-executive-recovery-intelligence">Recovery Intelligence</a>
            <a href="/shift-executive-continuity-mesh">Executive Continuity Mesh</a>'''

if target2 not in text:
    raise RuntimeError("Trust Dynamics insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Executive Trust Dynamics™</td><td>Forecasts operational trust propagation, governance trust resilience, survivability trust equilibrium, and continuity trust stability.</td><td><a href="/shift-executive-trust-dynamics">Open</a></td></tr>'

insert3 = '''
            <tr><td>Executive Continuity Mesh™</td><td>Models operational interdependencies, survivability propagation, governance continuity relationships, and enterprise resilience connectivity.</td><td><a href="/shift-executive-continuity-mesh">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>24</td><td><a href="/shift-executive-trust-dynamics">Executive Trust Dynamics</a></td><td>This forecasts operational trust propagation and governance trust equilibrium.</td></tr>'

insert4 = '''
            <tr><td>25</td><td><a href="/shift-executive-continuity-mesh">Executive Continuity Mesh</a></td><td>This models enterprise continuity propagation and survivability interdependencies.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-executive-trust-dynamics">Executive Trust Dynamics</a>'

insert5 = '''<a href="/shift-executive-trust-dynamics">Executive Trust Dynamics</a>
            <a href="/shift-executive-continuity-mesh">Executive Continuity Mesh</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Executive Continuity Mesh links added.")
