from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_EXECUTIVE_ASSURANCE_MATRIX_LINKS_ACTIVE"

if MARKER in text:
    print("Executive Assurance Matrix links already exist.")
    raise SystemExit(0)

if "SHIFT_EXECUTIVE_ASSURANCE_MATRIX_ACTIVE" not in text:
    raise RuntimeError("Executive Assurance Matrix marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-executive-confidence-fabric">Executive Confidence Fabric</a>'

insert1 = '''<!-- SHIFT_EXECUTIVE_ASSURANCE_MATRIX_LINKS_ACTIVE -->
            <a href="/shift-executive-confidence-fabric">Executive Confidence Fabric</a>
            <a href="/shift-executive-assurance-matrix">Executive Assurance Matrix</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Confidence Fabric nav
# ------------------------------------------------------------

target2 = '<a href="/shift-executive-resilience-orchestrator">Resilience Orchestrator</a>'

insert2 = '''<a href="/shift-executive-resilience-orchestrator">Resilience Orchestrator</a>
            <a href="/shift-executive-assurance-matrix">Executive Assurance Matrix</a>'''

if target2 not in text:
    raise RuntimeError("Confidence Fabric insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Executive Confidence Fabric™</td><td>Models operational trust propagation, assurance confidence, survivability stability, and governance confidence resilience.</td><td><a href="/shift-executive-confidence-fabric">Open</a></td></tr>'

insert3 = '''
            <tr><td>Executive Assurance Matrix™</td><td>Correlates survivability confidence, governance resilience, operational assurance, escalation continuity, and enterprise trust stability.</td><td><a href="/shift-executive-assurance-matrix">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>20</td><td><a href="/shift-executive-confidence-fabric">Executive Confidence Fabric</a></td><td>This models operational trust propagation and governance assurance confidence.</td></tr>'

insert4 = '''
            <tr><td>21</td><td><a href="/shift-executive-assurance-matrix">Executive Assurance Matrix</a></td><td>This correlates survivability assurance, governance resilience, and operational confidence.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-executive-confidence-fabric">Executive Confidence Fabric</a>'

insert5 = '''<a href="/shift-executive-confidence-fabric">Executive Confidence Fabric</a>
            <a href="/shift-executive-assurance-matrix">Executive Assurance Matrix</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Executive Assurance Matrix links added.")
