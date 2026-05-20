from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_EXECUTIVE_STABILITY_ENGINE_LINKS_ACTIVE"

if MARKER in text:
    print("Executive Stability Engine links already exist.")
    raise SystemExit(0)

if "SHIFT_EXECUTIVE_STABILITY_ENGINE_ACTIVE" not in text:
    raise RuntimeError("Executive Stability Engine marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-executive-assurance-matrix">Executive Assurance Matrix</a>'

insert1 = '''<!-- SHIFT_EXECUTIVE_STABILITY_ENGINE_LINKS_ACTIVE -->
            <a href="/shift-executive-assurance-matrix">Executive Assurance Matrix</a>
            <a href="/shift-executive-stability-engine">Executive Stability Engine</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Assurance Matrix nav
# ------------------------------------------------------------

target2 = '<a href="/shift-executive-confidence-fabric">Confidence Fabric</a>'

insert2 = '''<a href="/shift-executive-confidence-fabric">Confidence Fabric</a>
            <a href="/shift-executive-stability-engine">Executive Stability Engine</a>'''

if target2 not in text:
    raise RuntimeError("Assurance Matrix insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Executive Assurance Matrix™</td><td>Correlates survivability confidence, governance resilience, operational assurance, escalation continuity, and enterprise trust stability.</td><td><a href="/shift-executive-assurance-matrix">Open</a></td></tr>'

insert3 = '''
            <tr><td>Executive Stability Engine™</td><td>Forecasts governance equilibrium, survivability resilience, escalation continuity, and enterprise operational stability.</td><td><a href="/shift-executive-stability-engine">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>21</td><td><a href="/shift-executive-assurance-matrix">Executive Assurance Matrix</a></td><td>This correlates survivability assurance, governance resilience, and operational confidence.</td></tr>'

insert4 = '''
            <tr><td>22</td><td><a href="/shift-executive-stability-engine">Executive Stability Engine</a></td><td>This forecasts governance equilibrium and enterprise continuity stability.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-executive-assurance-matrix">Executive Assurance Matrix</a>'

insert5 = '''<a href="/shift-executive-assurance-matrix">Executive Assurance Matrix</a>
            <a href="/shift-executive-stability-engine">Executive Stability Engine</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Executive Stability Engine links added.")
