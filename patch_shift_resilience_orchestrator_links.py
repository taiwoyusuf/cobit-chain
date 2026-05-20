from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_EXECUTIVE_RESILIENCE_ORCHESTRATOR_LINKS_ACTIVE"

if MARKER in text:
    print("Executive Resilience Orchestrator links already exist.")
    raise SystemExit(0)

if "SHIFT_EXECUTIVE_RESILIENCE_ORCHESTRATOR_ACTIVE" not in text:
    raise RuntimeError("Executive Resilience Orchestrator marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-executive-decision-graph">Executive Decision Graph</a>'

insert1 = '''<!-- SHIFT_EXECUTIVE_RESILIENCE_ORCHESTRATOR_LINKS_ACTIVE -->
            <a href="/shift-executive-decision-graph">Executive Decision Graph</a>
            <a href="/shift-executive-resilience-orchestrator">Executive Resilience Orchestrator</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Executive Decision Graph nav
# ------------------------------------------------------------

target2 = '<a href="/shift-executive-digital-twin">Executive Digital Twin</a>'

insert2 = '''<a href="/shift-executive-digital-twin">Executive Digital Twin</a>
            <a href="/shift-executive-resilience-orchestrator">Executive Resilience Orchestrator</a>'''

if target2 not in text:
    raise RuntimeError("Executive Decision Graph insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Executive Decision Graph™</td><td>Visualizes governance dependencies, intervention relationships, survivability lineage, and operational consequence chains.</td><td><a href="/shift-executive-decision-graph">Open</a></td></tr>'

insert3 = '''
            <tr><td>Executive Resilience Orchestrator™</td><td>Coordinates survivability stabilization, governance resilience, escalation continuity, and operational recovery prioritization.</td><td><a href="/shift-executive-resilience-orchestrator">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>18</td><td><a href="/shift-executive-decision-graph">Executive Decision Graph</a></td><td>This visualizes governance dependencies and survivability consequence chains.</td></tr>'

insert4 = '''
            <tr><td>19</td><td><a href="/shift-executive-resilience-orchestrator">Executive Resilience Orchestrator</a></td><td>This coordinates survivability stabilization and enterprise continuity resilience.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-executive-decision-graph">Executive Decision Graph</a>'

insert5 = '''<a href="/shift-executive-decision-graph">Executive Decision Graph</a>
            <a href="/shift-executive-resilience-orchestrator">Executive Resilience Orchestrator</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Executive Resilience Orchestrator links added.")
