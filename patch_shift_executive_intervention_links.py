from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_EXECUTIVE_INTERVENTION_LINKS_ACTIVE"

if MARKER in text:
    print("Executive Intervention links already exist.")
    raise SystemExit(0)

if "SHIFT_EXECUTIVE_INTERVENTION_SIMULATOR_ACTIVE" not in text:
    raise RuntimeError("Executive Intervention Simulator marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-continuity-shock-simulator">Continuity Shock Simulator</a>'

insert1 = '''<!-- SHIFT_EXECUTIVE_INTERVENTION_LINKS_ACTIVE -->
            <a href="/shift-continuity-shock-simulator">Continuity Shock Simulator</a>
            <a href="/shift-executive-intervention-simulator">Executive Intervention Simulator</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center nav insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Continuity Shock Simulator nav
# ------------------------------------------------------------

target2 = '<a href="/shift-recovery-confidence">Recovery Confidence</a>'

insert2 = '''<a href="/shift-recovery-confidence">Recovery Confidence</a>
            <a href="/shift-executive-intervention-simulator">Executive Intervention Simulator</a>'''

if target2 not in text:
    raise RuntimeError("Continuity Shock nav insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Continuity Shock Simulator™</td><td>Stress-tests operational survivability during disruption, overload, escalation failure, and continuity degradation.</td><td><a href="/shift-continuity-shock-simulator">Open</a></td></tr>'

insert3 = '''
            <tr><td>Executive Intervention Simulator™</td><td>Simulates how leadership timing and governance decisions affect operational survivability and continuity stability.</td><td><a href="/shift-executive-intervention-simulator">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>12</td><td><a href="/shift-continuity-shock-simulator">Continuity Shock Simulator</a></td><td>This stress-tests survivability during operational disruption and escalation overload.</td></tr>'

insert4 = '''
            <tr><td>13</td><td><a href="/shift-executive-intervention-simulator">Executive Intervention Simulator</a></td><td>This simulates how leadership actions change survivability and recovery outcomes.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-continuity-shock-simulator">Continuity Shock Simulator</a>'

insert5 = '''<a href="/shift-continuity-shock-simulator">Continuity Shock Simulator</a>
            <a href="/shift-executive-intervention-simulator">Executive Intervention Simulator</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher nav insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Executive Intervention links added.")
