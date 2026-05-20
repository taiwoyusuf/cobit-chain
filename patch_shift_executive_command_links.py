from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_EXECUTIVE_COMMAND_CENTER_LINKS_ACTIVE"

if MARKER in text:
    print("Executive Command Center links already exist.")
    raise SystemExit(0)

if "SHIFT_EXECUTIVE_COMMAND_CENTER_ACTIVE" not in text:
    raise RuntimeError("Executive Command Center marker missing.")

# ------------------------------------------------------------
# Modules Directory
# ------------------------------------------------------------

target1 = '<div class="module-card"><span class="badge flagship">SURVIVABILITY</span><h3>ShiftTrust™ Operational Survivability Index</h3>'

insert1 = '''<!-- SHIFT_EXECUTIVE_COMMAND_CENTER_LINKS_ACTIVE -->
<div class="module-card"><span class="badge flagship">EXECUTIVE</span><h3>ShiftTrust™ Executive Command Center</h3><p>Primary leadership cockpit for survivability intelligence, governance posture, continuity pressure, escalation health, recovery realism, and operational intervention orchestration.</p><a href="/shift-executive-command-center">Open Executive Command Center</a></div>

<div class="module-card"><span class="badge flagship">SURVIVABILITY</span><h3>ShiftTrust™ Operational Survivability Index</h3>'''

if target1 not in text:
    raise RuntimeError("Modules Directory insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Mission Control nav
# ------------------------------------------------------------

target2 = '<a href="/shift-survivability-index">Survivability Index</a>'

insert2 = '''<a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-survivability-index">Survivability Index</a>'''

if target2 not in text:
    raise RuntimeError("Mission Control nav insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Survivability Index nav
# ------------------------------------------------------------

target3 = '<a href="/shift-mission-control">Mission Control</a>'

insert3 = '''<a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-mission-control">Mission Control</a>'''

if target3 not in text:
    raise RuntimeError("Survivability Index nav insertion point not found.")

text = text.replace(target3, insert3, 1)

# ------------------------------------------------------------
# Executive Summary nav
# ------------------------------------------------------------

target4 = '<a href="/shift-survivability-index">Survivability Index</a>'

insert4 = '''<a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-survivability-index">Survivability Index</a>'''

if target4 not in text:
    raise RuntimeError("Executive Summary nav insertion point not found.")

text = text.replace(target4, insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-survivability-index">Survivability Index</a>'

insert5 = '''<a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-survivability-index">Survivability Index</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher nav insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Executive Command Center links added.")
