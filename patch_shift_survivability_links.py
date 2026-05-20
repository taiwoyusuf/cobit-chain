from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_SURVIVABILITY_INDEX_LINKS_ACTIVE"

if MARKER in text:
    print("Survivability Index links already exist.")
    raise SystemExit(0)

if "SHIFT_SURVIVABILITY_INDEX_ACTIVE" not in text:
    raise RuntimeError("Survivability Index marker missing.")

# ------------------------------------------------------------
# Mission Control nav
# ------------------------------------------------------------

target1 = '<a href="/shift-executive-summary">Executive Summary</a>'

insert1 = '''<!-- SHIFT_SURVIVABILITY_INDEX_LINKS_ACTIVE -->
            <a href="/shift-survivability-index">Survivability Index</a>
            <a href="/shift-executive-summary">Executive Summary</a>'''

if target1 not in text:
    raise RuntimeError("Mission Control nav insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Executive Summary nav
# ------------------------------------------------------------

target2 = '<a href="/shift-mission-control">Mission Control</a>'

insert2 = '''<a href="/shift-survivability-index">Survivability Index</a>
            <a href="/shift-mission-control">Mission Control</a>'''

if target2 not in text:
    raise RuntimeError("Executive Summary nav insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target3 = '<a href="/shift-executive-summary">Executive Summary</a>'

insert3 = '''<a href="/shift-survivability-index">Survivability Index</a>
            <a href="/shift-executive-summary">Executive Summary</a>'''

if target3 not in text:
    raise RuntimeError("Advanced Launcher nav insertion point not found.")

text = text.replace(target3, insert3, 1)

# ------------------------------------------------------------
# Modules Directory
# ------------------------------------------------------------

target4 = '<div class="module-card"><span class="badge strategy">EXECUTIVE</span><h3>ShiftTrust™ Executive Summary</h3>'

insert4 = '''<div class="module-card"><span class="badge flagship">SURVIVABILITY</span><h3>ShiftTrust™ Operational Survivability Index</h3><p>Single executive trust score aggregating continuity confidence, governance drift, escalation lineage, peer resilience, operational memory, and survivability stability.</p><a href="/shift-survivability-index">Open Survivability Index</a></div>

<div class="module-card"><span class="badge strategy">EXECUTIVE</span><h3>ShiftTrust™ Executive Summary</h3>'''

if target4 not in text:
    raise RuntimeError("Modules Directory insertion point not found.")

text = text.replace(target4, insert4, 1)

# ------------------------------------------------------------
# Command Center quick access
# ------------------------------------------------------------

target5 = '<a href="/shift-mission-control">Mission Control</a>'

insert5 = '''<a href="/shift-survivability-index">Survivability Index</a>
            <a href="/shift-mission-control">Mission Control</a>'''

if target5 not in text:
    raise RuntimeError("Command Center insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Survivability Index links added.")
