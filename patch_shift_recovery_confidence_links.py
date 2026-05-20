from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_RECOVERY_CONFIDENCE_LINKS_ACTIVE"

if MARKER in text:
    print("Recovery Confidence links already exist.")
    raise SystemExit(0)

if "SHIFT_RECOVERY_CONFIDENCE_ENGINE_ACTIVE" not in text:
    raise RuntimeError("Recovery Confidence Engine marker missing.")

# ------------------------------------------------------------
# Survivability Index nav
# ------------------------------------------------------------

target1 = '<a href="/shift-human-dependency">Human Dependency</a>'

insert1 = '''<!-- SHIFT_RECOVERY_CONFIDENCE_LINKS_ACTIVE -->
            <a href="/shift-human-dependency">Human Dependency</a>
            <a href="/shift-recovery-confidence">Recovery Confidence</a>'''

if target1 not in text:
    raise RuntimeError("Survivability Index nav insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target2 = '<tr><td>Human Dependency Concentration Engine™</td><td>Detects hidden operational dependency on specific individuals, tribal knowledge, and fragile recovery ownership.</td><td><a href="/shift-human-dependency">Open</a></td></tr>'

insert2 = '''
            <tr><td>Recovery Confidence Engine™</td><td>Predicts whether operational continuity can realistically recover after disruption while preserving governance stability.</td><td><a href="/shift-recovery-confidence">Open</a></td></tr>'''

if target2 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target2, target2 + insert2, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target3 = '<tr><td>10</td><td><a href="/shift-human-dependency">Human Dependency Engine</a></td><td>This identifies fragile operational dependency on specific individuals and hidden tribal knowledge.</td></tr>'

insert3 = '''
            <tr><td>11</td><td><a href="/shift-recovery-confidence">Recovery Confidence Engine</a></td><td>This predicts whether operational continuity can realistically recover after disruption.</td></tr>'''

if target3 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target4 = '<a href="/shift-human-dependency">Human Dependency</a>'

insert4 = '''<a href="/shift-human-dependency">Human Dependency</a>
            <a href="/shift-recovery-confidence">Recovery Confidence</a>'''

if target4 not in text:
    raise RuntimeError("Advanced Launcher nav insertion point not found.")

text = text.replace(target4, insert4, 1)

APP.write_text(text, encoding="utf-8")

print("Recovery Confidence links added.")
