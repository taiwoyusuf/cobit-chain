from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_ADVANCED_LAUNCHER_MODULES_DIRECTORY_ACTIVE"

if MARKER in text:
    print("Shift Advanced Launcher already registered in Modules Directory.")
    raise SystemExit(0)

anchor = "SHIFT_ADVANCED_MODULES_DIRECTORY_ACTIVE"
if anchor not in text:
    raise RuntimeError("Shift advanced modules directory section not found.")

target = '<div class="grid">'
replacement = '''<div class="grid">
<!-- SHIFT_ADVANCED_LAUNCHER_MODULES_DIRECTORY_ACTIVE -->
<div class="module-card"><span class="badge flagship">SHIFT COMMAND</span><h3>ShiftTrust™ Advanced Launcher</h3><p>Single executive launchpad for autonomous continuity, treatment continuity, peer backup, shift topology, and workforce continuity digital twin modules.</p><a href="/shift-advanced">Open ShiftTrust Launcher</a></div>'''

idx = text.find(anchor)
if idx == -1:
    raise RuntimeError("Anchor index not found.")

grid_idx = text.find(target, idx)
if grid_idx == -1:
    raise RuntimeError("Could not find grid inside Shift advanced modules section.")

text = text[:grid_idx] + replacement + text[grid_idx + len(target):]

APP.write_text(text, encoding="utf-8")

print("Shift Advanced Launcher added to Modules Directory.")
