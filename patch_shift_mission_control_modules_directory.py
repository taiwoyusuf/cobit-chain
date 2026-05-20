from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_MISSION_CONTROL_MODULES_DIRECTORY_ACTIVE"

if MARKER in text:
    print("Shift Mission Control already registered in Modules Directory.")
    raise SystemExit(0)

if "SHIFT_MISSION_CONTROL_ACTIVE" not in text:
    raise RuntimeError("Shift Mission Control marker missing.")

anchor = "SHIFT_ADVANCED_LAUNCHER_MODULES_DIRECTORY_ACTIVE"
if anchor not in text:
    raise RuntimeError("Shift Advanced Launcher Modules Directory anchor missing.")

target = '<div class="module-card"><span class="badge flagship">SHIFT COMMAND</span><h3>ShiftTrust™ Advanced Launcher</h3>'
replacement = '''<!-- SHIFT_MISSION_CONTROL_MODULES_DIRECTORY_ACTIVE -->
<div class="module-card"><span class="badge flagship">SHIFT MISSION</span><h3>ShiftTrust™ Mission Control</h3><p>Primary executive command page for advanced ShiftTrust™: operational trust pulse, treatment continuity, peer backup, topology stability, governance fatigue, window compression, and operational gravity.</p><a href="/shift-mission-control">Open Mission Control</a></div>
<div class="module-card"><span class="badge flagship">SHIFT COMMAND</span><h3>ShiftTrust™ Advanced Launcher</h3>'''

if target not in text:
    raise RuntimeError("Could not find Shift Advanced Launcher card insertion point.")

text = text.replace(target, replacement, 1)

APP.write_text(text, encoding="utf-8")

print("Shift Mission Control added to Modules Directory.")
