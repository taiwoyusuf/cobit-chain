from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_EXECUTIVE_SUMMARY_MODULES_DIRECTORY_ACTIVE"

if MARKER in text:
    print("Shift Executive Summary already registered in Modules Directory.")
    raise SystemExit(0)

if "SHIFT_EXECUTIVE_SUMMARY_ACTIVE" not in text:
    raise RuntimeError("Shift Executive Summary marker missing.")

anchor = "SHIFT_MISSION_CONTROL_MODULES_DIRECTORY_ACTIVE"
if anchor not in text:
    raise RuntimeError("Shift Mission Control Modules Directory anchor missing.")

target = '<div class="module-card"><span class="badge flagship">SHIFT MISSION</span><h3>ShiftTrust™ Mission Control</h3>'

replacement = '''<!-- SHIFT_EXECUTIVE_SUMMARY_MODULES_DIRECTORY_ACTIVE -->
<div class="module-card"><span class="badge strategy">EXECUTIVE</span><h3>ShiftTrust™ Executive Summary</h3><p>Leadership-ready overview explaining how ShiftTrust™ protects operational survivability, peer resilience, treatment continuity, governance stability, and manufacturing timing confidence.</p><a href="/shift-executive-summary">Open Executive Summary</a></div>
<div class="module-card"><span class="badge flagship">SHIFT MISSION</span><h3>ShiftTrust™ Mission Control</h3>'''

if target not in text:
    raise RuntimeError("Could not find Shift Mission Control card insertion point.")

text = text.replace(target, replacement, 1)

APP.write_text(text, encoding="utf-8")

print("Shift Executive Summary added to Modules Directory.")
