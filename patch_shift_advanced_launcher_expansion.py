from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_ADVANCED_LAUNCHER_EXPANSION_ACTIVE"

if MARKER in text:
    print("Shift Advanced Launcher expansion already exists.")
    raise SystemExit(0)

if "SHIFT_TREATMENT_WINDOW_COMPRESSION_ACTIVE" not in text:
    raise RuntimeError("Treatment Window Compression marker missing.")

target = '<div class="card"><div class="label">Rotation Readiness</div><div class="value">86%</div><p><a href="/shift-rotation-digital-twin">Open Workforce Twin</a></p></div>'

replacement = target + '''
<!-- SHIFT_ADVANCED_LAUNCHER_EXPANSION_ACTIVE -->
<div class="card"><div class="label">Window Compression</div><div class="value">82%</div><p><a href="/shift-treatment-window-compression">Open Compression Simulator</a></p></div>'''

if target not in text:
    raise RuntimeError("Could not find Shift Advanced Launcher insertion point.")

text = text.replace(target, replacement, 1)
APP.write_text(text, encoding="utf-8")

print("Treatment Window Compression added to Shift Advanced Launcher.")
