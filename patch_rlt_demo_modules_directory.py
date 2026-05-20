from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "RLT_DEMO_GUIDE_MODULES_DIRECTORY_ACTIVE"

if MARKER in text:
    print("RLT Demo Guide already registered in Modules Directory.")
    raise SystemExit(0)

target = '<div class="module-card"><span class="badge recovery">RISK HEAT MAP</span><h3>Operational Risk Heat Map</h3><p>Displays executive-level governance risk across isolator readiness, environmental monitoring, shift handoff governance, audit trail review, SOP alignment, and CAPA exposure.</p><a href="/rlt-operations/risk-heatmap">Open Risk Heat Map</a></div>'

insert = target + '''
<!-- RLT_DEMO_GUIDE_MODULES_DIRECTORY_ACTIVE -->
<div class="module-card"><span class="badge twin">DEMO GUIDE</span><h3>RLT Presentation Control Center™</h3><p>Guided executive demo path for presenting RLT operational trust, manufacturing confidence, deviation prevention, batch passport, release confidence, audit reconstruction, digital twin, and enterprise federation.</p><a href="/rlt-demo">Open Demo Guide</a></div>'''

if target not in text:
    raise RuntimeError("Could not find RLT Risk Heat Map card insertion point.")

text = text.replace(target, insert, 1)

APP.write_text(text, encoding="utf-8")

print("RLT Demo Guide added to Modules Directory.")
