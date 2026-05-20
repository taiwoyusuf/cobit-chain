from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_EXECUTIVE_NARRATIVE_LINKS_ACTIVE"

if MARKER in text:
    print("Shift Executive Narrative links already exist.")
    raise SystemExit(0)

if "SHIFT_EXECUTIVE_NARRATIVE_ENGINE_ACTIVE" not in text:
    raise RuntimeError("Executive Narrative Engine marker missing.")

# ------------------------------------------------------------
# Mission Control link
# ------------------------------------------------------------

mission_target = '<a href="/shift-operational-gravity">Operational Gravity</a>'

mission_replace = '''<a href="/shift-operational-gravity">Operational Gravity</a>
            <!-- SHIFT_EXECUTIVE_NARRATIVE_LINKS_ACTIVE -->
            <a href="/shift-executive-narrative">Executive Narrative</a>'''

if mission_target not in text:
    raise RuntimeError("Mission Control nav insertion point not found.")

text = text.replace(mission_target, mission_replace, 1)

# ------------------------------------------------------------
# Executive Summary demo flow link
# ------------------------------------------------------------

summary_target = '<tr><td>5</td><td><a href="/shift-treatment-window-compression">Window Compression</a></td><td>This shows how unresolved support issues consume timing buffer.</td></tr>'

summary_insert = '''
            <tr><td>6</td><td><a href="/shift-executive-narrative">Executive Narrative Engine</a></td><td>This converts governance telemetry into leadership-ready operational storytelling.</td></tr>'''

if summary_target not in text:
    raise RuntimeError("Executive Summary flow insertion point not found.")

text = text.replace(summary_target, summary_target + summary_insert, 1)

APP.write_text(text, encoding="utf-8")

print("Shift Executive Narrative links added.")
