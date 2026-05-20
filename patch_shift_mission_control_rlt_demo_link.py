from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_MISSION_CONTROL_RLT_DEMO_LINK_ACTIVE"

if MARKER in text:
    print("Shift Mission Control already linked in RLT demo.")
    raise SystemExit(0)

if "SHIFT_MISSION_CONTROL_ACTIVE" not in text:
    raise RuntimeError("Shift Mission Control marker missing.")

if "RLT_DEMO_GUIDE_ACTIVE" not in text:
    raise RuntimeError("RLT Demo Guide marker missing.")

target = '<tr><td><span class="pill">Step 3</span></td><td>Live Manufacturing Confidence</td><td>Show confidence movement, not only static status.</td><td><a href="/rlt-operations/manufacturing-confidence">Open</a></td></tr>'

insert = '''<!-- SHIFT_MISSION_CONTROL_RLT_DEMO_LINK_ACTIVE -->
            <tr><td><span class="pill">Step 3A</span></td><td>ShiftTrust™ Mission Control</td><td>Show operational survivability, peer backup, treatment-continuity risk, governance fatigue, and timing-window compression.</td><td><a href="/shift-mission-control">Open</a></td></tr>'''

if target not in text:
    raise RuntimeError("Could not find RLT demo flow insertion point.")

text = text.replace(target, target + "\n" + insert, 1)

APP.write_text(text, encoding="utf-8")

print("Shift Mission Control added to RLT demo guide.")
