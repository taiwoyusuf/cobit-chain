from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_MISSION_CONTROL_PRIMARY_LINK_ACTIVE"

if MARKER in text:
    print("Shift Mission Control primary link already exists.")
    raise SystemExit(0)

if "SHIFT_MISSION_CONTROL_ACTIVE" not in text:
    raise RuntimeError("Shift Mission Control marker missing.")

target = '<a href="/shift-assurance">Shift Assurance</a>'
replacement = '''<!-- SHIFT_MISSION_CONTROL_PRIMARY_LINK_ACTIVE -->
            <a href="/shift-mission-control">Mission Control</a>
            <a href="/shift-assurance">Shift Assurance</a>'''

if target not in text:
    raise RuntimeError("Could not find Shift Advanced nav insertion point.")

text = text.replace(target, replacement, 1)

target2 = '<a href="/shift-advanced" style="display:inline-block;padding:12px 16px;border-radius:14px;'
insert2 = '''<div style="margin-top:10px;">
                <a href="/shift-mission-control" style="display:inline-block;padding:12px 16px;border-radius:14px;
                background:#ffffff;color:#06111f;text-decoration:none;font-weight:900;">
                    Open ShiftTrust™ Mission Control
                </a>
            </div>

            '''

if target2 in text:
    text = text.replace(target2, insert2 + target2, 1)

APP.write_text(text, encoding="utf-8")

print("Shift Mission Control primary links added.")
