from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_ADVANCED_LAUNCHER_COMMAND_LINK_ACTIVE"

if MARKER in text:
    print("Shift advanced launcher command link already exists.")
    raise SystemExit(0)

target = '<b>Executive meaning:</b> most shift tools show who is working. ShiftTrust™ now shows whether the'
insert = '''<!-- SHIFT_ADVANCED_LAUNCHER_COMMAND_LINK_ACTIVE -->
            <div style="margin-top:16px;">
                <a href="/shift-advanced" style="display:inline-block;padding:12px 16px;border-radius:14px;
                background:#7fffd4;color:#06111f;text-decoration:none;font-weight:900;">
                    Open ShiftTrust™ Advanced Launcher
                </a>
            </div>

                <b>Executive meaning:</b> most shift tools show who is working. ShiftTrust™ now shows whether the'''

if target not in text:
    raise RuntimeError("Could not find Shift Command Center panel insertion point.")

text = text.replace(target, insert, 1)
APP.write_text(text, encoding="utf-8")

print("Shift advanced launcher link added to Command Center panel.")
