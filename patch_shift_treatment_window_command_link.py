from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_TREATMENT_WINDOW_COMMAND_LINK_ACTIVE"

if MARKER in text:
    print("Treatment Window Command Center link already exists.")
    raise SystemExit(0)

if "SHIFT_TREATMENT_WINDOW_COMPRESSION_ACTIVE" not in text:
    raise RuntimeError("Treatment Window Compression marker missing.")

target = '<a href="/shift-advanced" style="display:inline-block;padding:12px 16px;border-radius:14px;'
if target not in text:
    raise RuntimeError("Could not find Shift Advanced launcher command link insertion point.")

insert = '''<!-- SHIFT_TREATMENT_WINDOW_COMMAND_LINK_ACTIVE -->
            <div style="margin-top:10px;">
                <a href="/shift-treatment-window-compression" style="display:inline-block;padding:12px 16px;border-radius:14px;
                background:#0ea5e9;color:#ffffff;text-decoration:none;font-weight:900;">
                    Open Treatment Window Compression Simulator
                </a>
            </div>

            '''

text = text.replace(target, insert + target, 1)
APP.write_text(text, encoding="utf-8")

print("Treatment Window Compression link added to Command Center panel.")
