from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# RLT_DEMO_GUIDE_NAV_ACTIVE"

if MARKER in text:
    print("RLT demo nav already exists.")
    raise SystemExit(0)

if "RLT_WIDE_ENTERPRISE_UI_ACTIVE" not in text:
    raise RuntimeError("RLT wide UI marker missing.")

target = '<a href="/rlt-operations">Mission Control</a>'
replacement = f'''{target}
                    <!-- RLT_DEMO_GUIDE_NAV_ACTIVE -->
                    <a href="/rlt-demo">Demo Guide</a>'''

if target not in text:
    raise RuntimeError("Could not find RLT top nav Mission Control link.")

text = text.replace(target, replacement, 1)
APP.write_text(text, encoding="utf-8")

print("RLT Demo Guide nav link added.")
