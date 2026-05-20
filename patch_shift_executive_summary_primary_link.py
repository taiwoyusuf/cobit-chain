from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_EXECUTIVE_SUMMARY_PRIMARY_LINK_ACTIVE"

if MARKER in text:
    print("Shift Executive Summary primary link already exists.")
    raise SystemExit(0)

if "SHIFT_EXECUTIVE_SUMMARY_ACTIVE" not in text:
    raise RuntimeError("Shift Executive Summary marker missing.")

target = '<a href="/shift-mission-control">Mission Control</a>'
replacement = '''<!-- SHIFT_EXECUTIVE_SUMMARY_PRIMARY_LINK_ACTIVE -->
            <a href="/shift-executive-summary">Executive Summary</a>
            <a href="/shift-mission-control">Mission Control</a>'''

if target not in text:
    raise RuntimeError("Could not find Shift Mission Control nav link insertion point.")

text = text.replace(target, replacement, 1)

APP.write_text(text, encoding="utf-8")

print("Shift Executive Summary primary link added.")
