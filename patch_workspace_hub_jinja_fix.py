from pathlib import Path

p = Path("app.py")
text = p.read_text(encoding="utf-8")

old = "{% for item in group.items %}"
new = "{% for item in group['items'] %}"

if old not in text:
    raise SystemExit("ERROR: Could not find group.items loop.")

text = text.replace(old, new)

p.write_text(text, encoding="utf-8")

print("SUCCESS: Fixed Enterprise Workspace Hub Jinja loop.")
