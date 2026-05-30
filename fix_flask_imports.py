from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

OLD = "from flask import Flask"

NEW = "from flask import Flask, render_template_string, jsonify"

if NEW in text:
    print("Flask imports already fixed.")
    raise SystemExit()

if OLD not in text:
    print("Could not locate Flask import.")
    raise SystemExit()

text = text.replace(OLD, NEW, 1)

APP.write_text(text, encoding="utf-8")

print("Flask imports fixed.")
