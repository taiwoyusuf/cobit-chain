from pathlib import Path
import re

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

pattern = r'@app\.route\("/irlt-commercial-readiness/governance-singularity"\).*?def irlt_governance_singularity\(\):.*?return jsonify\(\{.*?\}\)\s*'

matches = list(re.finditer(pattern, text, flags=re.DOTALL))

print(f"Found {len(matches)} governance singularity route blocks")

if len(matches) <= 1:
    print("No duplicates found.")
    raise SystemExit()

first = matches[0]

new_text = text[:first.end()]

remaining = text[first.end():]

remaining = re.sub(pattern, "", remaining, flags=re.DOTALL)

new_text += remaining

APP.write_text(new_text, encoding="utf-8")

print("Duplicate governance singularity routes removed safely.")
