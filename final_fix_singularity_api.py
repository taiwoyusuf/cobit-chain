from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

target = 'def irlt_governance_singularity_api():'

count = text.count(target)

print(f"Found {count} API functions")

if count < 2:
    print("Duplicate API not found.")
    raise SystemExit()

first = text.find(target)

second = text.find(target, first + 1)

before = text[:second]

after = text[second:]

after = after.replace(
    target,
    'def irlt_governance_singularity_api_legacy_disabled():',
    1
)

APP.write_text(before + after, encoding="utf-8")

print("Duplicate API renamed successfully.")
