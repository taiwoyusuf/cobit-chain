from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

target = 'def irlt_governance_singularity():'

count = text.count(target)

print(f"Found {count} singularity functions")

if count <= 1:
    print("No duplicate functions found.")
    raise SystemExit()

first_index = text.find(target)

second_index = text.find(target, first_index + 1)

text = (
    text[:second_index]
    + text[second_index:].replace(
        target,
        'def irlt_governance_singularity_legacy_disabled():',
        1
    )
)

APP.write_text(text, encoding="utf-8")

print("Duplicate singularity function renamed safely.")
