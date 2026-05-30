from pathlib import Path

APP = Path("app.py")
lines = APP.read_text(encoding="utf-8").splitlines()

fixed = []
removed = False

for i, line in enumerate(lines):
    # Remove standalone comma line immediately before batch-record-review-gate
    if line.strip() == ",":
        next_lines = "\n".join(lines[i+1:i+5])
        if '"batch-record-review-gate"' in next_lines:
            removed = True
            continue
    fixed.append(line)

if not removed:
    raise SystemExit("Did not find standalone bad comma before batch-record-review-gate.")

APP.write_text("\n".join(fixed) + "\n", encoding="utf-8")
print("Removed standalone bad comma before batch-record-review-gate.")
