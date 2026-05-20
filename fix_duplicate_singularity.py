from pathlib import Path
import re

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

start_marker = "# ============================================================\n# IRLT_GOVERNANCE_SINGULARITY_ENGINE_V2_ACTIVE"
end_marker = "# ============================================================\n# END IRLT_GOVERNANCE_SINGULARITY_ENGINE_V2\n# ============================================================"

matches = list(
    re.finditer(
        re.escape(start_marker) + r".*?" + re.escape(end_marker),
        text,
        flags=re.DOTALL
    )
)

if len(matches) <= 1:
    print("No duplicate singularity blocks found.")
    raise SystemExit()

first = matches[0]

for m in reversed(matches[1:]):
    text = text[:m.start()] + text[m.end():]

APP.write_text(text, encoding="utf-8")

print("Duplicate Governance Singularity blocks removed safely.")
