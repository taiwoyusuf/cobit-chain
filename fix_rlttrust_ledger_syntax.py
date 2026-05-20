from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

BAD_LINE = '"readiness": "Strong" if evidence_integrity if \'evidence_integrity\' in payload else True else "Warning"'

GOOD_LINE = '"readiness": "Strong" if accountability_score >= 85 and missing_evidence <= 1 and stale_records <= 1 else "Warning"'

if BAD_LINE not in text:
    raise RuntimeError("Bad syntax line was not found. The file may already be fixed or the line is different.")

text = text.replace(BAD_LINE, GOOD_LINE, 1)

APP_PATH.write_text(text, encoding="utf-8")

print("Fixed invalid Radioactive Material Ledger ternary expression.")
