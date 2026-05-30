from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

route_anchor = '@app.route("/irlt-commercial-readiness/modules-v2")'
route_pos = text.find(route_anchor)

if route_pos == -1:
    raise SystemExit("Could not find modules-v2 route anchor.")

# Remove broken misplaced extension from outside dictionary
bad_start = text.rfind('\n    ,', 0, route_pos)
batch_pos = text.find('"batch-record-review-gate"', bad_start, route_pos)

if bad_start != -1 and batch_pos != -1:
    text = text[:bad_start] + "\n\n" + text[route_pos:]
    print("Removed broken misplaced extension.")
else:
    print("No misplaced extension block found.")

# Re-find clean route position
route_pos = text.find(route_anchor)

# Find actual dictionary close before route
dict_close = text.rfind("\n}", 0, route_pos)

if dict_close == -1:
    raise SystemExit("Could not find registry dictionary close.")

addition = '''
,
    "batch-record-review-gate": {
        "title": "Batch Record Review Gate",
        "summary": "Governed batch record review layer for completeness, exception review, QA readiness, and inspection defensibility.",
        "score": 96,
        "status": "Verified",
        "category": "Quality",
        "gates": ["Batch record completeness", "Execution evidence", "Review by exception", "QA readiness", "Release dependency check", "Inspection defensibility"]
    },

    "executive-readiness-gate": {
        "title": "Executive Readiness Gate",
        "summary": "Executive governance readiness layer for commercialization visibility, risk understanding, decision confidence, and pilot readiness.",
        "score": 97,
        "status": "Executive Ready",
        "category": "Executive",
        "gates": ["Readiness visibility", "Risk visibility", "Evidence confidence", "Inspection confidence", "Pilot readiness", "Decision support"]
    }
'''

if '"batch-record-review-gate"' not in text[:route_pos]:
    text = text[:dict_close] + addition + text[dict_close:]
    print("Inserted extension correctly inside registry dictionary.")
else:
    print("Extension already exists inside registry dictionary.")

APP.write_text(text, encoding="utf-8")
print("Repair complete.")
