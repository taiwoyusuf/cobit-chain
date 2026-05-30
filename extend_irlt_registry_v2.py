from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

if "IRLT_DYNAMIC_MODULE_REGISTRY_V2_ACTIVE" not in text:
    raise SystemExit("IRLT Registry V2 not found.")

if '"radioactive-material-accountability-gate"' in text:
    print("Registry extension already exists.")
    raise SystemExit()

new_modules = '''
,
    "radioactive-material-accountability-gate": {
        "title": "Radioactive Material Accountability Gate",
        "summary": "Governed accountability layer for radioactive material control, custody, usage, reconciliation, and inspection defensibility.",
        "score": 97,
        "status": "Controlled",
        "category": "Radiation Governance",
        "gates": ["Material identity confirmation", "Custody ownership", "Usage reconciliation", "Waste or return tracking", "Exception escalation", "Inspection defensibility"]
    },

    "treatment-slot-protection-gate": {
        "title": "Treatment Slot Protection Gate",
        "summary": "Governed treatment-slot protection layer for dose timing, scheduling, delivery readiness, and treatment continuity.",
        "score": 96,
        "status": "Protected",
        "category": "Treatment Coordination",
        "gates": ["Patient schedule alignment", "Dose timing protection", "Site readiness", "Shipment arrival window", "Exception escalation", "Treatment continuity"]
    },

    "qa-release-defensibility-gate": {
        "title": "QA Release Defensibility Gate",
        "summary": "Governed QA release assurance layer for release decision evidence, batch readiness, QC readiness, and inspection defense.",
        "score": 97,
        "status": "Defensible",
        "category": "Quality",
        "gates": ["QA disposition evidence", "Batch record review", "QC release linkage", "Deviation review", "Approval lineage", "Inspection defensibility"]
    },

    "inspection-survivability-gate": {
        "title": "Inspection Survivability Gate",
        "summary": "Governed inspection survivability layer for evidence readiness, audit trail review, and operational proof.",
        "score": 96,
        "status": "Inspection Ready",
        "category": "Inspection",
        "gates": ["Evidence completeness", "Audit trail readiness", "CAPA closure proof", "Training defensibility", "Release proof", "Inspection response package"]
    },

    "commercialization-readiness-gate": {
        "title": "Commercialization Readiness Gate",
        "summary": "Governed commercialization readiness layer combining manufacturing, QA, release, logistics, treatment, evidence, and executive readiness.",
        "score": 97,
        "status": "Launch Ready",
        "category": "Commercialization",
        "gates": ["Manufacturing readiness", "QA release readiness", "Cold chain readiness", "Treatment coordination", "Evidence readiness", "Executive readiness"]
    }
'''

anchor = '\n}\n\n@app.route("/irlt-commercial-readiness/modules-v2")'

if anchor not in text:
    raise SystemExit("Could not find Registry V2 closing anchor.")

text = text.replace(anchor, new_modules + anchor, 1)

APP.write_text(text, encoding="utf-8")
print("IRLT Registry V2 extension installed.")
