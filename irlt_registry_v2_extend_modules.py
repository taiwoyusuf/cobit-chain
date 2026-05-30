from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_DYNAMIC_MODULE_REGISTRY_V2_ACTIVE"

if MARKER not in text:
    raise SystemExit("IRLT Registry V2 marker not found. Stop and verify app.py.")

NEW_MODULES = r'''
    "radioactive-material-accountability-gate": {
        "title": "Radioactive Material Accountability Gate",
        "summary": "Governed accountability layer for radioactive material control, custody, usage, reconciliation, and inspection defensibility.",
        "score": 97,
        "status": "Controlled",
        "category": "Radiation Governance",
        "gates": [
            "Material identity confirmation",
            "Custody ownership",
            "Usage reconciliation",
            "Waste or return tracking",
            "Exception escalation",
            "Inspection defensibility"
        ]
    },

    "treatment-slot-protection-gate": {
        "title": "Treatment Slot Protection Gate",
        "summary": "Governed treatment-slot protection layer for dose timing, patient scheduling, delivery readiness, and treatment continuity.",
        "score": 96,
        "status": "Protected",
        "category": "Treatment Coordination",
        "gates": [
            "Patient schedule alignment",
            "Dose timing protection",
            "Site readiness",
            "Shipment arrival window",
            "Exception escalation",
            "Treatment continuity"
        ]
    },

    "qa-release-defensibility-gate": {
        "title": "QA Release Defensibility Gate",
        "summary": "Governed QA release assurance layer for release decision evidence, batch readiness, QC readiness, and inspection defense.",
        "score": 97,
        "status": "Defensible",
        "category": "Quality",
        "gates": [
            "QA disposition evidence",
            "Batch record review",
            "QC release linkage",
            "Deviation review",
            "Approval lineage",
            "Inspection defensibility"
        ]
    },

    "inspection-survivability-gate": {
        "title": "Inspection Survivability Gate",
        "summary": "Governed inspection survivability layer for evidence readiness, response defensibility, audit trail review, and operational proof.",
        "score": 96,
        "status": "Inspection Ready",
        "category": "Inspection",
        "gates": [
            "Evidence completeness",
            "Audit trail readiness",
            "CAPA closure proof",
            "Training defensibility",
            "Release proof",
            "Inspection response package"
        ]
    },

    "supplier-readiness-gate": {
        "title": "Supplier Readiness Gate",
        "summary": "Governed supplier readiness layer for qualification, supplier quality, material dependency, disruption risk, and inspection proof.",
        "score": 94,
        "status": "Monitored",
        "category": "Supply Chain",
        "gates": [
            "Supplier qualification",
            "Supplier quality status",
            "Material dependency",
            "Supply disruption risk",
            "Alternative supplier readiness",
            "Inspection defensibility"
        ]
    },

    "site-readiness-gate": {
        "title": "Site Readiness Gate",
        "summary": "Governed site readiness layer for receiving capability, treatment preparation, operational staffing, and administration readiness.",
        "score": 95,
        "status": "Ready",
        "category": "Site Operations",
        "gates": [
            "Receiving readiness",
            "Treatment preparation",
            "Staffing readiness",
            "Handling capability",
            "Exception escalation",
            "Site evidence package"
        ]
    },

    "deviation-capa-gate": {
        "title": "Deviation CAPA Gate",
        "summary": "Governed deviation and CAPA assurance layer for issue linkage, root cause, effectiveness, closure evidence, and QA defensibility.",
        "score": 93,
        "status": "Active Control",
        "category": "Quality",
        "gates": [
            "Deviation linkage",
            "Impact assessment",
            "CAPA root cause",
            "Effectiveness review",
            "Closure evidence",
            "QA defensibility"
        ]
    },

    "environmental-monitoring-gate": {
        "title": "Environmental Monitoring Gate",
        "summary": "Governed environmental monitoring readiness layer for EM data, excursions, trend review, cleanroom state, and inspection readiness.",
        "score": 94,
        "status": "Monitored",
        "category": "Manufacturing",
        "gates": [
            "EM data availability",
            "Alert and action review",
            "Cleanroom state",
            "Deviation linkage",
            "Trend review",
            "Inspection defensibility"
        ]
    },

    "training-readiness-gate": {
        "title": "Training Readiness Gate",
        "summary": "Governed training readiness layer for role-based training, GMP readiness, system access alignment, and inspection defensibility.",
        "score": 95,
        "status": "Ready",
        "category": "People Readiness",
        "gates": [
            "Role-based assignment",
            "Training completion",
            "GMP readiness",
            "Access alignment",
            "Training drift detection",
            "Inspection defensibility"
        ]
    },

    "commercialization-readiness-gate": {
        "title": "Commercialization Readiness Gate",
        "summary": "Governed commercialization readiness layer combining manufacturing, QA, release, logistics, treatment, evidence, and executive readiness.",
        "score": 97,
        "status": "Launch Ready",
        "category": "Commercialization",
        "gates": [
            "Manufacturing readiness",
            "QA release readiness",
            "Cold chain readiness",
            "Treatment coordination",
            "Evidence readiness",
            "Executive readiness"
        ]
    },
'''

if '"radioactive-material-accountability-gate"' in text:
    print("Registry extension already exists.")
    raise SystemExit()

anchor = "\n}\n\n@app.route(\"/irlt-commercial-readiness/modules-v2\")"

if anchor not in text:
    raise SystemExit("Could not find Registry V2 closing anchor.")

text = text.replace(
    anchor,
    ",\n\n" + NEW_MODULES + anchor,
    1
)

APP.write_text(text, encoding="utf-8")

print("IRLT Registry V2 extended successfully.")
