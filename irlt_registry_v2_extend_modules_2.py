from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_DYNAMIC_MODULE_REGISTRY_V2_ACTIVE"

if MARKER not in text:
    raise SystemExit("IRLT Registry V2 marker not found. Stop and verify app.py.")

NEW_MODULES = r'''
    "batch-record-review-gate": {
        "title": "Batch Record Review Gate",
        "summary": "Governed batch record review layer for completeness, exception review, QA readiness, and inspection defensibility.",
        "score": 96,
        "status": "Verified",
        "category": "Quality",
        "gates": [
            "Batch record completeness",
            "Execution evidence",
            "Review by exception",
            "QA readiness",
            "Release dependency check",
            "Inspection defensibility"
        ]
    },

    "material-readiness-gate": {
        "title": "Material Readiness Gate",
        "summary": "Governed material readiness layer for availability, qualification, inventory accuracy, expiry controls, and shortage escalation.",
        "score": 95,
        "status": "Ready",
        "category": "Supply Chain",
        "gates": [
            "Material availability",
            "Material qualification",
            "Inventory accuracy",
            "Expiry and shelf-life check",
            "Shortage escalation",
            "Inspection defensibility"
        ]
    },

    "equipment-readiness-gate": {
        "title": "Equipment Readiness Gate",
        "summary": "Governed equipment readiness layer for qualification, calibration, maintenance, deviation linkage, and redundancy readiness.",
        "score": 94,
        "status": "Controlled",
        "category": "Manufacturing",
        "gates": [
            "Equipment qualification",
            "Calibration readiness",
            "Preventive maintenance",
            "Equipment deviation linkage",
            "Backup readiness",
            "Inspection defensibility"
        ]
    },

    "change-control-gate": {
        "title": "Change Control Gate",
        "summary": "Governed change-control layer for GMP impact, approvals, implementation evidence, rollback planning, and post-change verification.",
        "score": 95,
        "status": "Controlled",
        "category": "Governance",
        "gates": [
            "Change request definition",
            "GMP impact assessment",
            "Approval lineage",
            "Implementation evidence",
            "Rollback planning",
            "Post-change verification"
        ]
    },

    "validation-gate": {
        "title": "Validation Gate",
        "summary": "Governed validation readiness layer for scope, GMP impact, protocol evidence, deviation handling, and approval to use.",
        "score": 96,
        "status": "Defensible",
        "category": "Validation",
        "gates": [
            "Validation scope",
            "GMP impact classification",
            "Protocol evidence",
            "Validation deviation review",
            "Approval to use",
            "Inspection defensibility"
        ]
    },

    "audit-trail-gate": {
        "title": "Audit Trail Gate",
        "summary": "Governed audit trail readiness layer for critical event review, reviewer accountability, change linkage, and inspection defensibility.",
        "score": 96,
        "status": "Defensible",
        "category": "Audit",
        "gates": [
            "Audit trail availability",
            "Reviewer accountability",
            "Critical event detection",
            "Change-control linkage",
            "Periodic review evidence",
            "Inspection defensibility"
        ]
    },

    "data-reconciliation-gate": {
        "title": "Data Reconciliation Gate",
        "summary": "Governed data reconciliation layer for source data, cross-system consistency, evidence matching, and approval reconciliation.",
        "score": 94,
        "status": "Monitored",
        "category": "Data Integrity",
        "gates": [
            "Source data identification",
            "Cross-system consistency",
            "Evidence-to-data match",
            "Exception detection",
            "Approval reconciliation",
            "Inspection defensibility"
        ]
    },

    "evidence-integrity-gate": {
        "title": "Evidence Integrity Gate",
        "summary": "Governed evidence integrity layer for completeness, authenticity, traceability, approval lineage, and inspection readiness.",
        "score": 98,
        "status": "Verified",
        "category": "Evidence",
        "gates": [
            "Evidence completeness",
            "Evidence traceability",
            "Evidence authenticity",
            "Cross-system linkage",
            "Approval lineage",
            "Inspection readiness"
        ]
    },

    "release-dependency-gate": {
        "title": "Release Dependency Gate",
        "summary": "Governed release dependency layer connecting QA, QC, batch records, cold chain, shipment, and treatment readiness.",
        "score": 96,
        "status": "Active Control",
        "category": "Release Governance",
        "gates": [
            "QA dependency",
            "QC dependency",
            "Batch record dependency",
            "Cold chain dependency",
            "Shipment dependency",
            "Treatment dependency"
        ]
    },

    "executive-readiness-gate": {
        "title": "Executive Readiness Gate",
        "summary": "Executive governance readiness layer for commercialization visibility, risk understanding, decision confidence, and pilot readiness.",
        "score": 97,
        "status": "Executive Ready",
        "category": "Executive",
        "gates": [
            "Readiness visibility",
            "Risk visibility",
            "Evidence confidence",
            "Inspection confidence",
            "Pilot readiness",
            "Decision support"
        ]
    },
'''

if '"batch-record-review-gate"' in text:
    print("Registry extension 2 already exists.")
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

print("IRLT Registry V2 extension 2 added successfully.")
