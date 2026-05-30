from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

start = text.find('IRLT_DYNAMIC_MODULES_V2 = {')
route = text.find('@app.route("/irlt-commercial-readiness/modules-v2")', start)

if start == -1 or route == -1:
    raise SystemExit("Could not find Registry V2 block.")

# Remove broken extension 2 if present
broken_start = text.find('"batch-record-review-gate"', start, route)
if broken_start != -1:
    # include bad comma before it if present
    remove_start = text.rfind("\n,", start, broken_start)
    if remove_start == -1:
        remove_start = broken_start

    text = text[:remove_start] + text[route:]

# Recalculate route after cleanup
start = text.find('IRLT_DYNAMIC_MODULES_V2 = {')
route = text.find('@app.route("/irlt-commercial-readiness/modules-v2")', start)
dict_close = text.rfind("\n}", start, route)

if dict_close == -1:
    raise SystemExit("Could not find Registry V2 dictionary close.")

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

    "material-readiness-gate": {
        "title": "Material Readiness Gate",
        "summary": "Governed material readiness layer for availability, qualification, inventory accuracy, expiry controls, and shortage escalation.",
        "score": 95,
        "status": "Ready",
        "category": "Supply Chain",
        "gates": ["Material availability", "Material qualification", "Inventory accuracy", "Expiry and shelf-life check", "Shortage escalation", "Inspection defensibility"]
    },

    "equipment-readiness-gate": {
        "title": "Equipment Readiness Gate",
        "summary": "Governed equipment readiness layer for qualification, calibration, maintenance, deviation linkage, and redundancy readiness.",
        "score": 94,
        "status": "Controlled",
        "category": "Manufacturing",
        "gates": ["Equipment qualification", "Calibration readiness", "Preventive maintenance", "Equipment deviation linkage", "Backup readiness", "Inspection defensibility"]
    },

    "change-control-gate": {
        "title": "Change Control Gate",
        "summary": "Governed change-control layer for GMP impact, approvals, implementation evidence, rollback planning, and post-change verification.",
        "score": 95,
        "status": "Controlled",
        "category": "Governance",
        "gates": ["Change request definition", "GMP impact assessment", "Approval lineage", "Implementation evidence", "Rollback planning", "Post-change verification"]
    },

    "validation-gate": {
        "title": "Validation Gate",
        "summary": "Governed validation readiness layer for scope, GMP impact, protocol evidence, deviation handling, and approval to use.",
        "score": 96,
        "status": "Defensible",
        "category": "Validation",
        "gates": ["Validation scope", "GMP impact classification", "Protocol evidence", "Validation deviation review", "Approval to use", "Inspection defensibility"]
    },

    "audit-trail-gate": {
        "title": "Audit Trail Gate",
        "summary": "Governed audit trail readiness layer for critical event review, reviewer accountability, change linkage, and inspection defensibility.",
        "score": 96,
        "status": "Defensible",
        "category": "Audit",
        "gates": ["Audit trail availability", "Reviewer accountability", "Critical event detection", "Change-control linkage", "Periodic review evidence", "Inspection defensibility"]
    },

    "data-reconciliation-gate": {
        "title": "Data Reconciliation Gate",
        "summary": "Governed data reconciliation layer for source data, cross-system consistency, evidence matching, and approval reconciliation.",
        "score": 94,
        "status": "Monitored",
        "category": "Data Integrity",
        "gates": ["Source data identification", "Cross-system consistency", "Evidence-to-data match", "Exception detection", "Approval reconciliation", "Inspection defensibility"]
    },

    "evidence-integrity-gate": {
        "title": "Evidence Integrity Gate",
        "summary": "Governed evidence integrity layer for completeness, authenticity, traceability, approval lineage, and inspection readiness.",
        "score": 98,
        "status": "Verified",
        "category": "Evidence",
        "gates": ["Evidence completeness", "Evidence traceability", "Evidence authenticity", "Cross-system linkage", "Approval lineage", "Inspection readiness"]
    },

    "release-dependency-gate": {
        "title": "Release Dependency Gate",
        "summary": "Governed release dependency layer connecting QA, QC, batch records, cold chain, shipment, and treatment readiness.",
        "score": 96,
        "status": "Active Control",
        "category": "Release Governance",
        "gates": ["QA dependency", "QC dependency", "Batch record dependency", "Cold chain dependency", "Shipment dependency", "Treatment dependency"]
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

text = text[:dict_close] + addition + text[dict_close:]

APP.write_text(text, encoding="utf-8")
print("Broken extension fixed and Registry V2 extension 2 installed correctly.")
