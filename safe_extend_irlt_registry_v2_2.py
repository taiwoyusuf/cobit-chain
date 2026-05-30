from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

# Ensure needed Flask imports exist
m = re.search(r"from flask import ([^\n]+)", text)
if not m:
    raise SystemExit("Could not find Flask import line.")

imports = [x.strip() for x in m.group(1).split(",")]
for item in ["render_template_string", "jsonify"]:
    if item not in imports:
        imports.append(item)

text = text[:m.start()] + "from flask import " + ", ".join(imports) + text[m.end():]

# Normalize startup block
text = re.sub(
    r'if __name__ == ["\']__main__["\']:\s*\n\s*app\.run\(debug=True\)',
    'if __name__ == "__main__":\n    app.run(debug=True)',
    text
)

if "IRLT_DYNAMIC_MODULE_REGISTRY_V2_ACTIVE" not in text:
    raise SystemExit("Registry V2 not found. Stop.")

modules_to_add = '''
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

if '"batch-record-review-gate"' not in text:
    route_anchor = '@app.route("/irlt-commercial-readiness/modules-v2")'
    idx = text.find(route_anchor)
    if idx == -1:
        raise SystemExit("Could not find Registry V2 route anchor.")

    before = text[:idx]
    after = text[idx:]

    close_idx = before.rfind("\n}")
    if close_idx == -1:
        raise SystemExit("Could not find Registry V2 dictionary close.")

    text = before[:close_idx] + modules_to_add + before[close_idx:] + after

APP.write_text(text, encoding="utf-8")
print("IRLT Registry V2 extension 2 safely installed.")
