from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "ENTERPRISE_RECONCILIATION_MATRIX_EXPANDED"

if MARKER in text:
    print("Enterprise reconciliation matrix already expanded.")
    raise SystemExit(0)

old_block = """
    reconciliation_cases = [
"""

new_block = """
    # ENTERPRISE_RECONCILIATION_MATRIX_EXPANDED

    reconciliation_cases = [
        {
            "workflow": "Veeva ↔ Blue Mountain Periodic Review",
            "middleware": "Veeva Review Approved",
            "lis": "Blue Mountain Review Pending",
            "downstream": "Equipment still operational",
            "servicenow": "Closed",
            "cobitchain_truth": "NOT RECONCILED",
            "issue": "Document approval completed but validated equipment review dependency remains incomplete.",
            "impact": "Weak GMP defensibility and incomplete review chain.",
            "risk": "HIGH"
        },
        {
            "workflow": "ServiceNow ↔ myAccess Access Validation",
            "middleware": "ServiceNow Access Request Closed",
            "lis": "myAccess Role Not Yet Provisioned",
            "downstream": "User still blocked",
            "servicenow": "Closed",
            "cobitchain_truth": "FALSE COMPLETION",
            "issue": "Ticket closure occurred before IAM provisioning completed.",
            "impact": "Operational access mismatch and governance drift.",
            "risk": "HIGH"
        },
        {
            "workflow": "Middleware ↔ LIS ↔ Downstream Release",
            "middleware": "Verified",
            "lis": "Held",
            "downstream": "Unavailable",
            "servicenow": "Closed",
            "cobitchain_truth": "NOT RECONCILED",
            "issue": "Verification completed but release dependency chain is incomplete.",
            "impact": "False release assumption and audit exposure.",
            "risk": "HIGH"
        },
        {
            "workflow": "Batch Disposition Dependency Validation",
            "middleware": "QC Testing Complete",
            "lis": "QA Review Pending",
            "downstream": "Batch Hold",
            "servicenow": "Resolved",
            "cobitchain_truth": "BLOCKED",
            "issue": "Batch disposition dependency chain incomplete.",
            "impact": "Release readiness cannot be trusted.",
            "risk": "HIGH"
        },
        {
            "workflow": "QC Release Dependency Chain",
            "middleware": "Instrument Data Approved",
            "lis": "Second Reviewer Pending",
            "downstream": "Release Certificate Not Generated",
            "servicenow": "Closed",
            "cobitchain_truth": "PARTIAL",
            "issue": "QC release chain incomplete despite operational closure.",
            "impact": "Weak release defensibility.",
            "risk": "MEDIUM"
        },
        {
            "workflow": "Deviation ↔ CAPA Dependency Mapping",
            "middleware": "Deviation Closed",
            "lis": "CAPA Still Open",
            "downstream": "Effectiveness Check Pending",
            "servicenow": "Closed",
            "cobitchain_truth": "REOPEN REQUIRED",
            "issue": "Deviation closure occurred before CAPA effectiveness completion.",
            "impact": "Weak quality governance closure.",
            "risk": "HIGH"
        },
        {
            "workflow": "ERP ↔ MES ↔ LIMS Governance Validation",
            "middleware": "MES Batch Complete",
            "lis": "LIMS Result Pending",
            "downstream": "ERP Inventory Updated",
            "servicenow": "Closed",
            "cobitchain_truth": "MISMATCH",
            "issue": "Enterprise systems disagree on manufacturing completion state.",
            "impact": "Operational truth inconsistency across manufacturing stack.",
            "risk": "HIGH"
        },
"""

if old_block not in text:
    raise SystemExit("ERROR: Could not find reconciliation_cases block.")

text = text.replace(old_block, new_block, 1)

required = [
    "ENTERPRISE_RECONCILIATION_MATRIX_EXPANDED",
    "Veeva ↔ Blue Mountain Periodic Review",
    "ServiceNow ↔ myAccess Access Validation",
    "ERP ↔ MES ↔ LIMS Governance Validation",
    "Deviation ↔ CAPA Dependency Mapping"
]

missing = [x for x in required if x not in text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

APP.write_text(text, encoding="utf-8")

print("SUCCESS: Governance Reconciliation Layer expanded with enterprise reconciliation matrix.")
