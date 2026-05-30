from pathlib import Path
import ast
import pprint

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

TARGET = "IRLT_DYNAMIC_MODULES_V2"

new_entries = {
    "release-decision-intelligence-gate": {
        "title": "Release Decision Intelligence Gate",
        "summary": "Governed release-decision intelligence layer for QA disposition, evidence readiness, dependency validation, and executive release confidence.",
        "score": 96,
        "status": "Defensible",
        "category": "Release Governance",
        "gates": [
            "QA disposition review",
            "Evidence readiness",
            "Dependency validation",
            "Deviation impact check",
            "Approval lineage",
            "Executive release confidence"
        ]
    },

    "batch-disposition-gate": {
        "title": "Batch Disposition Gate",
        "summary": "Governed batch disposition layer for batch review, QC confirmation, deviation status, QA decision, and release defensibility.",
        "score": 96,
        "status": "Controlled",
        "category": "Quality",
        "gates": [
            "Batch review completion",
            "QC confirmation",
            "Deviation status check",
            "QA disposition",
            "Release decision evidence",
            "Inspection defensibility"
        ]
    },

    "isotope-lineage-gate": {
        "title": "Isotope Lineage Gate",
        "summary": "Governed isotope lineage layer for radioactive source traceability, production linkage, decay timing, custody, and accountability.",
        "score": 97,
        "status": "Verified",
        "category": "Radiation Governance",
        "gates": [
            "Isotope source traceability",
            "Production linkage",
            "Decay timing awareness",
            "Custody accountability",
            "Usage reconciliation",
            "Regulatory defensibility"
        ]
    },

    "executive-commercial-readiness-gate": {
        "title": "Executive Commercial Readiness Gate",
        "summary": "Executive readiness layer for launch confidence, operational risk visibility, inspection readiness, governance trust, and commercialization defensibility.",
        "score": 98,
        "status": "Executive Ready",
        "category": "Executive",
        "gates": [
            "Launch confidence",
            "Operational risk visibility",
            "Inspection readiness",
            "Governance trust",
            "Evidence defensibility",
            "Commercialization decision support"
        ]
    }
}

tree = ast.parse(text)

target_node = None

for node in tree.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == TARGET:
                target_node = node
                break
    if target_node is not None:
        break

if target_node is None:
    raise SystemExit("Could not find IRLT_DYNAMIC_MODULES_V2 assignment.")

existing = ast.literal_eval(ast.unparse(target_node.value))

added = []
skipped = []

for key, value in new_entries.items():
    if key in existing:
        skipped.append(key)
    else:
        existing[key] = value
        added.append(key)

start = target_node.lineno - 1
end = target_node.end_lineno

new_assignment = TARGET + " = " + pprint.pformat(
    existing,
    width=120,
    sort_dicts=False
)

lines = text.splitlines()
lines[start:end] = new_assignment.splitlines()

APP.write_text("\n".join(lines) + "\n", encoding="utf-8")

print("Registry updated safely.")
print("Added:", added)
print("Skipped:", skipped)
