from pathlib import Path
import ast
import pprint

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

TARGET = "IRLT_DYNAMIC_MODULES_V2"

new_entries = {
    "release-orchestration-gate": {
        "title": "Release Orchestration Gate",
        "summary": "Governed release orchestration layer coordinating QA, QC, manufacturing, logistics, treatment timing, and commercialization readiness.",
        "score": 97,
        "status": "Orchestrated",
        "category": "Release Governance",
        "gates": ["QA coordination", "QC coordination", "Manufacturing coordination", "Shipment coordination", "Treatment timing alignment", "Commercial readiness approval"]
    },
    "cold-chain-excursion-gate": {
        "title": "Cold Chain Excursion Gate",
        "summary": "Governed cold-chain excursion layer for temperature deviation detection, escalation, impact analysis, and treatment protection.",
        "score": 95,
        "status": "Monitored",
        "category": "Cold Chain",
        "gates": ["Excursion detection", "Impact assessment", "Shipment escalation", "Dose viability review", "QA notification", "Treatment continuity protection"]
    },
    "radiation-safety-governance-gate": {
        "title": "Radiation Safety Governance Gate",
        "summary": "Governed radiation safety layer for handling controls, exposure governance, accountability, escalation readiness, and inspection defensibility.",
        "score": 96,
        "status": "Controlled",
        "category": "Radiation Governance",
        "gates": ["Handling procedure adherence", "Exposure monitoring", "Personnel accountability", "Incident escalation", "Safety evidence retention", "Inspection defensibility"]
    },
    "shipment-delay-impact-gate": {
        "title": "Shipment Delay Impact Gate",
        "summary": "Governed shipment-delay impact layer for logistics disruption analysis, decay-window awareness, treatment impact, and escalation coordination.",
        "score": 94,
        "status": "Escalation Active",
        "category": "Logistics",
        "gates": ["Delay detection", "Decay-window analysis", "Treatment impact review", "Courier escalation", "Site communication", "Continuity decision support"]
    },
    "gmp-escalation-governance-gate": {
        "title": "GMP Escalation Governance Gate",
        "summary": "Governed GMP escalation layer for critical event routing, operational risk visibility, accountability, and executive escalation management.",
        "score": 95,
        "status": "Active Governance",
        "category": "GMP Governance",
        "gates": ["Critical event detection", "Escalation routing", "Operational risk visibility", "Executive notification", "Accountability tracking", "Closure defensibility"]
    },
    "evidence-lineage-gate": {
        "title": "Evidence Lineage Gate",
        "summary": "Governed evidence-lineage layer for operational proof, cross-system linkage, approval traceability, and audit survivability.",
        "score": 98,
        "status": "Verified",
        "category": "Evidence Governance",
        "gates": ["Evidence traceability", "Cross-system linkage", "Approval lineage", "Record integrity", "Audit survivability", "Inspection defensibility"]
    },
    "executive-risk-visibility-gate": {
        "title": "Executive Risk Visibility Gate",
        "summary": "Executive governance layer for operational risk heatmaps, dependency visibility, escalation intelligence, and commercialization confidence.",
        "score": 96,
        "status": "Executive Active",
        "category": "Executive",
        "gates": ["Operational risk visibility", "Dependency heatmaps", "Escalation intelligence", "Inspection risk awareness", "Commercialization confidence", "Decision support readiness"]
    },
    "dependency-propagation-gate": {
        "title": "Dependency Propagation Gate",
        "summary": "Governed dependency propagation layer for identifying cascading operational impact across QA, QC, manufacturing, logistics, and treatment.",
        "score": 95,
        "status": "Mapped",
        "category": "Operational Intelligence",
        "gates": ["Dependency mapping", "Cascading impact detection", "Operational linkage", "Escalation awareness", "Readiness synchronization", "Recovery prioritization"]
    },
    "gmp-restart-readiness-gate": {
        "title": "GMP Restart Readiness Gate",
        "summary": "Governed GMP restart layer for operational recovery, evidence reconciliation, release confidence, and controlled restart execution.",
        "score": 94,
        "status": "Recovery Ready",
        "category": "Recovery Governance",
        "gates": ["Operational recovery validation", "Evidence reconciliation", "System restart coordination", "Release confidence verification", "Escalation management", "Controlled restart approval"]
    },
    "commercial-scale-up-governance-gate": {
        "title": "Commercial Scale-Up Governance Gate",
        "summary": "Governed scale-up readiness layer for operational growth, manufacturing expansion, staffing readiness, logistics scaling, and inspection resilience.",
        "score": 97,
        "status": "Scale-Up Ready",
        "category": "Commercialization",
        "gates": ["Manufacturing expansion readiness", "Operational staffing readiness", "Logistics scaling", "QA scaling readiness", "Inspection resilience", "Executive scale-up approval"]
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
    if target_node:
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

new_assignment = TARGET + " = " + pprint.pformat(existing, width=120, sort_dicts=False)

lines = text.splitlines()
lines[start:end] = new_assignment.splitlines()

APP.write_text("\n".join(lines) + "\n", encoding="utf-8")

print("Registry updated safely.")
print("Added:", added)
print("Skipped:", skipped)
