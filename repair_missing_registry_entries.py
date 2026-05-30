from pathlib import Path
import ast
import pprint
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")
TARGET = "IRLT_DYNAMIC_MODULES_V2"

# Ensure imports
m = re.search(r"from flask import ([^\n]+)", text)
if not m:
    raise SystemExit("Flask import not found.")

imports = [x.strip() for x in m.group(1).split(",")]
for item in ["render_template_string", "jsonify"]:
    if item not in imports:
        imports.append(item)
text = text[:m.start()] + "from flask import " + ", ".join(imports) + text[m.end():]

new_entries = {
    "chain-of-custody-gate": {
        "title": "Chain of Custody Gate",
        "summary": "Governed custody assurance layer for radioactive material, dose movement, courier handoff, receiving, and treatment continuity.",
        "score": 98,
        "status": "Verified",
        "category": "Traceability",
        "gates": ["Custody owner validation", "Handoff timestamp control", "Courier accountability", "Receiving confirmation", "Exception escalation", "Inspection defensibility"]
    },
    "powerbi-readiness-gate": {
        "title": "Power BI Readiness Gate",
        "summary": "Analytics readiness layer for executive dashboards, readiness heatmaps, operational trust scoring, and governance reporting.",
        "score": 92,
        "status": "Planned Integration",
        "category": "Analytics",
        "gates": ["Dataset readiness", "API readiness", "Scorecard mapping", "Heatmap logic", "Executive dashboard", "Refresh governance"]
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
    raise SystemExit("IRLT_DYNAMIC_MODULES_V2 not found.")

existing = ast.literal_eval(ast.unparse(target_node.value))

for key, value in new_entries.items():
    existing[key] = value

start = target_node.lineno - 1
end = target_node.end_lineno
new_assignment = TARGET + " = " + pprint.pformat(existing, width=120, sort_dicts=False)

lines = text.splitlines()
lines[start:end] = new_assignment.splitlines()
text = "\n".join(lines) + "\n"

APP.write_text(text, encoding="utf-8")
print("Missing registry entries repaired.")
