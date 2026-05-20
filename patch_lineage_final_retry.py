from pathlib import Path

p = Path("app.py")
text = p.read_text(encoding="utf-8")

if '"id": "governance_lineage_center"' not in text:
    marker = "WORKSPACES = ["
    i = text.find(marker)
    if i == -1:
        raise SystemExit("ERROR: WORKSPACES not found")
    j = text.find("\n", i) + 1
    workspace = '''    {
        "id": "governance_lineage_center",
        "slug": "governance-lineage-center",
        "name": "Governance Lineage Center",
        "short_name": "Lineage",
        "status": "DEMO",
        "route": "/workspace/governance-lineage-center",
        "description": "End-to-end operational lineage from ticket to shift, technician, equipment, evidence, review, and audit export.",
        "module_note": "Synthetic lineage demo showing accountability continuity and audit-ready evidence traceability."
    },
'''
    text = text[:j] + workspace + text[j:]

if 'render_governance_lineage_center_workspace(workspace)' not in text:
    target = '''    return render_planned_workspace(workspace)
'''
    branch = '''    if workspace["id"] == "governance_lineage_center":
        return render_governance_lineage_center_workspace(workspace)

'''
    if target not in text:
        raise SystemExit("ERROR: default planned workspace return not found")
    text = text.replace(target, branch + target)

if "def render_governance_lineage_center_workspace(current_workspace):" not in text:
    marker = "def render_planned_workspace"
    k = text.find(marker)
    if k == -1:
        raise SystemExit("ERROR: planned workspace function not found")

    fn = r'''
def render_governance_lineage_center_workspace(current_workspace):
    kpis = {
        "traceability": "95%",
        "chain_integrity": "96%",
        "open_breaks": "1",
        "audit_readiness": "90%"
    }

    lineage = [
        {"stage":"1", "node":"ServiceNow Ticket", "record":"DEMO-INC-10052", "owner":"Operations", "state":"Created", "risk":"LOW"},
        {"stage":"2", "node":"Shift Assignment", "record":"Night Coverage C/D", "owner":"Shift Supervisor", "state":"Assigned", "risk":"LOW"},
        {"stage":"3", "node":"Technician Ownership", "record":"TECH-C / TECH-D Backup", "owner":"Primary + Backup", "state":"Acknowledgement Pending", "risk":"MEDIUM"},
        {"stage":"4", "node":"Equipment Context", "record":"Environmental Monitoring Device", "owner":"Equipment Support", "state":"Escalated", "risk":"HIGH"},
        {"stage":"5", "node":"Evidence Package", "record":"Audit Trail Export", "owner":"Technician / Supervisor", "state":"Partially Attached", "risk":"HIGH"},
        {"stage":"6", "node":"Supervisor Review", "record":"Review Checkpoint", "owner":"Supervisor", "state":"Required", "risk":"MEDIUM"},
        {"stage":"7", "node":"Audit Export", "record":"Lineage Package", "owner":"Audit / QA", "state":"Ready After Evidence Closure", "risk":"LOW"}
    ]

    checks = [
        {"check":"Ticket linked to equipment", "result":"PASS", "meaning":"The operational event is tied to governed equipment context."},
        {"check":"Shift owner assigned", "result":"PASS", "meaning":"Primary and backup coverage are visible."},
        {"check":"Incoming handoff acknowledged", "result":"WARNING", "meaning":"Incoming technician acknowledgement is pending."},
        {"check":"Evidence attached", "result":"FAIL", "meaning":"Required audit trail export is missing."},
        {"check":"Supervisor review required", "result":"WARNING", "meaning":"Closure should wait for governance review."},
        {"check":"Audit package exportable", "result":"PASS", "meaning":"Lineage package structure is ready."}
    ]

    template = """
<!DOCTYPE html>
<html>
<head>
<title>Governance Lineage Center</title>
<style>
body{margin:0;font-family:Arial;background:#f4f7fb;color:#0f172a}
.top{background:linear-gradient(135deg,#111827,#6d28d9);color:white;padding:28px 36px}
.top h1{margin:0;font-size:32px}.top p{color:#ede9fe}
.layout{display:flex;min-height:100vh}.side{width:290px;background:#111827;color:white;padding:24px}
.side a{display:block;color:#d1d5db;text-decoration:none;padding:12px;border-radius:10px;margin-bottom:8px}
.side a.active,.side a:hover{background:#6d28d9;color:white}
.main{flex:1;padding:30px}.panel,.kpi{background:white;border-radius:18px;padding:22px;box-shadow:0 8px 25px rgba(15,23,42,.08);margin-bottom:22px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}.kpi span{color:#64748b;font-weight:bold}.kpi strong{display:block;font-size:30px;margin-top:8px}
.chain{display:grid;grid-template-columns:repeat(7,1fr);gap:10px}
.node{background:#f8fafc;border:1px solid #ddd6fe;border-radius:16px;padding:14px;text-align:center;min-height:130px}
.node b{color:#5b21b6} table{width:100%;border-collapse:collapse} th{background:#f5f3ff;color:#5b21b6;text-align:left;padding:12px}
td{border-bottom:1px solid #e5e7eb;padding:12px;font-size:13px}.badge{padding:6px 10px;border-radius:999px;font-weight:bold;font-size:11px}
.LOW{background:#dcfce7;color:#166534}.MEDIUM,.WARNING{background:#fef3c7;color:#92400e}.HIGH,.FAIL{background:#fee2e2;color:#991b1b}.PASS{background:#dcfce7;color:#166534}
select{width:100%;padding:10px;border-radius:10px;margin-bottom:18px}
</style>
</head>
<body>
<div class="top">
<h1>COBIT-Chain™ Governance Lineage Center</h1>
<p>Ticket → Shift → Technician → Equipment → Evidence → Supervisor Review → Audit Export</p>
</div>

<div class="layout">
<div class="side">
<h3>Governance Workspaces</h3>
<select onchange="window.location.href=this.value">
{% for w in workspaces %}
<option value="{{ w.route }}" {% if w.id == current_workspace.id %}selected{% endif %}>{{ w.name }} — {{ w.status }}</option>
{% endfor %}
</select>
{% for w in workspaces %}
<a class="{% if w.id == current_workspace.id %}active{% endif %}" href="{{ w.route }}"><b>{{ w.short_name }}</b><br>{{ w.status }}</a>
{% endfor %}
</div>

<div class="main">
<div class="panel">
<h2>Operational Governance Lineage</h2>
<p>This workspace proves how a service event stays connected across shift ownership, technician accountability, equipment context, evidence package, supervisor review, and audit export.</p>
</div>

<div class="grid">
<div class="kpi"><span>Traceability</span><strong>{{ kpis.traceability }}</strong></div>
<div class="kpi"><span>Chain Integrity</span><strong>{{ kpis.chain_integrity }}</strong></div>
<div class="kpi"><span>Open Breaks</span><strong>{{ kpis.open_breaks }}</strong></div>
<div class="kpi"><span>Audit Readiness</span><strong>{{ kpis.audit_readiness }}</strong></div>
</div>

<div class="panel">
<h3>1. Visual Governance Chain</h3>
<div class="chain">
{% for l in lineage %}
<div class="node">
<b>{{ l.stage }}. {{ l.node }}</b><br>
{{ l.record }}<br><br>
{{ l.owner }}<br>
<span class="badge {{ l.risk }}">{{ l.risk }}</span>
</div>
{% endfor %}
</div>
</div>

<div class="panel">
<h3>2. Lineage Detail</h3>
<table>
<tr><th>Stage</th><th>Node</th><th>Record</th><th>Owner</th><th>State</th><th>Risk</th></tr>
{% for l in lineage %}
<tr><td>{{ l.stage }}</td><td><b>{{ l.node }}</b></td><td>{{ l.record }}</td><td>{{ l.owner }}</td><td>{{ l.state }}</td><td><span class="badge {{ l.risk }}">{{ l.risk }}</span></td></tr>
{% endfor %}
</table>
</div>

<div class="panel">
<h3>3. Governance Checkpoints</h3>
<table>
<tr><th>Checkpoint</th><th>Result</th><th>Meaning</th></tr>
{% for c in checks %}
<tr><td><b>{{ c.check }}</b></td><td><span class="badge {{ c.result }}">{{ c.result }}</span></td><td>{{ c.meaning }}</td></tr>
{% endfor %}
</table>
</div>

<div class="panel">
<h3>Executive Meaning</h3>
<p>ServiceNow shows that a ticket exists. This lineage center shows whether the ticket remained governed across ownership, equipment, evidence, review, and audit-readiness expectations.</p>
<p><a href="/">Return to Executive Platform Overview</a></p>
</div>
</div>
</div>
</body>
</html>
"""
    return render_template_string(template, current_workspace=current_workspace, workspaces=WORKSPACES, kpis=kpis, lineage=lineage, checks=checks)


'''
    text = text[:k] + fn + text[k:]

required = [
    '"id": "governance_lineage_center"',
    'render_governance_lineage_center_workspace(workspace)',
    'def render_governance_lineage_center_workspace(current_workspace):'
]

missing = [x for x in required if x not in text]
if missing:
    raise SystemExit("ERROR missing: " + ", ".join(missing))

p.write_text(text, encoding="utf-8")
print("SUCCESS: Governance Lineage Center added.")
