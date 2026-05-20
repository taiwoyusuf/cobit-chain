from pathlib import Path

p = Path("app.py")
text = p.read_text(encoding="utf-8")

if '"id": "lilly_operational_demo"' not in text:
    marker = "WORKSPACES = ["
    i = text.find(marker)
    if i == -1:
        raise SystemExit("ERROR: WORKSPACES not found")
    j = text.find("\n", i) + 1

    workspace = '''    {
        "id": "lilly_operational_demo",
        "slug": "lilly-operational-governance",
        "name": "Lilly Operational Governance Demo",
        "short_name": "Lilly Demo",
        "status": "DEMO",
        "route": "/workspace/lilly-operational-governance",
        "description": "Sanitized executive demo workspace for operational governance, shift continuity, equipment assurance, ServiceNow-aware ticket flow, and audit-ready evidence posture.",
        "module_note": "Clean Lilly-facing demo workspace using synthetic records only. No confidential Lilly data, no real technician names, and no real production records."
    },
'''
    text = text[:j] + workspace + text[j:]

if 'render_lilly_operational_demo_workspace(workspace)' not in text:
    target = '''    if workspace["id"] == "governance_lineage_center":
        return render_governance_lineage_center_workspace(workspace)

'''
    branch = '''    if workspace["id"] == "lilly_operational_demo":
        return render_lilly_operational_demo_workspace(workspace)

'''
    if target not in text:
        raise SystemExit("ERROR: lineage router branch not found")
    text = text.replace(target, target + branch)

if "def render_lilly_operational_demo_workspace(current_workspace):" not in text:
    marker = "def render_governance_lineage_center_workspace"
    k = text.find(marker)
    if k == -1:
        raise SystemExit("ERROR: lineage function not found")

    fn = r'''
def render_lilly_operational_demo_workspace(current_workspace):
    kpis = {
        "operational_readiness": "92%",
        "coverage_assurance": "94%",
        "evidence_integrity": "96%",
        "audit_posture": "88%"
    }

    command_center = [
        {"domain": "Shift Continuity", "status": "Controlled", "score": "94%", "risk": "LOW", "evidence": "Overlap coverage and handoff continuity visible"},
        {"domain": "Equipment Assurance", "status": "Monitored", "score": "89%", "risk": "MEDIUM", "evidence": "Equipment ownership and backup coverage mapped"},
        {"domain": "ServiceNow Ticket Flow", "status": "Simulated", "score": "91%", "risk": "LOW", "evidence": "Synthetic ticket flow mapped to governance checks"},
        {"domain": "Audit Readiness", "status": "Review Needed", "score": "88%", "risk": "MEDIUM", "evidence": "Missing evidence and review checkpoints visible"}
    ]

    tickets = [
        {"ticket": "DEMO-INC-10041", "type": "Incident", "equipment": "Critical Utility Monitor", "priority": "P2", "window": "A/B Overlap", "state": "Validated", "risk": "LOW"},
        {"ticket": "DEMO-WO-20488", "type": "Work Order", "equipment": "Sterile Process Support Unit", "priority": "P3", "window": "B to C Transition", "state": "Evidence Pending", "risk": "MEDIUM"},
        {"ticket": "DEMO-INC-10052", "type": "Incident", "equipment": "Environmental Monitoring Device", "priority": "P2", "window": "Night Coverage", "state": "Escalation Required", "risk": "HIGH"},
        {"ticket": "DEMO-WO-20517", "type": "Work Order", "equipment": "GMP Equipment Cluster", "priority": "P4", "window": "C/D Overlap", "state": "Controlled", "risk": "LOW"}
    ]

    talking_points = [
        "This is not a replacement for ServiceNow; it is a governance assurance layer above operational systems.",
        "ServiceNow can show that a ticket exists. COBIT-Chain shows whether the work stayed governed across shift, equipment, evidence, and audit expectations.",
        "The demo uses synthetic records only, so it can be shown safely without exposing real operational data.",
        "The same platform can support shift assurance, manufacturing evidence, SOP governance, access governance, audit/CAPA, and Power BI reporting."
    ]

    template = """
<!DOCTYPE html>
<html>
<head>
<title>Lilly Operational Governance Demo</title>
<style>
body{margin:0;font-family:Arial;background:#f4f7fb;color:#0f172a}
.top{background:linear-gradient(135deg,#0f172a,#1d4ed8);color:white;padding:28px 36px}
.top h1{margin:0;font-size:32px}.top p{color:#dbeafe}
.layout{display:flex;min-height:100vh}.side{width:290px;background:#111827;color:white;padding:24px}
.side a{display:block;color:#d1d5db;text-decoration:none;padding:12px;border-radius:10px;margin-bottom:8px}
.side a.active,.side a:hover{background:#2563eb;color:white}
.main{flex:1;padding:30px}.panel,.kpi{background:white;border-radius:18px;padding:22px;box-shadow:0 8px 25px rgba(15,23,42,.08);margin-bottom:22px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}.kpi span{color:#64748b;font-weight:bold}.kpi strong{display:block;font-size:30px;margin-top:8px}
table{width:100%;border-collapse:collapse}th{background:#eff6ff;color:#1e3a8a;text-align:left;padding:12px}td{border-bottom:1px solid #e5e7eb;padding:12px;font-size:13px}
.badge{padding:6px 10px;border-radius:999px;font-weight:bold;font-size:11px}.LOW{background:#dcfce7;color:#166534}.MEDIUM{background:#fef3c7;color:#92400e}.HIGH{background:#fee2e2;color:#991b1b}
.safe{background:#ecfeff;border:1px solid #a5f3fc;color:#155e75;padding:16px;border-radius:14px;margin-bottom:20px}
select{width:100%;padding:10px;border-radius:10px;margin-bottom:18px}
</style>
</head>
<body>
<div class="top">
<h1>COBIT-Chain™ Lilly Operational Governance Demo</h1>
<p>Sanitized executive workspace • Operational governance • Shift continuity • Audit readiness</p>
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
<h2>Lilly Operational Governance Demo Workspace</h2>
<p>This clean executive demo shows how COBIT-Chain can sit above operational systems as a governance assurance layer without exposing real company records.</p>
</div>

<div class="safe"><b>Data safety statement:</b> synthetic demo records only. No real ticket numbers, technician names, production incidents, SOP content, deviations, or equipment records.</div>

<div class="grid">
<div class="kpi"><span>Operational Readiness</span><strong>{{ kpis.operational_readiness }}</strong></div>
<div class="kpi"><span>Coverage Assurance</span><strong>{{ kpis.coverage_assurance }}</strong></div>
<div class="kpi"><span>Evidence Integrity</span><strong>{{ kpis.evidence_integrity }}</strong></div>
<div class="kpi"><span>Audit Posture</span><strong>{{ kpis.audit_posture }}</strong></div>
</div>

<div class="panel">
<h3>1. Executive Command Center</h3>
<table>
<tr><th>Domain</th><th>Status</th><th>Score</th><th>Risk</th><th>Evidence Signal</th></tr>
{% for c in command_center %}
<tr><td><b>{{ c.domain }}</b></td><td>{{ c.status }}</td><td><b>{{ c.score }}</b></td><td><span class="badge {{ c.risk }}">{{ c.risk }}</span></td><td>{{ c.evidence }}</td></tr>
{% endfor %}
</table>
</div>

<div class="panel">
<h3>2. Sanitized ServiceNow-Aware Ticket Flow</h3>
<table>
<tr><th>Demo Ticket</th><th>Type</th><th>Equipment Area</th><th>Priority</th><th>Coverage Window</th><th>Governance State</th><th>Risk</th></tr>
{% for t in tickets %}
<tr><td><b>{{ t.ticket }}</b></td><td>{{ t.type }}</td><td>{{ t.equipment }}</td><td>{{ t.priority }}</td><td>{{ t.window }}</td><td>{{ t.state }}</td><td><span class="badge {{ t.risk }}">{{ t.risk }}</span></td></tr>
{% endfor %}
</table>
</div>

<div class="panel">
<h3>3. Executive Talking Points</h3>
<ul>
{% for point in talking_points %}
<li>{{ point }}</li>
{% endfor %}
</ul>
<p><a href="/">Return to Executive Platform Overview</a></p>
</div>
</div>
</div>
</body>
</html>
"""
    return render_template_string(template, current_workspace=current_workspace, workspaces=WORKSPACES, kpis=kpis, command_center=command_center, tickets=tickets, talking_points=talking_points)


'''
    text = text[:k] + fn + text[k:]

required = [
    '"id": "lilly_operational_demo"',
    'render_lilly_operational_demo_workspace(workspace)',
    'def render_lilly_operational_demo_workspace(current_workspace):'
]
missing = [x for x in required if x not in text]
if missing:
    raise SystemExit("ERROR missing: " + ", ".join(missing))

p.write_text(text, encoding="utf-8")
print("SUCCESS: Lilly Operational Governance Demo added.")
