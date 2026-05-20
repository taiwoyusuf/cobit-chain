from pathlib import Path

p = Path("app.py")
text = p.read_text(encoding="utf-8")

if '"id": "powerbi_command_center"' not in text:
    marker = "WORKSPACES = ["
    i = text.find(marker)
    if i == -1:
        raise SystemExit("ERROR: WORKSPACES not found")
    j = text.find("\n", i) + 1

    workspace = '''    {
        "id": "powerbi_command_center",
        "slug": "powerbi-command-center",
        "name": "Power BI Command Center",
        "short_name": "Power BI",
        "status": "DEMO",
        "route": "/workspace/powerbi-command-center",
        "description": "Executive analytics workspace for governance KPIs, risk heatmaps, ticket aging, equipment continuity, and audit-readiness reporting.",
        "module_note": "Power BI-ready command center using synthetic datasets for executive governance reporting."
    },
'''
    text = text[:j] + workspace + text[j:]

if 'render_powerbi_command_center_workspace(workspace)' not in text:
    target = '''    if workspace["id"] == "lilly_operational_demo":
        return render_lilly_operational_demo_workspace(workspace)

'''
    branch = '''    if workspace["id"] == "powerbi_command_center":
        return render_powerbi_command_center_workspace(workspace)

'''
    if target not in text:
        raise SystemExit("ERROR: Lilly router branch not found")
    text = text.replace(target, target + branch)

if "def render_powerbi_command_center_workspace(current_workspace):" not in text:
    marker = "def render_lilly_operational_demo_workspace"
    k = text.find(marker)
    if k == -1:
        raise SystemExit("ERROR: Lilly function not found")

    fn = r'''
def render_powerbi_command_center_workspace(current_workspace):
    kpis = {
        "governance_confidence": "91%",
        "audit_readiness": "88%",
        "evidence_integrity": "96%",
        "coverage_integrity": "94%"
    }

    heatmap = [
        {"domain": "Shift Continuity", "score": "94%", "risk": "LOW", "driver": "Overlap coverage active across support windows"},
        {"domain": "Equipment Assurance", "score": "89%", "risk": "MEDIUM", "driver": "One equipment area requires evidence completion"},
        {"domain": "Ticket Governance", "score": "86%", "risk": "MEDIUM", "driver": "One aged escalation requires supervisor review"},
        {"domain": "Evidence Integrity", "score": "96%", "risk": "LOW", "driver": "Most evidence records are hash-ready"},
        {"domain": "Audit Posture", "score": "88%", "risk": "MEDIUM", "driver": "Audit export readiness depends on missing attachment closure"},
        {"domain": "Manufacturing Assurance", "score": "92%", "risk": "LOW", "driver": "Process-chain records are governed and traceable"}
    ]

    datasets = [
        {"dataset": "governance_scorecard.csv", "source": "COBIT-Chain KPIs", "use": "Executive scorecards and trend cards", "status": "Ready"},
        {"dataset": "shift_continuity.csv", "source": "Shift Assurance", "use": "Coverage heatmap and handoff trend", "status": "Ready"},
        {"dataset": "ticket_aging.csv", "source": "ServiceNow-style export", "use": "SLA aging and escalation reporting", "status": "Ready"},
        {"dataset": "equipment_continuity.csv", "source": "Equipment Matrix", "use": "Equipment ownership and risk dashboard", "status": "Ready"},
        {"dataset": "audit_readiness.csv", "source": "Evidence Layer", "use": "Missing evidence and audit posture", "status": "Ready"}
    ]

    pages = [
        {"page": "Executive Overview", "visuals": "Readiness score, open risk, governance confidence, evidence integrity"},
        {"page": "Operational Heatmap", "visuals": "Domain-level risk matrix across shift, equipment, ticket, evidence, and manufacturing"},
        {"page": "Ticket Aging", "visuals": "SLA buckets, risk trend, escalation carryover"},
        {"page": "Equipment Assurance", "visuals": "Equipment owner continuity and backup coverage"},
        {"page": "Audit Readiness", "visuals": "Missing evidence, review status, governance exceptions"}
    ]

    template = """
<!DOCTYPE html>
<html>
<head>
<title>Power BI Command Center</title>
<style>
body{margin:0;font-family:Arial;background:#f4f7fb;color:#0f172a}
.top{background:linear-gradient(135deg,#0f172a,#2563eb);color:white;padding:28px 36px}
.top h1{margin:0;font-size:32px}.top p{color:#dbeafe}
.layout{display:flex;min-height:100vh}.side{width:290px;background:#111827;color:white;padding:24px}
.side a{display:block;color:#d1d5db;text-decoration:none;padding:12px;border-radius:10px;margin-bottom:8px}
.side a.active,.side a:hover{background:#2563eb;color:white}
.main{flex:1;padding:30px}.panel,.kpi{background:white;border-radius:18px;padding:22px;box-shadow:0 8px 25px rgba(15,23,42,.08);margin-bottom:22px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}.kpi span{color:#64748b;font-weight:bold}.kpi strong{display:block;font-size:30px;margin-top:8px}
table{width:100%;border-collapse:collapse}th{background:#eff6ff;color:#1e3a8a;text-align:left;padding:12px}td{border-bottom:1px solid #e5e7eb;padding:12px;font-size:13px}
.badge{padding:6px 10px;border-radius:999px;font-weight:bold;font-size:11px}.LOW{background:#dcfce7;color:#166534}.MEDIUM{background:#fef3c7;color:#92400e}.HIGH{background:#fee2e2;color:#991b1b}
.ready{background:#dcfce7;color:#166534}.note{background:#ecfeff;border:1px solid #a5f3fc;color:#155e75;padding:16px;border-radius:14px;margin-bottom:20px}
select{width:100%;padding:10px;border-radius:10px;margin-bottom:18px}
</style>
</head>
<body>
<div class="top">
<h1>COBIT-Chain™ Power BI Command Center</h1>
<p>Executive analytics • Governance heatmap • Ticket aging • Equipment continuity • Audit readiness</p>
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
<h2>Executive Governance Analytics Layer</h2>
<p>This workspace prepares COBIT-Chain data for Power BI-style executive reporting. It uses synthetic demo data now, but the structure is designed for future CSV export, API feeds, Power BI dashboards, and leadership scorecards.</p>
</div>

<div class="note"><b>Positioning:</b> Power BI visualizes performance. COBIT-Chain prepares the governed evidence and continuity data underneath the visuals.</div>

<div class="grid">
<div class="kpi"><span>Governance Confidence</span><strong>{{ kpis.governance_confidence }}</strong></div>
<div class="kpi"><span>Audit Readiness</span><strong>{{ kpis.audit_readiness }}</strong></div>
<div class="kpi"><span>Evidence Integrity</span><strong>{{ kpis.evidence_integrity }}</strong></div>
<div class="kpi"><span>Coverage Integrity</span><strong>{{ kpis.coverage_integrity }}</strong></div>
</div>

<div class="panel">
<h3>1. Governance Heatmap</h3>
<table>
<tr><th>Domain</th><th>Score</th><th>Risk</th><th>Risk Driver</th></tr>
{% for h in heatmap %}
<tr><td><b>{{ h.domain }}</b></td><td><b>{{ h.score }}</b></td><td><span class="badge {{ h.risk }}">{{ h.risk }}</span></td><td>{{ h.driver }}</td></tr>
{% endfor %}
</table>
</div>

<div class="panel">
<h3>2. Power BI Dataset Catalog</h3>
<table>
<tr><th>Dataset</th><th>Source</th><th>Power BI Use</th><th>Status</th></tr>
{% for d in datasets %}
<tr><td><b>{{ d.dataset }}</b></td><td>{{ d.source }}</td><td>{{ d.use }}</td><td><span class="badge ready">{{ d.status }}</span></td></tr>
{% endfor %}
</table>
</div>

<div class="panel">
<h3>3. Recommended Power BI Report Pages</h3>
<table>
<tr><th>Report Page</th><th>Suggested Visuals</th></tr>
{% for p in pages %}
<tr><td><b>{{ p.page }}</b></td><td>{{ p.visuals }}</td></tr>
{% endfor %}
</table>
</div>

<div class="panel">
<h3>Executive Meaning</h3>
<p>Power BI can show the dashboard. COBIT-Chain explains the governed evidence behind the dashboard: who owned the work, whether evidence exists, whether handoff happened, whether risk was carried forward, and whether audit posture is defensible.</p>
<p><a href="/">Return to Executive Platform Overview</a></p>
</div>
</div>
</div>
</body>
</html>
"""
    return render_template_string(template, current_workspace=current_workspace, workspaces=WORKSPACES, kpis=kpis, heatmap=heatmap, datasets=datasets, pages=pages)


'''
    text = text[:k] + fn + text[k:]

required = [
    '"id": "powerbi_command_center"',
    'render_powerbi_command_center_workspace(workspace)',
    'def render_powerbi_command_center_workspace(current_workspace):'
]
missing = [x for x in required if x not in text]
if missing:
    raise SystemExit("ERROR missing: " + ", ".join(missing))

p.write_text(text, encoding="utf-8")
print("SUCCESS: Power BI Command Center added.")
