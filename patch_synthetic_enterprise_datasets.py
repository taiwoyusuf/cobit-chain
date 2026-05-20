from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SYNTHETIC_ENTERPRISE_DATASET_LAYER_ACTIVE"

if MARKER in text:
    print("Synthetic Enterprise Dataset Layer already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# SYNTHETIC_ENTERPRISE_DATASET_LAYER_ACTIVE
# Safe additive route only.
# Adds /synthetic-enterprise-datasets without modifying protected modules.
# Provides controlled demo datasets for tickets, shifts, equipment,
# evidence, audit, confidence, and digital twin records.
# ============================================================

@app.route("/synthetic-enterprise-datasets")
def synthetic_enterprise_datasets():
    dataset_kpis = {
        "demo_records": "42",
        "synthetic_tickets": "8",
        "equipment_assets": "6",
        "evidence_items": "12",
        "audit_questions": "5",
        "confidence_rows": "7",
        "powerbi_ready": "YES",
        "data_sensitivity": "Synthetic"
    }

    ticket_dataset = [
        {"ticket": "SYN-INC-10052", "type": "Incident", "state": "In Progress", "shift": "B→C", "equipment": "Environmental Monitoring Device", "confidence": "74%", "risk": "HIGH"},
        {"ticket": "SYN-WO-20488", "type": "Work Order", "state": "Assigned", "shift": "A→B", "equipment": "Sterile Process Support Unit", "confidence": "82%", "risk": "MEDIUM"},
        {"ticket": "SYN-INC-10041", "type": "Incident", "state": "Resolved", "shift": "C→D", "equipment": "Critical Utility Monitor", "confidence": "96%", "risk": "LOW"},
        {"ticket": "SYN-WO-20517", "type": "Work Order", "state": "Closed", "shift": "D→A", "equipment": "GMP Equipment Cluster", "confidence": "91%", "risk": "LOW"},
    ]

    equipment_dataset = [
        {"asset": "Environmental Monitoring Device", "owner": "TECH-C", "backup": "TECH-D", "state": "Warning", "evidence": "Partial", "audit": "Conditional", "risk": "HIGH"},
        {"asset": "Sterile Process Support Unit", "owner": "TECH-B", "backup": "TECH-A", "state": "Active", "evidence": "Pending", "audit": "Review Needed", "risk": "MEDIUM"},
        {"asset": "Critical Utility Monitor", "owner": "TECH-D", "backup": "TECH-C", "state": "Normal", "evidence": "Complete", "audit": "Ready", "risk": "LOW"},
        {"asset": "GMP Equipment Cluster", "owner": "TECH-A", "backup": "TECH-B", "state": "Normal", "evidence": "Complete", "audit": "Ready", "risk": "LOW"},
    ]

    evidence_dataset = [
        {"evidence": "Audit trail export", "linked_record": "SYN-INC-10052", "status": "Missing", "hash_ready": "NO", "audit_value": "Critical", "risk": "HIGH"},
        {"evidence": "Handoff acknowledgement", "linked_record": "SYN-INC-10052", "status": "Pending", "hash_ready": "NO", "audit_value": "High", "risk": "HIGH"},
        {"evidence": "Supervisor review note", "linked_record": "SYN-WO-20488", "status": "Pending", "hash_ready": "NO", "audit_value": "Medium", "risk": "MEDIUM"},
        {"evidence": "Equipment state screenshot", "linked_record": "SYN-INC-10041", "status": "Complete", "hash_ready": "YES", "audit_value": "High", "risk": "LOW"},
        {"evidence": "Closure rationale", "linked_record": "SYN-WO-20517", "status": "Complete", "hash_ready": "YES", "audit_value": "High", "risk": "LOW"},
    ]

    confidence_dataset = [
        {"factor": "Overlap Integrity", "score": "94", "weight": "15", "trend": "Stable", "risk": "LOW"},
        {"factor": "Handoff Integrity", "score": "87", "weight": "15", "trend": "Watch", "risk": "MEDIUM"},
        {"factor": "Evidence Completeness", "score": "82", "weight": "20", "trend": "Declining", "risk": "MEDIUM"},
        {"factor": "Escalation Ownership", "score": "85", "weight": "15", "trend": "Watch", "risk": "MEDIUM"},
        {"factor": "Audit Readiness", "score": "84", "weight": "15", "trend": "Watch", "risk": "MEDIUM"},
        {"factor": "Lineage Continuity", "score": "96", "weight": "10", "trend": "Strong", "risk": "LOW"},
        {"factor": "Platform Health", "score": "92", "weight": "10", "trend": "Stable", "risk": "LOW"},
    ]

    export_catalog = [
        {"dataset": "synthetic_tickets.csv", "purpose": "ServiceNow overlay, shift overlap, digital twin", "powerbi_table": "FactTickets", "status": "Ready"},
        {"dataset": "synthetic_equipment.csv", "purpose": "Equipment continuity and ownership risk", "powerbi_table": "DimEquipment", "status": "Ready"},
        {"dataset": "synthetic_evidence.csv", "purpose": "Evidence completeness and audit readiness", "powerbi_table": "FactEvidence", "status": "Ready"},
        {"dataset": "synthetic_confidence.csv", "purpose": "Governance confidence score model", "powerbi_table": "FactConfidence", "status": "Ready"},
        {"dataset": "synthetic_audit_questions.csv", "purpose": "Audit simulation and inspection readiness", "powerbi_table": "FactAuditSimulation", "status": "Ready"},
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Synthetic Enterprise Datasets</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .top { background:#0f172a; color:white; padding:14px 24px; display:flex; justify-content:space-between; align-items:center; gap:18px; flex-wrap:wrap; position:sticky; top:0; z-index:10; }
            .brand { font-weight:900; font-size:18px; }
            .brand span { color:#38bdf8; }
            .nav { display:flex; gap:10px; flex-wrap:wrap; }
            .nav a { color:#dbeafe; text-decoration:none; font-size:12px; font-weight:800; padding:8px 10px; border-radius:999px; background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.12); }
            .nav a:hover { background:#2563eb; color:white; }
            .hero { background:linear-gradient(135deg,#111827,#0369a1); color:white; padding:36px 44px 78px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:40px; }
            .hero p { color:#e0f2fe; max-width:1120px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1320px; margin:-46px auto 40px; padding:0 24px; }
            .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            .kpi, .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            .kpi span { color:#64748b; font-weight:900; font-size:12px; text-transform:uppercase; letter-spacing:.07em; }
            .kpi strong { display:block; margin-top:9px; font-size:28px; }
            table { width:100%; border-collapse:collapse; }
            th { background:#e0f2fe; color:#075985; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .LOW, .Ready, .Complete, .YES { background:#dcfce7; color:#166534; }
            .MEDIUM, .Pending, .Watch { background:#fef3c7; color:#92400e; }
            .HIGH, .Missing, .NO { background:#fee2e2; color:#991b1b; }
            .note { background:#e0f2fe; border:1px solid #7dd3fc; color:#075985; padding:16px; border-radius:16px; margin-bottom:22px; }
            @media(max-width:1000px){ .grid4{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:650px){ .grid4{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <div class="top">
            <div class="brand">COBIT-Chain™ <span>Synthetic Dataset Layer</span></div>
            <nav class="nav">
                <a href="/enterprise-workspaces">Workspaces</a>
                <a href="/governance-relationship-graph">Graph</a>
                <a href="/governance-digital-twin">Digital Twin</a>
                <a href="/servicenow-governance-overlay">ServiceNow Overlay</a>
                <a href="/audit-simulation-engine">Audit</a>
            </nav>
        </div>

        <section class="hero">
            <h1>Live Synthetic Enterprise Dataset Layer</h1>
            <p>
                Controlled, non-confidential demo datasets that make the platform feel live while avoiding real company records.
                These records can feed ServiceNow overlay, shift intelligence, digital twin, audit simulation, confidence scoring, and Power BI demos.
            </p>
            <span class="badge">SYNTHETIC ONLY</span>
            <span class="badge">POWER BI READY</span>
            <span class="badge">NO CONFIDENTIAL DATA</span>
            <span class="badge">DEMO-SAFE DATA MODEL</span>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Executive meaning:</b> This dataset layer lets you demonstrate live governance intelligence without exposing Lilly, Point, Roche, or any real operational data.
            </div>

            <div class="grid4">
                <div class="kpi"><span>Demo Records</span><strong>{{ dataset_kpis.demo_records }}</strong></div>
                <div class="kpi"><span>Synthetic Tickets</span><strong>{{ dataset_kpis.synthetic_tickets }}</strong></div>
                <div class="kpi"><span>Equipment Assets</span><strong>{{ dataset_kpis.equipment_assets }}</strong></div>
                <div class="kpi"><span>Evidence Items</span><strong>{{ dataset_kpis.evidence_items }}</strong></div>
            </div>

            <div class="grid4">
                <div class="kpi"><span>Audit Questions</span><strong>{{ dataset_kpis.audit_questions }}</strong></div>
                <div class="kpi"><span>Confidence Rows</span><strong>{{ dataset_kpis.confidence_rows }}</strong></div>
                <div class="kpi"><span>Power BI Ready</span><strong>{{ dataset_kpis.powerbi_ready }}</strong></div>
                <div class="kpi"><span>Data Sensitivity</span><strong>{{ dataset_kpis.data_sensitivity }}</strong></div>
            </div>

            <section class="panel">
                <h2>1. Synthetic Ticket Dataset</h2>
                <table>
                    <tr><th>Ticket</th><th>Type</th><th>State</th><th>Shift</th><th>Equipment</th><th>Confidence</th><th>Risk</th></tr>
                    {% for t in ticket_dataset %}
                    <tr>
                        <td><b>{{ t.ticket }}</b></td>
                        <td>{{ t.type }}</td>
                        <td>{{ t.state }}</td>
                        <td>{{ t.shift }}</td>
                        <td>{{ t.equipment }}</td>
                        <td>{{ t.confidence }}</td>
                        <td><span class="pill {{ t.risk }}">{{ t.risk }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>2. Synthetic Equipment Dataset</h2>
                <table>
                    <tr><th>Asset</th><th>Owner</th><th>Backup</th><th>State</th><th>Evidence</th><th>Audit</th><th>Risk</th></tr>
                    {% for e in equipment_dataset %}
                    <tr>
                        <td><b>{{ e.asset }}</b></td>
                        <td>{{ e.owner }}</td>
                        <td>{{ e.backup }}</td>
                        <td>{{ e.state }}</td>
                        <td>{{ e.evidence }}</td>
                        <td>{{ e.audit }}</td>
                        <td><span class="pill {{ e.risk }}">{{ e.risk }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>3. Synthetic Evidence Dataset</h2>
                <table>
                    <tr><th>Evidence</th><th>Linked Record</th><th>Status</th><th>Hash Ready</th><th>Audit Value</th><th>Risk</th></tr>
                    {% for e in evidence_dataset %}
                    <tr>
                        <td><b>{{ e.evidence }}</b></td>
                        <td>{{ e.linked_record }}</td>
                        <td><span class="pill {{ e.status }}">{{ e.status }}</span></td>
                        <td><span class="pill {{ e.hash_ready }}">{{ e.hash_ready }}</span></td>
                        <td>{{ e.audit_value }}</td>
                        <td><span class="pill {{ e.risk }}">{{ e.risk }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>4. Confidence Dataset</h2>
                <table>
                    <tr><th>Factor</th><th>Score</th><th>Weight</th><th>Trend</th><th>Risk</th></tr>
                    {% for c in confidence_dataset %}
                    <tr>
                        <td><b>{{ c.factor }}</b></td>
                        <td>{{ c.score }}</td>
                        <td>{{ c.weight }}</td>
                        <td>{{ c.trend }}</td>
                        <td><span class="pill {{ c.risk }}">{{ c.risk }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>5. Power BI Export Catalog</h2>
                <table>
                    <tr><th>Dataset</th><th>Purpose</th><th>Power BI Table</th><th>Status</th></tr>
                    {% for x in export_catalog %}
                    <tr>
                        <td><b>{{ x.dataset }}</b></td>
                        <td>{{ x.purpose }}</td>
                        <td>{{ x.powerbi_table }}</td>
                        <td><span class="pill {{ x.status }}">{{ x.status }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>
        </main>
    </body>
    </html>
    """

    return render_template_string(
        html,
        dataset_kpis=dataset_kpis,
        ticket_dataset=ticket_dataset,
        equipment_dataset=equipment_dataset,
        evidence_dataset=evidence_dataset,
        confidence_dataset=confidence_dataset,
        export_catalog=export_catalog
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "SYNTHETIC_ENTERPRISE_DATASET_LAYER_ACTIVE",
    '@app.route("/synthetic-enterprise-datasets")',
    "Live Synthetic Enterprise Dataset Layer",
    "Synthetic Ticket Dataset",
    "Power BI Export Catalog"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Synthetic Enterprise Dataset Layer added safely at /synthetic-enterprise-datasets")
