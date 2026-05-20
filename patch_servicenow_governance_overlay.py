from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SERVICENOW_GOVERNANCE_OVERLAY_ACTIVE"

if MARKER in text:
    print("ServiceNow Governance Overlay already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# SERVICENOW_GOVERNANCE_OVERLAY_ACTIVE
# Safe additive route only.
# Adds /servicenow-governance-overlay without modifying protected modules.
# Shows ServiceNow as workflow state and COBIT-Chain as governance trust state.
# ============================================================

@app.route("/servicenow-governance-overlay")
def servicenow_governance_overlay():
    overlay_kpis = {
        "tickets_analyzed": "12",
        "governed_tickets": "9",
        "governance_exceptions": "3",
        "confidence_score": "88%",
        "orphaned_ownership": "1",
        "missing_evidence": "2",
        "audit_exposure": "MEDIUM",
        "overlay_status": "Simulation Ready"
    }

    ticket_overlay = [
        {
            "ticket": "SNOW-INC-10052",
            "servicenow_state": "In Progress",
            "workflow_owner": "Support Queue",
            "equipment": "Environmental Monitoring Device",
            "cobitchain_state": "Governance Exception",
            "trust_score": "74%",
            "exception": "Missing incoming handoff acknowledgement and evidence export",
            "risk": "HIGH"
        },
        {
            "ticket": "SNOW-WO-20488",
            "servicenow_state": "Assigned",
            "workflow_owner": "Technician Group",
            "equipment": "Sterile Process Support Unit",
            "cobitchain_state": "Evidence Pending",
            "trust_score": "82%",
            "exception": "PM evidence not yet attached to closure package",
            "risk": "MEDIUM"
        },
        {
            "ticket": "SNOW-INC-10041",
            "servicenow_state": "Resolved",
            "workflow_owner": "BMS Support",
            "equipment": "Critical Utility Monitor",
            "cobitchain_state": "Governed",
            "trust_score": "96%",
            "exception": "No governance exception detected",
            "risk": "LOW"
        },
        {
            "ticket": "SNOW-WO-20517",
            "servicenow_state": "Closed",
            "workflow_owner": "Night Support",
            "equipment": "GMP Equipment Cluster",
            "cobitchain_state": "Governed With Review",
            "trust_score": "91%",
            "exception": "Supervisor review completed; evidence lineage intact",
            "risk": "LOW"
        },
    ]

    governance_controls = [
        {
            "control": "Ownership Continuity",
            "servicenow_view": "Assigned to group / individual",
            "cobitchain_overlay": "Checks whether ownership survived shift transition and backup owner exists.",
            "value": "Prevents orphaned tickets."
        },
        {
            "control": "Evidence Completeness",
            "servicenow_view": "Attachment may exist on ticket",
            "cobitchain_overlay": "Checks whether required evidence exists, is linked to equipment, and is audit-ready.",
            "value": "Prevents weak closure."
        },
        {
            "control": "Audit Defensibility",
            "servicenow_view": "Ticket is resolved or closed",
            "cobitchain_overlay": "Checks whether closure is supported by lineage, review, evidence, and confidence score.",
            "value": "Makes closure defensible."
        },
        {
            "control": "Pre-Deviation Risk",
            "servicenow_view": "No deviation until deviation is created",
            "cobitchain_overlay": "Detects weak signals before deviation/CAPA risk materializes.",
            "value": "Supports proactive prevention."
        },
        {
            "control": "Blast Radius",
            "servicenow_view": "Ticket impact field or related records",
            "cobitchain_overlay": "Maps downstream impact across shift, equipment, evidence, review, and audit readiness.",
            "value": "Improves impact analysis."
        },
    ]

    overlay_flow = [
        {"step": "1", "title": "ServiceNow Ticket Created", "description": "Incident or work order enters the operational workflow."},
        {"step": "2", "title": "COBIT-Chain Intake", "description": "Ticket is evaluated for equipment context, shift window, ownership, and evidence requirements."},
        {"step": "3", "title": "Governance Scoring", "description": "Confidence score is calculated using ownership, evidence, handoff, review, and audit readiness."},
        {"step": "4", "title": "Exception Detection", "description": "Orphaned ownership, missing evidence, weak handoff, or review gaps are flagged."},
        {"step": "5", "title": "Audit-Ready Outcome", "description": "Ticket can be trusted, remediated, escalated, or blocked from weak closure."},
    ]

    executive_points = [
        "ServiceNow remains the system of record for workflow and ticket state.",
        "COBIT-Chain adds a governance trust state on top of the workflow state.",
        "A closed ticket is not automatically a governed ticket.",
        "The overlay identifies missing evidence, weak handoff, orphaned ownership, and audit exposure.",
        "This lets leadership see which operational records are trustworthy before audit, deviation, or CAPA pressure."
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain ServiceNow Governance Overlay</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .hero { background:linear-gradient(135deg,#111827,#0284c7); color:white; padding:36px 44px 78px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:40px; }
            .hero p { color:#e0f2fe; max-width:1080px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1320px; margin:-46px auto 40px; padding:0 24px; }
            .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            .kpi, .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            .kpi span { color:#64748b; font-weight:900; font-size:12px; text-transform:uppercase; letter-spacing:.07em; }
            .kpi strong { display:block; margin-top:9px; font-size:30px; }
            table { width:100%; border-collapse:collapse; }
            th { background:#e0f2fe; color:#075985; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .LOW, .Governed { background:#dcfce7; color:#166534; }
            .MEDIUM, .Evidence { background:#fef3c7; color:#92400e; }
            .HIGH, .Governance { background:#fee2e2; color:#991b1b; }
            .flow { display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin-top:14px; }
            .step { background:#f8fafc; border:1px solid #bae6fd; border-radius:16px; padding:16px; min-height:155px; }
            .step b { display:block; color:#0369a1; margin-bottom:8px; font-size:18px; }
            .note { background:#e0f2fe; border:1px solid #7dd3fc; color:#075985; padding:16px; border-radius:16px; margin-bottom:22px; }
            .toplinks { margin-top:18px; }
            .toplinks a { color:white; text-decoration:none; font-weight:800; margin-right:16px; }
            ul { line-height:1.8; }
            @media(max-width:1100px){ .flow{grid-template-columns:repeat(2,1fr);} .grid4{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:700px){ .flow,.grid4{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <section class="hero">
            <h1>COBIT-Chain™ ServiceNow Governance Overlay</h1>
            <p>
                ServiceNow shows workflow state. COBIT-Chain adds governance trust state: ownership continuity,
                evidence completeness, handoff integrity, audit readiness, and pre-deviation risk.
            </p>
            <span class="badge">SERVICENOW-AWARE</span>
            <span class="badge">GOVERNANCE TRUST STATE</span>
            <span class="badge">EVIDENCE READINESS</span>
            <span class="badge">AUDIT DEFENSIBILITY</span>
            <div class="toplinks">
                <a href="/enterprise-workspaces">Enterprise Workspaces</a>
                <a href="/governance-confidence-engine">Governance Confidence</a>
                <a href="/audit-simulation-engine">Audit Simulation</a>
                <a href="/operational-lineage">Operational Lineage</a>
            </div>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Executive message:</b> A ServiceNow ticket can be closed but still weak from a governance perspective.
                COBIT-Chain evaluates whether that ticket is operationally and auditably trustworthy.
            </div>

            <div class="grid4">
                <div class="kpi"><span>Tickets Analyzed</span><strong>{{ overlay_kpis.tickets_analyzed }}</strong></div>
                <div class="kpi"><span>Governed Tickets</span><strong>{{ overlay_kpis.governed_tickets }}</strong></div>
                <div class="kpi"><span>Governance Exceptions</span><strong>{{ overlay_kpis.governance_exceptions }}</strong></div>
                <div class="kpi"><span>Confidence Score</span><strong>{{ overlay_kpis.confidence_score }}</strong></div>
            </div>

            <div class="grid4">
                <div class="kpi"><span>Orphaned Ownership</span><strong>{{ overlay_kpis.orphaned_ownership }}</strong></div>
                <div class="kpi"><span>Missing Evidence</span><strong>{{ overlay_kpis.missing_evidence }}</strong></div>
                <div class="kpi"><span>Audit Exposure</span><strong>{{ overlay_kpis.audit_exposure }}</strong></div>
                <div class="kpi"><span>Overlay Status</span><strong>{{ overlay_kpis.overlay_status }}</strong></div>
            </div>

            <section class="panel">
                <h2>1. Ticket Governance Overlay</h2>
                <table>
                    <tr><th>Ticket</th><th>ServiceNow State</th><th>Workflow Owner</th><th>Equipment</th><th>COBIT-Chain State</th><th>Trust Score</th><th>Exception</th><th>Risk</th></tr>
                    {% for t in ticket_overlay %}
                    <tr>
                        <td><b>{{ t.ticket }}</b></td>
                        <td>{{ t.servicenow_state }}</td>
                        <td>{{ t.workflow_owner }}</td>
                        <td>{{ t.equipment }}</td>
                        <td>{{ t.cobitchain_state }}</td>
                        <td><b>{{ t.trust_score }}</b></td>
                        <td>{{ t.exception }}</td>
                        <td><span class="pill {{ t.risk }}">{{ t.risk }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>2. ServiceNow State vs COBIT-Chain Trust State</h2>
                <table>
                    <tr><th>Control Area</th><th>ServiceNow View</th><th>COBIT-Chain Overlay</th><th>Enterprise Value</th></tr>
                    {% for c in governance_controls %}
                    <tr>
                        <td><b>{{ c.control }}</b></td>
                        <td>{{ c.servicenow_view }}</td>
                        <td>{{ c.cobitchain_overlay }}</td>
                        <td>{{ c.value }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>3. Overlay Flow</h2>
                <div class="flow">
                    {% for f in overlay_flow %}
                    <div class="step">
                        <b>{{ f.step }}. {{ f.title }}</b>
                        <p>{{ f.description }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="panel">
                <h2>4. Executive Talking Points</h2>
                <ul>
                    {% for point in executive_points %}
                    <li>{{ point }}</li>
                    {% endfor %}
                </ul>
            </section>
        </main>
    </body>
    </html>
    """

    return render_template_string(
        html,
        overlay_kpis=overlay_kpis,
        ticket_overlay=ticket_overlay,
        governance_controls=governance_controls,
        overlay_flow=overlay_flow,
        executive_points=executive_points
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "SERVICENOW_GOVERNANCE_OVERLAY_ACTIVE",
    '@app.route("/servicenow-governance-overlay")',
    "ServiceNow Governance Overlay",
    "Ticket Governance Overlay",
    "ServiceNow State vs COBIT-Chain Trust State"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: ServiceNow Governance Overlay added safely at /servicenow-governance-overlay")
