from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_DIGITAL_TWIN_ACTIVE"

if MARKER in text:
    print("Governance Digital Twin already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# GOVERNANCE_DIGITAL_TWIN_ACTIVE
# Safe additive route only.
# Adds /governance-digital-twin without modifying protected modules.
# Shows connected governance state across ticket, shift, technician,
# equipment, evidence, review, confidence, and audit readiness.
# ============================================================

@app.route("/governance-digital-twin")
def governance_digital_twin():
    twin_kpis = {
        "governance_state": "Watch",
        "trust_score": "89%",
        "connected_nodes": "8",
        "open_gaps": "3",
        "audit_readiness": "84%",
        "blast_radius": "HIGH",
        "pre_deviation": "Active",
        "confidence_trend": "Recoverable"
    }

    twin_nodes = [
        {"node": "ServiceNow Ticket", "state": "In Progress", "signal": "SNOW-INC-10052 active with equipment linkage", "risk": "MEDIUM"},
        {"node": "Shift Window", "state": "B-to-C Transition", "signal": "Critical overlap window active", "risk": "MEDIUM"},
        {"node": "Technician Owner", "state": "Acknowledgement Pending", "signal": "Incoming owner not confirmed", "risk": "HIGH"},
        {"node": "Equipment", "state": "Warning", "signal": "Environmental monitoring device under watch", "risk": "HIGH"},
        {"node": "Evidence", "state": "Partial", "signal": "Audit trail export missing", "risk": "HIGH"},
        {"node": "Supervisor Review", "state": "Required", "signal": "Review checkpoint needed before closure", "risk": "MEDIUM"},
        {"node": "Confidence Score", "state": "89%", "signal": "Governed with minor gaps", "risk": "MEDIUM"},
        {"node": "Audit State", "state": "Conditionally Ready", "signal": "Export pack ready after evidence closure", "risk": "MEDIUM"},
    ]

    relationships = [
        {"from": "Ticket", "to": "Equipment", "relationship": "Ticket impact linked to equipment state", "governance_value": "Prevents orphaned technical issue"},
        {"from": "Ticket", "to": "Shift", "relationship": "Ticket belongs to active overlap window", "governance_value": "Supports ownership continuity"},
        {"from": "Shift", "to": "Technician", "relationship": "Incoming owner must acknowledge unresolved item", "governance_value": "Prevents handoff failure"},
        {"from": "Technician", "to": "Evidence", "relationship": "Technician must attach required evidence", "governance_value": "Supports audit defensibility"},
        {"from": "Evidence", "to": "Supervisor Review", "relationship": "Supervisor review depends on evidence completeness", "governance_value": "Prevents weak closure"},
        {"from": "Review", "to": "Audit State", "relationship": "Review outcome determines audit package confidence", "governance_value": "Supports inspection readiness"},
        {"from": "All Nodes", "to": "Confidence Score", "relationship": "Each node contributes to trust score", "governance_value": "Creates executive confidence view"},
    ]

    scenario_questions = [
        {"question": "What if the incoming technician never acknowledges the issue?", "answer": "Ownership risk increases, confidence drops, supervisor review is forced, and audit readiness weakens."},
        {"question": "What if evidence is attached before closure?", "answer": "Evidence integrity improves, audit readiness increases, and confidence score recovers."},
        {"question": "What if the issue repeats across multiple transitions?", "answer": "The system treats it as a systemic continuity weakness and raises CAPA/deviation exposure."},
        {"question": "What if leadership asks whether the operation is safe to trust?", "answer": "The digital twin shows current state, weak nodes, confidence score, and remediation path."},
    ]

    recovery_path = [
        {"step": "1", "action": "Capture incoming technician acknowledgement", "effect": "Reduces ownership risk"},
        {"step": "2", "action": "Attach missing audit trail export", "effect": "Improves evidence integrity"},
        {"step": "3", "action": "Complete supervisor review checkpoint", "effect": "Improves closure defensibility"},
        {"step": "4", "action": "Recalculate governance confidence", "effect": "Updates executive trust score"},
        {"step": "5", "action": "Export audit package", "effect": "Creates inspection-ready record"},
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Governance Digital Twin</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .hero { background:linear-gradient(135deg,#111827,#0f766e); color:white; padding:36px 44px 78px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:40px; }
            .hero p { color:#ccfbf1; max-width:1080px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1320px; margin:-46px auto 40px; padding:0 24px; }
            .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            .kpi, .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            .kpi span { color:#64748b; font-weight:900; font-size:12px; text-transform:uppercase; letter-spacing:.07em; }
            .kpi strong { display:block; margin-top:9px; font-size:30px; }
            .twin { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; }
            .node { background:#f8fafc; border:1px solid #ccfbf1; border-radius:18px; padding:18px; min-height:145px; }
            .node h3 { margin:0 0 8px; color:#0f766e; }
            .node p { color:#475569; line-height:1.45; font-size:13px; }
            table { width:100%; border-collapse:collapse; }
            th { background:#ecfeff; color:#115e59; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .LOW { background:#dcfce7; color:#166534; }
            .MEDIUM, .Watch, .Recoverable, .Active { background:#fef3c7; color:#92400e; }
            .HIGH { background:#fee2e2; color:#991b1b; }
            .note { background:#ecfeff; border:1px solid #99f6e4; color:#115e59; padding:16px; border-radius:16px; margin-bottom:22px; }
            .toplinks { margin-top:18px; }
            .toplinks a { color:white; text-decoration:none; font-weight:800; margin-right:16px; }
            @media(max-width:1100px){ .twin,.grid4{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:700px){ .twin,.grid4{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <section class="hero">
            <h1>COBIT-Chain™ Governance Digital Twin</h1>
            <p>
                A connected operational governance model showing the live relationship between ServiceNow ticket,
                shift window, technician ownership, equipment state, evidence, supervisor review, confidence, and audit readiness.
            </p>
            <span class="badge">CONNECTED GOVERNANCE MODEL</span>
            <span class="badge">OPERATIONAL TRUST GRAPH</span>
            <span class="badge">PRE-DEVIATION SIGNALS</span>
            <span class="badge">AUDIT STATE</span>
            <div class="toplinks">
                <a href="/enterprise-workspaces">Enterprise Workspaces</a>
                <a href="/servicenow-governance-overlay">ServiceNow Overlay</a>
                <a href="/governance-confidence-engine">Governance Confidence</a>
                <a href="/audit-simulation-engine">Audit Simulation</a>
            </div>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Executive meaning:</b> The digital twin does not just show records. It shows how records depend on each other
                and where operational trust can break.
            </div>

            <div class="grid4">
                <div class="kpi"><span>Governance State</span><strong>{{ twin_kpis.governance_state }}</strong></div>
                <div class="kpi"><span>Trust Score</span><strong>{{ twin_kpis.trust_score }}</strong></div>
                <div class="kpi"><span>Connected Nodes</span><strong>{{ twin_kpis.connected_nodes }}</strong></div>
                <div class="kpi"><span>Open Gaps</span><strong>{{ twin_kpis.open_gaps }}</strong></div>
            </div>

            <div class="grid4">
                <div class="kpi"><span>Audit Readiness</span><strong>{{ twin_kpis.audit_readiness }}</strong></div>
                <div class="kpi"><span>Blast Radius</span><strong>{{ twin_kpis.blast_radius }}</strong></div>
                <div class="kpi"><span>Pre-Deviation</span><strong>{{ twin_kpis.pre_deviation }}</strong></div>
                <div class="kpi"><span>Confidence Trend</span><strong>{{ twin_kpis.confidence_trend }}</strong></div>
            </div>

            <section class="panel">
                <h2>1. Digital Twin Nodes</h2>
                <div class="twin">
                    {% for n in twin_nodes %}
                    <div class="node">
                        <h3>{{ n.node }}</h3>
                        <p><b>State:</b> {{ n.state }}</p>
                        <p>{{ n.signal }}</p>
                        <span class="pill {{ n.risk }}">{{ n.risk }}</span>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="panel">
                <h2>2. Governance Relationships</h2>
                <table>
                    <tr><th>From</th><th>To</th><th>Relationship</th><th>Governance Value</th></tr>
                    {% for r in relationships %}
                    <tr>
                        <td><b>{{ r.from }}</b></td>
                        <td><b>{{ r.to }}</b></td>
                        <td>{{ r.relationship }}</td>
                        <td>{{ r.governance_value }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>3. Scenario Questions</h2>
                <table>
                    <tr><th>Leadership Question</th><th>Digital Twin Answer</th></tr>
                    {% for q in scenario_questions %}
                    <tr>
                        <td><b>{{ q.question }}</b></td>
                        <td>{{ q.answer }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>4. Recovery Path</h2>
                <table>
                    <tr><th>Step</th><th>Action</th><th>Effect</th></tr>
                    {% for r in recovery_path %}
                    <tr>
                        <td><b>{{ r.step }}</b></td>
                        <td>{{ r.action }}</td>
                        <td>{{ r.effect }}</td>
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
        twin_kpis=twin_kpis,
        twin_nodes=twin_nodes,
        relationships=relationships,
        scenario_questions=scenario_questions,
        recovery_path=recovery_path
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "GOVERNANCE_DIGITAL_TWIN_ACTIVE",
    '@app.route("/governance-digital-twin")',
    "Governance Digital Twin",
    "Digital Twin Nodes",
    "Governance Relationships"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Governance Digital Twin added safely at /governance-digital-twin")
