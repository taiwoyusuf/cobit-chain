from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_RECONCILIATION_LAYER_ACTIVE"

if MARKER in text:
    print("Governance Reconciliation Layer already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# GOVERNANCE_RECONCILIATION_LAYER_ACTIVE
# Safe additive route only.
# Adds /governance-reconciliation-layer without modifying protected modules.
# Reconciles conflicting workflow truth states across systems.
# ============================================================

@app.route("/governance-reconciliation-layer")
def governance_reconciliation_layer():

    reconciliation_kpis = {
        "systems_reconciled": "6",
        "mismatched_states": "4",
        "truth_alignment_score": "74%",
        "held_workflows": "2",
        "false_closure_risk": "HIGH",
        "reconciliation_alerts": "5",
        "audit_exposure": "HIGH",
        "reconciliation_mode": "Synthetic Enterprise"
    }

    reconciliation_cases = [
        {
            "workflow": "Lab Result Release",
            "middleware": "Verified",
            "lis": "Held",
            "downstream": "Unavailable",
            "servicenow": "Closed",
            "cobitchain_truth": "NOT RECONCILED",
            "issue": "Operational systems disagree on workflow completion.",
            "impact": "Potential false closure and audit exposure.",
            "risk": "HIGH"
        },
        {
            "workflow": "QC Sample Disposition",
            "middleware": "Processed",
            "lis": "Pending QA Review",
            "downstream": "Batch Hold",
            "servicenow": "Resolved",
            "cobitchain_truth": "PARTIAL",
            "issue": "Workflow appears operationally processed but QA dependency remains incomplete.",
            "impact": "Batch disposition cannot be trusted as complete.",
            "risk": "HIGH"
        },
        {
            "workflow": "Deviation Closure",
            "middleware": "N/A",
            "lis": "N/A",
            "downstream": "CAPA Pending",
            "servicenow": "Closed",
            "cobitchain_truth": "REOPEN REQUIRED",
            "issue": "Workflow closure occurred before CAPA dependency resolution.",
            "impact": "Weak governance closure path.",
            "risk": "MEDIUM"
        },
        {
            "workflow": "Audit Trail Export",
            "middleware": "Export Generated",
            "lis": "Export Approved",
            "downstream": "Evidence Repository Updated",
            "servicenow": "Closed",
            "cobitchain_truth": "RECONCILED",
            "issue": "All systems align on completion state.",
            "impact": "Audit-ready workflow.",
            "risk": "LOW"
        },
    ]

    reconciliation_logic = [
        {
            "control": "Cross-system truth validation",
            "logic": "Workflow completion requires dependent systems to align before closure is trusted.",
            "value": "Prevents one-system false completion assumptions."
        },
        {
            "control": "False closure detection",
            "logic": "If ServiceNow shows Closed but dependent systems remain incomplete, COBIT-Chain flags weak closure.",
            "value": "Protects governance integrity."
        },
        {
            "control": "Dependency-aware workflow truth",
            "logic": "Held, pending review, CAPA, or blocked downstream states prevent trusted completion.",
            "value": "Reflects operational reality."
        },
        {
            "control": "Reconciliation-based audit readiness",
            "logic": "Audit readiness requires aligned evidence, review, release, and dependency states.",
            "value": "Improves inspection defensibility."
        },
    ]

    system_relationships = [
        {"system": "Middleware", "purpose": "Initial processing and verification"},
        {"system": "LIS/LIMS", "purpose": "Controlled review, hold, release, and approval"},
        {"system": "Downstream Consumer", "purpose": "Operational usage or release state"},
        {"system": "ServiceNow", "purpose": "Workflow and ticket state"},
        {"system": "QA / CAPA", "purpose": "Governance dependency oversight"},
        {"system": "COBIT-Chain™", "purpose": "Enterprise reconciliation and workflow truth assurance"},
    ]

    executive_summary = [
        "Different systems can disagree about whether work is truly complete.",
        "COBIT-Chain reconciles operational truth across dependent systems before governance trust is granted.",
        "This prevents false closure, weak audit defensibility, and downstream release assumptions.",
        "Workflow completion becomes dependency-aware, not ticket-aware.",
        "The reconciliation layer strengthens GMP, QA, middleware/LIS, CAPA, and enterprise operational governance."
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Governance Reconciliation Layer</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .top { background:#0f172a; color:white; padding:14px 24px; display:flex; justify-content:space-between; align-items:center; gap:18px; flex-wrap:wrap; position:sticky; top:0; z-index:10; }
            .brand { font-weight:900; font-size:18px; }
            .brand span { color:#38bdf8; }
            .nav { display:flex; gap:10px; flex-wrap:wrap; }
            .nav a { color:#dbeafe; text-decoration:none; font-size:12px; font-weight:800; padding:8px 10px; border-radius:999px; background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.12); }
            .nav a:hover { background:#2563eb; color:white; }
            .hero { background:linear-gradient(135deg,#111827,#7c3aed); color:white; padding:38px 44px 82px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:42px; }
            .hero p { color:#ede9fe; max-width:1120px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1360px; margin:-48px auto 40px; padding:0 24px; }
            .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            .kpi, .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            .kpi span { color:#64748b; font-weight:900; font-size:12px; text-transform:uppercase; letter-spacing:.07em; }
            .kpi strong { display:block; margin-top:9px; font-size:26px; }
            table { width:100%; border-collapse:collapse; }
            th { background:#f5f3ff; color:#5b21b6; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .LOW, .RECONCILED { background:#dcfce7; color:#166534; }
            .MEDIUM, .PARTIAL { background:#fef3c7; color:#92400e; }
            .HIGH, .NOT, .REOPEN { background:#fee2e2; color:#991b1b; }
            .system-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:14px; }
            .system-card { background:#f8fafc; border:1px solid #ddd6fe; border-radius:18px; padding:18px; }
            .system-card h3 { margin:0 0 8px; color:#5b21b6; }
            .system-card p { color:#334155; font-size:13px; line-height:1.45; }
            .note { background:#f5f3ff; border:1px solid #ddd6fe; color:#5b21b6; padding:16px; border-radius:16px; margin-bottom:22px; }
            ul { line-height:1.8; color:#334155; }
            @media(max-width:1100px){ .grid4,.system-grid{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:700px){ .grid4,.system-grid{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <div class="top">
            <div class="brand">COBIT-Chain™ <span>Governance Reconciliation Layer</span></div>
            <nav class="nav">
                <a href="/governance-digital-command-center">Command Center</a>
                <a href="/cross-system-dependency-validation">Dependency Validation</a>
                <a href="/executive-mission-control">Mission Control</a>
                <a href="/ai-governance-copilot">AI Copilot</a>
                <a href="/audit-simulation-engine">Audit</a>
            </nav>
        </div>

        <section class="hero">
            <h1>Governance Reconciliation Layer™</h1>
            <p>
                Reconciles conflicting workflow states across systems and determines whether operational truth,
                release readiness, governance closure, and audit defensibility are genuinely aligned.
            </p>
            <span class="badge">WORKFLOW RECONCILIATION</span>
            <span class="badge">FALSE CLOSURE DETECTION</span>
            <span class="badge">DEPENDENCY-AWARE GOVERNANCE</span>
            <span class="badge">ENTERPRISE TRUTH VALIDATION</span>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Core principle:</b> workflow completion is not trusted until dependent systems reconcile to the same operational truth state.
            </div>

            <div class="grid4">
                <div class="kpi"><span>Systems Reconciled</span><strong>{{ reconciliation_kpis.systems_reconciled }}</strong></div>
                <div class="kpi"><span>Mismatched States</span><strong>{{ reconciliation_kpis.mismatched_states }}</strong></div>
                <div class="kpi"><span>Truth Alignment Score</span><strong>{{ reconciliation_kpis.truth_alignment_score }}</strong></div>
                <div class="kpi"><span>Held Workflows</span><strong>{{ reconciliation_kpis.held_workflows }}</strong></div>
            </div>

            <div class="grid4">
                <div class="kpi"><span>False Closure Risk</span><strong>{{ reconciliation_kpis.false_closure_risk }}</strong></div>
                <div class="kpi"><span>Reconciliation Alerts</span><strong>{{ reconciliation_kpis.reconciliation_alerts }}</strong></div>
                <div class="kpi"><span>Audit Exposure</span><strong>{{ reconciliation_kpis.audit_exposure }}</strong></div>
                <div class="kpi"><span>Reconciliation Mode</span><strong>{{ reconciliation_kpis.reconciliation_mode }}</strong></div>
            </div>

            <section class="panel">
                <h2>1. Enterprise Reconciliation Cases</h2>
                <table>
                    <tr>
                        <th>Workflow</th>
                        <th>Middleware</th>
                        <th>LIS/LIMS</th>
                        <th>Downstream</th>
                        <th>ServiceNow</th>
                        <th>COBIT-Chain Truth</th>
                        <th>Issue</th>
                        <th>Impact</th>
                        <th>Risk</th>
                    </tr>
                    {% for r in reconciliation_cases %}
                    <tr>
                        <td><b>{{ r.workflow }}</b></td>
                        <td>{{ r.middleware }}</td>
                        <td>{{ r.lis }}</td>
                        <td>{{ r.downstream }}</td>
                        <td>{{ r.servicenow }}</td>
                        <td><span class="pill {{ r.cobitchain_truth.split()[0] }}">{{ r.cobitchain_truth }}</span></td>
                        <td>{{ r.issue }}</td>
                        <td>{{ r.impact }}</td>
                        <td><span class="pill {{ r.risk }}">{{ r.risk }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>2. Reconciliation Logic</h2>
                <table>
                    <tr><th>Control</th><th>Logic</th><th>Value</th></tr>
                    {% for l in reconciliation_logic %}
                    <tr>
                        <td><b>{{ l.control }}</b></td>
                        <td>{{ l.logic }}</td>
                        <td>{{ l.value }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>3. Enterprise Relationship Map</h2>
                <div class="system-grid">
                    {% for s in system_relationships %}
                    <div class="system-card">
                        <h3>{{ s.system }}</h3>
                        <p>{{ s.purpose }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="panel">
                <h2>4. Executive Summary</h2>
                <ul>
                    {% for e in executive_summary %}
                    <li>{{ e }}</li>
                    {% endfor %}
                </ul>
            </section>
        </main>
    </body>
    </html>
    """

    return render_template_string(
        html,
        reconciliation_kpis=reconciliation_kpis,
        reconciliation_cases=reconciliation_cases,
        reconciliation_logic=reconciliation_logic,
        system_relationships=system_relationships,
        executive_summary=executive_summary
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "GOVERNANCE_RECONCILIATION_LAYER_ACTIVE",
    '@app.route("/governance-reconciliation-layer")',
    "Governance Reconciliation Layer",
    "Enterprise Reconciliation Cases",
    "Reconciliation Logic"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Governance Reconciliation Layer added safely at /governance-reconciliation-layer")
