from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "PREDICTIVE_GOVERNANCE_DRIFT_ENGINE_ACTIVE"

if MARKER in text:
    print("Predictive Governance Drift Engine already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# PREDICTIVE_GOVERNANCE_DRIFT_ENGINE_ACTIVE
# Safe additive route only.
# Adds /predictive-governance-drift without modifying protected modules.
# Synthetic predictive governance intelligence simulation.
# ============================================================

@app.route("/predictive-governance-drift")
def predictive_governance_drift():

    drift_kpis = {
        "current_confidence": "89%",
        "projected_24h": "84%",
        "projected_72h": "77%",
        "projected_7d": "68%",
        "audit_exposure_window": "48 Hours",
        "projected_blast_radius": "HIGH",
        "risk_velocity": "Accelerating",
        "model_mode": "Synthetic Predictive"
    }

    drift_timeline = [
        {
            "window": "Current",
            "confidence": "89%",
            "state": "Governed Under Watch",
            "driver": "Evidence gap + pending overlap acknowledgement",
            "risk": "MEDIUM"
        },
        {
            "window": "+24 Hours",
            "confidence": "84%",
            "state": "Audit Concern Emerging",
            "driver": "Supervisor checkpoint still incomplete",
            "risk": "MEDIUM"
        },
        {
            "window": "+72 Hours",
            "confidence": "77%",
            "state": "Escalation Threshold",
            "driver": "Operational trust divergence increasing",
            "risk": "HIGH"
        },
        {
            "window": "+7 Days",
            "confidence": "68%",
            "state": "Potential Deviation Exposure",
            "driver": "Persistent unresolved evidence chain weakness",
            "risk": "HIGH"
        },
    ]

    predicted_failures = [
        {
            "area": "Audit Readiness",
            "prediction": "Auditor questions evidence completeness first",
            "likelihood": "92%",
            "impact": "High",
            "time_window": "24-48 Hours"
        },
        {
            "area": "Shift Continuity",
            "prediction": "Unverified ownership causes governance drift",
            "likelihood": "87%",
            "impact": "Medium",
            "time_window": "48 Hours"
        },
        {
            "area": "Supervisor Review",
            "prediction": "Delayed review weakens closure defensibility",
            "likelihood": "81%",
            "impact": "Medium",
            "time_window": "72 Hours"
        },
        {
            "area": "CAPA / Deviation",
            "prediction": "Governance weakness becomes formal quality issue",
            "likelihood": "63%",
            "impact": "High",
            "time_window": "5-7 Days"
        },
    ]

    intervention_models = [
        {
            "action": "Attach missing audit trail export",
            "confidence_recovery": "+5",
            "blast_radius_change": "HIGH → MEDIUM",
            "audit_readiness_gain": "+6",
            "priority": "P1"
        },
        {
            "action": "Capture incoming owner acknowledgement",
            "confidence_recovery": "+3",
            "blast_radius_change": "MEDIUM → CONTROLLED",
            "audit_readiness_gain": "+2",
            "priority": "P1"
        },
        {
            "action": "Complete supervisor review checkpoint",
            "confidence_recovery": "+4",
            "blast_radius_change": "CONTROLLED",
            "audit_readiness_gain": "+5",
            "priority": "P2"
        },
        {
            "action": "Recalculate governance trust state",
            "confidence_recovery": "Dynamic",
            "blast_radius_change": "Re-modeled",
            "audit_readiness_gain": "Updated",
            "priority": "P2"
        },
    ]

    predictive_story = [
        "The platform is now estimating where governance posture is heading.",
        "This changes governance from reactive reporting into predictive intelligence.",
        "Leadership can see projected confidence degradation before operational failure occurs.",
        "The system forecasts which weakness becomes material first.",
        "Recovery actions can now be prioritized by projected trust restoration impact."
    ]

    drift_curve = [
        {"label": "Current", "score": 89},
        {"label": "+24h", "score": 84},
        {"label": "+72h", "score": 77},
        {"label": "+7d", "score": 68},
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Predictive Governance Drift</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .top { background:#0f172a; color:white; padding:14px 24px; display:flex; justify-content:space-between; align-items:center; gap:18px; flex-wrap:wrap; position:sticky; top:0; z-index:10; }
            .brand { font-weight:900; font-size:18px; }
            .brand span { color:#38bdf8; }
            .nav { display:flex; gap:10px; flex-wrap:wrap; }
            .nav a { color:#dbeafe; text-decoration:none; font-size:12px; font-weight:800; padding:8px 10px; border-radius:999px; background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.12); }
            .nav a:hover { background:#2563eb; color:white; }
            .hero { background:linear-gradient(135deg,#111827,#b91c1c); color:white; padding:38px 44px 82px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:42px; }
            .hero p { color:#fee2e2; max-width:1120px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1360px; margin:-48px auto 40px; padding:0 24px; }
            .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            .kpi, .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            .kpi span { color:#64748b; font-weight:900; font-size:12px; text-transform:uppercase; letter-spacing:.07em; }
            .kpi strong { display:block; margin-top:9px; font-size:28px; }
            table { width:100%; border-collapse:collapse; }
            th { background:#fee2e2; color:#991b1b; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .HIGH, .P1 { background:#fee2e2; color:#991b1b; }
            .MEDIUM, .P2 { background:#fef3c7; color:#92400e; }
            .LOW { background:#dcfce7; color:#166534; }
            .curve {
                display:flex;
                align-items:flex-end;
                gap:22px;
                height:260px;
                padding:30px 10px 10px;
            }
            .bar-wrap { text-align:center; flex:1; }
            .bar {
                width:100%;
                background:linear-gradient(180deg,#ef4444,#7f1d1d);
                border-radius:14px 14px 0 0;
                position:relative;
            }
            .bar span {
                position:absolute;
                top:-28px;
                left:50%;
                transform:translateX(-50%);
                font-weight:900;
                color:#991b1b;
            }
            .curve-label { margin-top:10px; font-weight:900; color:#334155; }
            .note { background:#fef2f2; border:1px solid #fecaca; color:#991b1b; padding:16px; border-radius:16px; margin-bottom:22px; }
            ul { line-height:1.8; color:#334155; }
            @media(max-width:1000px){ .grid4{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:700px){ .grid4{grid-template-columns:1fr;} .hero h1{font-size:30px;} .curve{height:220px;} }
        </style>
    </head>
    <body>
        <div class="top">
            <div class="brand">COBIT-Chain™ <span>Predictive Governance Drift</span></div>
            <nav class="nav">
                <a href="/executive-mission-control">Mission Control</a>
                <a href="/ai-governance-copilot">AI Copilot</a>
                <a href="/live-governance-ticker">Live Ticker</a>
                <a href="/governance-confidence-engine">Confidence</a>
                <a href="/governance-blast-radius">Blast Radius</a>
            </nav>
        </div>

        <section class="hero">
            <h1>Predictive Governance Drift Engine™</h1>
            <p>
                A synthetic predictive intelligence layer estimating governance degradation,
                projected audit exposure, blast radius expansion, and operational trust decline
                before failure becomes visible operationally.
            </p>
            <span class="badge">PREDICTIVE GOVERNANCE</span>
            <span class="badge">CONFIDENCE FORECASTING</span>
            <span class="badge">AUDIT EXPOSURE MODELING</span>
            <span class="badge">RISK VELOCITY ANALYSIS</span>
        </section>

        <main class="wrap">

            <div class="note">
                <b>Executive meaning:</b> This moves the platform from reactive governance reporting
                into predictive governance intelligence.
            </div>

            <div class="grid4">
                <div class="kpi"><span>Current Confidence</span><strong>{{ drift_kpis.current_confidence }}</strong></div>
                <div class="kpi"><span>Projected 24h</span><strong>{{ drift_kpis.projected_24h }}</strong></div>
                <div class="kpi"><span>Projected 72h</span><strong>{{ drift_kpis.projected_72h }}</strong></div>
                <div class="kpi"><span>Projected 7d</span><strong>{{ drift_kpis.projected_7d }}</strong></div>
            </div>

            <div class="grid4">
                <div class="kpi"><span>Audit Exposure Window</span><strong>{{ drift_kpis.audit_exposure_window }}</strong></div>
                <div class="kpi"><span>Projected Blast Radius</span><strong>{{ drift_kpis.projected_blast_radius }}</strong></div>
                <div class="kpi"><span>Risk Velocity</span><strong>{{ drift_kpis.risk_velocity }}</strong></div>
                <div class="kpi"><span>Model Mode</span><strong>{{ drift_kpis.model_mode }}</strong></div>
            </div>

            <section class="panel">
                <h2>1. Predictive Confidence Curve</h2>

                <div class="curve">
                    {% for d in drift_curve %}
                    <div class="bar-wrap">
                        <div class="bar" style="height: {{ d.score * 2 }}px;">
                            <span>{{ d.score }}%</span>
                        </div>
                        <div class="curve-label">{{ d.label }}</div>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="panel">
                <h2>2. Governance Drift Timeline</h2>
                <table>
                    <tr><th>Window</th><th>Confidence</th><th>Projected State</th><th>Primary Driver</th><th>Risk</th></tr>
                    {% for d in drift_timeline %}
                    <tr>
                        <td><b>{{ d.window }}</b></td>
                        <td>{{ d.confidence }}</td>
                        <td>{{ d.state }}</td>
                        <td>{{ d.driver }}</td>
                        <td><span class="pill {{ d.risk }}">{{ d.risk }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>3. Predicted Governance Failures</h2>
                <table>
                    <tr><th>Area</th><th>Prediction</th><th>Likelihood</th><th>Impact</th><th>Window</th></tr>
                    {% for p in predicted_failures %}
                    <tr>
                        <td><b>{{ p.area }}</b></td>
                        <td>{{ p.prediction }}</td>
                        <td>{{ p.likelihood }}</td>
                        <td>{{ p.impact }}</td>
                        <td>{{ p.time_window }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>4. Intervention Simulation</h2>
                <table>
                    <tr><th>Priority</th><th>Action</th><th>Confidence Recovery</th><th>Blast Radius Change</th><th>Audit Gain</th></tr>
                    {% for i in intervention_models %}
                    <tr>
                        <td><span class="pill {{ i.priority }}">{{ i.priority }}</span></td>
                        <td><b>{{ i.action }}</b></td>
                        <td>{{ i.confidence_recovery }}</td>
                        <td>{{ i.blast_radius_change }}</td>
                        <td>{{ i.audit_readiness_gain }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>5. Predictive Governance Story</h2>
                <ul>
                    {% for p in predictive_story %}
                    <li>{{ p }}</li>
                    {% endfor %}
                </ul>
            </section>

        </main>
    </body>
    </html>
    """

    return render_template_string(
        html,
        drift_kpis=drift_kpis,
        drift_timeline=drift_timeline,
        predicted_failures=predicted_failures,
        intervention_models=intervention_models,
        predictive_story=predictive_story,
        drift_curve=drift_curve
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "PREDICTIVE_GOVERNANCE_DRIFT_ENGINE_ACTIVE",
    '@app.route("/predictive-governance-drift")',
    "Predictive Governance Drift Engine",
    "Predictive Confidence Curve",
    "Predicted Governance Failures"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Predictive Governance Drift Engine added safely at /predictive-governance-drift")
