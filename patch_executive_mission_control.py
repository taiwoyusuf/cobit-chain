from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "EXECUTIVE_MISSION_CONTROL_ACTIVE"

if MARKER in text:
    print("Executive Mission Control already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# EXECUTIVE_MISSION_CONTROL_ACTIVE
# Safe additive route only.
# Adds /executive-mission-control without modifying protected modules.
# Single-pane executive governance command center.
# ============================================================

@app.route("/executive-mission-control")
def executive_mission_control():
    mission_kpis = {
        "governance_confidence": "89%",
        "audit_readiness": "84%",
        "operational_continuity": "91%",
        "service_now_trust": "88%",
        "open_governance_gaps": "3",
        "critical_alerts": "1",
        "blast_radius": "HIGH",
        "mission_status": "Watch"
    }

    boardroom_signals = [
        {
            "signal": "Evidence gap is the top trust limiter",
            "source": "Evidence Integrity",
            "impact": "Audit readiness and governance confidence remain constrained.",
            "priority": "P1",
            "route": "/synthetic-enterprise-datasets"
        },
        {
            "signal": "B-to-C handoff acknowledgement is pending",
            "source": "Shift Overlap Intelligence",
            "impact": "Operational continuity remains governed but under watch.",
            "priority": "P1",
            "route": "/shift-overlap-intelligence"
        },
        {
            "signal": "ServiceNow workflow state differs from trust state",
            "source": "ServiceNow Governance Overlay",
            "impact": "Ticket may be active operationally but weak from a governance standpoint.",
            "priority": "P2",
            "route": "/servicenow-governance-overlay"
        },
        {
            "signal": "Digital twin shows connected risk across evidence, review, and audit state",
            "source": "Governance Digital Twin",
            "impact": "Risk is not isolated; remediation must address connected nodes.",
            "priority": "P2",
            "route": "/governance-digital-twin"
        },
    ]

    command_tiles = [
        {"title": "Enterprise Workspaces", "route": "/enterprise-workspaces", "summary": "Open the full modular governance workspace hub.", "status": "LIVE"},
        {"title": "Executive Demo Flow", "route": "/executive-demo-flow", "summary": "Follow the guided leadership demonstration sequence.", "status": "LIVE"},
        {"title": "Live Governance Ticker", "route": "/live-governance-ticker", "summary": "View live-style governance alerts, drift, and remediation signals.", "status": "LIVE"},
        {"title": "Governance Relationship Graph", "route": "/governance-relationship-graph", "summary": "Visualize the operational trust graph and downstream dependencies.", "status": "LIVE"},
        {"title": "Governance Confidence Engine", "route": "/governance-confidence-engine", "summary": "Review executive trust score and confidence recovery plan.", "status": "LIVE"},
        {"title": "Audit Simulation Engine", "route": "/audit-simulation-engine", "summary": "Simulate what would fail first if audited today.", "status": "LIVE"},
        {"title": "ServiceNow Governance Overlay", "route": "/servicenow-governance-overlay", "summary": "Compare workflow state with governance trust state.", "status": "LIVE"},
        {"title": "Governance Digital Twin", "route": "/governance-digital-twin", "summary": "See connected ticket, shift, equipment, evidence, review, and audit state.", "status": "LIVE"},
    ]

    executive_recommendations = [
        {"priority": "P1", "recommendation": "Close evidence gap before operational closure", "expected_result": "Audit readiness +6, confidence +5"},
        {"priority": "P1", "recommendation": "Capture incoming technician acknowledgement", "expected_result": "Handoff integrity +3, continuity watch removed"},
        {"priority": "P2", "recommendation": "Complete supervisor review checkpoint", "expected_result": "Review readiness +4, closure defensibility improved"},
        {"priority": "P2", "recommendation": "Recalculate governance confidence after remediation", "expected_result": "Mission status can move from Watch to Governed"},
    ]

    mission_story = [
        "The platform is no longer presenting isolated governance pages.",
        "It is now showing a connected governance operating picture.",
        "Leadership can see confidence, risk, audit readiness, workflow trust, and remediation in one place.",
        "ServiceNow remains workflow state; COBIT-Chain adds governance trust state.",
        "The mission control view becomes the boardroom entry point for the whole platform."
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Executive Mission Control</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .top { background:#0f172a; color:white; padding:14px 24px; display:flex; justify-content:space-between; align-items:center; gap:18px; flex-wrap:wrap; position:sticky; top:0; z-index:10; }
            .brand { font-weight:900; font-size:18px; }
            .brand span { color:#38bdf8; }
            .nav { display:flex; gap:10px; flex-wrap:wrap; }
            .nav a { color:#dbeafe; text-decoration:none; font-size:12px; font-weight:800; padding:8px 10px; border-radius:999px; background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.12); }
            .nav a:hover { background:#2563eb; color:white; }
            .hero { background:linear-gradient(135deg,#020617,#1d4ed8); color:white; padding:38px 44px 82px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:42px; }
            .hero p { color:#dbeafe; max-width:1120px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1360px; margin:-48px auto 40px; padding:0 24px; }
            .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            .kpi, .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            .kpi span { color:#64748b; font-weight:900; font-size:12px; text-transform:uppercase; letter-spacing:.07em; }
            .kpi strong { display:block; margin-top:9px; font-size:28px; }
            .mission-layout { display:grid; grid-template-columns:1.2fr .8fr; gap:20px; }
            .tiles { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; }
            .tile { background:#f8fafc; border:1px solid #e2e8f0; border-radius:18px; padding:18px; min-height:170px; }
            .tile h3 { margin:0 0 8px; color:#1e3a8a; }
            .tile p { color:#475569; line-height:1.45; font-size:13px; }
            .tile a { display:inline-block; text-decoration:none; background:#0f172a; color:white; padding:9px 12px; border-radius:10px; font-weight:800; font-size:13px; margin-top:8px; }
            table { width:100%; border-collapse:collapse; }
            th { background:#eff6ff; color:#1e3a8a; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .LIVE, .Governed { background:#dcfce7; color:#166534; }
            .Watch, .MEDIUM, .P2 { background:#fef3c7; color:#92400e; }
            .HIGH, .P1 { background:#fee2e2; color:#991b1b; }
            .note { background:#eff6ff; border:1px solid #bfdbfe; color:#1e3a8a; padding:16px; border-radius:16px; margin-bottom:22px; }
            ul { line-height:1.8; color:#334155; }
            @media(max-width:1200px){ .tiles{grid-template-columns:repeat(2,1fr);} .mission-layout{grid-template-columns:1fr;} .grid4{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:700px){ .tiles,.grid4{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <div class="top">
            <div class="brand">COBIT-Chain™ <span>Executive Mission Control</span></div>
            <nav class="nav">
                <a href="/enterprise-workspaces">Workspaces</a>
                <a href="/executive-demo-flow">Demo Flow</a>
                <a href="/live-governance-ticker">Live Ticker</a>
                <a href="/governance-relationship-graph">Graph</a>
                <a href="/platform-health">Health</a>
            </nav>
        </div>

        <section class="hero">
            <h1>Executive Mission Control Dashboard™</h1>
            <p>
                A single-pane executive governance command center combining confidence, audit readiness,
                operational continuity, ServiceNow trust state, blast radius, live alerts, and remediation recommendations.
            </p>
            <span class="badge">SINGLE PANE OF GLASS</span>
            <span class="badge">BOARDROOM READY</span>
            <span class="badge">GOVERNANCE TRUST STATE</span>
            <span class="badge">MISSION STATUS: {{ mission_kpis.mission_status }}</span>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Executive meaning:</b> This page is the leadership entry point. It shows whether the operation can be trusted,
                what is limiting trust, and what action restores confidence.
            </div>

            <div class="grid4">
                <div class="kpi"><span>Governance Confidence</span><strong>{{ mission_kpis.governance_confidence }}</strong></div>
                <div class="kpi"><span>Audit Readiness</span><strong>{{ mission_kpis.audit_readiness }}</strong></div>
                <div class="kpi"><span>Operational Continuity</span><strong>{{ mission_kpis.operational_continuity }}</strong></div>
                <div class="kpi"><span>ServiceNow Trust</span><strong>{{ mission_kpis.service_now_trust }}</strong></div>
            </div>

            <div class="grid4">
                <div class="kpi"><span>Open Governance Gaps</span><strong>{{ mission_kpis.open_governance_gaps }}</strong></div>
                <div class="kpi"><span>Critical Alerts</span><strong>{{ mission_kpis.critical_alerts }}</strong></div>
                <div class="kpi"><span>Blast Radius</span><strong>{{ mission_kpis.blast_radius }}</strong></div>
                <div class="kpi"><span>Mission Status</span><strong>{{ mission_kpis.mission_status }}</strong></div>
            </div>

            <section class="mission-layout">
                <div class="panel">
                    <h2>1. Boardroom Signals</h2>
                    <table>
                        <tr><th>Signal</th><th>Source</th><th>Impact</th><th>Priority</th><th>Open</th></tr>
                        {% for s in boardroom_signals %}
                        <tr>
                            <td><b>{{ s.signal }}</b></td>
                            <td>{{ s.source }}</td>
                            <td>{{ s.impact }}</td>
                            <td><span class="pill {{ s.priority }}">{{ s.priority }}</span></td>
                            <td><a href="{{ s.route }}">Open</a></td>
                        </tr>
                        {% endfor %}
                    </table>
                </div>

                <div class="panel">
                    <h2>2. Mission Story</h2>
                    <ul>
                        {% for m in mission_story %}
                        <li>{{ m }}</li>
                        {% endfor %}
                    </ul>
                </div>
            </section>

            <section class="panel">
                <h2>3. Command Tiles</h2>
                <div class="tiles">
                    {% for t in command_tiles %}
                    <div class="tile">
                        <span class="pill {{ t.status }}">{{ t.status }}</span>
                        <h3>{{ t.title }}</h3>
                        <p>{{ t.summary }}</p>
                        <a href="{{ t.route }}">Open</a>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="panel">
                <h2>4. Executive Recommendations</h2>
                <table>
                    <tr><th>Priority</th><th>Recommendation</th><th>Expected Result</th></tr>
                    {% for r in executive_recommendations %}
                    <tr>
                        <td><span class="pill {{ r.priority }}">{{ r.priority }}</span></td>
                        <td><b>{{ r.recommendation }}</b></td>
                        <td>{{ r.expected_result }}</td>
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
        mission_kpis=mission_kpis,
        boardroom_signals=boardroom_signals,
        command_tiles=command_tiles,
        executive_recommendations=executive_recommendations,
        mission_story=mission_story
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "EXECUTIVE_MISSION_CONTROL_ACTIVE",
    '@app.route("/executive-mission-control")',
    "Executive Mission Control Dashboard",
    "Boardroom Signals",
    "Executive Recommendations"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Executive Mission Control added safely at /executive-mission-control")
