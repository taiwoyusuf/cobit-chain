from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_DIGITAL_COMMAND_CENTER_ACTIVE"

if MARKER in text:
    print("Governance Digital Command Center already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# GOVERNANCE_DIGITAL_COMMAND_CENTER_ACTIVE
# Safe additive route only.
# Adds /governance-digital-command-center without modifying protected modules.
# Unified boardroom-style command center for governance intelligence.
# ============================================================

@app.route("/governance-digital-command-center")
def governance_digital_command_center():

    command_kpis = {
        "mission_status": "WATCH",
        "governance_confidence": "89%",
        "audit_readiness": "84%",
        "predictive_72h": "77%",
        "active_alerts": "6",
        "critical_risk": "1",
        "blast_radius": "HIGH",
        "recovery_potential": "+28"
    }

    live_alerts = [
        {"severity": "HIGH", "message": "Missing audit trail export is limiting audit readiness.", "route": "/audit-simulation-engine"},
        {"severity": "MEDIUM", "message": "B-to-C shift acknowledgement remains pending.", "route": "/shift-overlap-intelligence"},
        {"severity": "MEDIUM", "message": "ServiceNow ticket state and governance trust state are misaligned.", "route": "/servicenow-governance-overlay"},
        {"severity": "HIGH", "message": "Blast radius remains elevated across evidence, review, and audit state.", "route": "/governance-blast-radius"},
    ]

    command_modules = [
        {"name": "Mission Control", "route": "/executive-mission-control", "signal": "Boardroom entry point", "status": "LIVE"},
        {"name": "AI Governance Copilot", "route": "/ai-governance-copilot", "signal": "Explains why trust changed", "status": "LIVE"},
        {"name": "Predictive Drift", "route": "/predictive-governance-drift", "signal": "Forecasts confidence degradation", "status": "LIVE"},
        {"name": "Recovery Simulator", "route": "/governance-recovery-simulator", "signal": "Models fastest trust restoration", "status": "LIVE"},
        {"name": "Scenario Simulator", "route": "/governance-scenario-simulator", "signal": "War-games audit and operational failures", "status": "LIVE"},
        {"name": "Relationship Graph", "route": "/governance-relationship-graph", "signal": "Visualizes trust dependencies", "status": "LIVE"},
        {"name": "Live Ticker", "route": "/live-governance-ticker", "signal": "Streams governance drift alerts", "status": "LIVE"},
        {"name": "Synthetic Datasets", "route": "/synthetic-enterprise-datasets", "signal": "Demo-safe operational telemetry", "status": "LIVE"},
    ]

    trust_heatmap = [
        {"domain": "Evidence Integrity", "score": "82%", "risk": "HIGH", "trend": "Declining"},
        {"domain": "Shift Continuity", "score": "87%", "risk": "MEDIUM", "trend": "Watch"},
        {"domain": "ServiceNow Trust", "score": "88%", "risk": "MEDIUM", "trend": "Stable"},
        {"domain": "Audit Readiness", "score": "84%", "risk": "MEDIUM", "trend": "Watch"},
        {"domain": "Lineage Strength", "score": "91%", "risk": "LOW", "trend": "Stable"},
        {"domain": "Recovery Potential", "score": "+28", "risk": "LOW", "trend": "Strong"},
    ]

    executive_actions = [
        {"priority": "P1", "action": "Close missing audit trail export", "impact": "Audit readiness +6, confidence +5"},
        {"priority": "P1", "action": "Capture incoming B-to-C owner acknowledgement", "impact": "Handoff integrity +3"},
        {"priority": "P2", "action": "Complete supervisor review checkpoint", "impact": "Closure defensibility +4"},
        {"priority": "P2", "action": "Run recovery simulator after remediation", "impact": "Mission status may move from WATCH to GOVERNED"},
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Governance Digital Command Center</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#07111f; color:#e5e7eb; }
            .shell { display:grid; grid-template-columns:280px 1fr; min-height:100vh; }
            .side { background:#020617; padding:24px; border-right:1px solid #1e293b; position:sticky; top:0; height:100vh; box-sizing:border-box; }
            .side h2 { margin:0 0 8px; color:white; }
            .side p { color:#94a3b8; font-size:13px; line-height:1.5; }
            .side a { display:block; color:#dbeafe; text-decoration:none; font-weight:800; padding:10px 12px; border-radius:12px; margin:8px 0; background:#0f172a; border:1px solid #1e293b; font-size:13px; }
            .side a:hover { background:#1d4ed8; color:white; }
            .main { padding:28px; }
            .hero { background:linear-gradient(135deg,#1e3a8a,#020617); border:1px solid #1e40af; border-radius:26px; padding:30px; margin-bottom:22px; box-shadow:0 18px 40px rgba(0,0,0,.35); }
            .hero h1 { margin:0 0 10px; font-size:38px; color:white; }
            .hero p { color:#bfdbfe; max-width:1100px; line-height:1.55; }
            .badge { display:inline-block; background:rgba(59,130,246,.18); border:1px solid rgba(147,197,253,.28); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:900; color:#dbeafe; }
            .kpi-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            .kpi { background:#0f172a; border:1px solid #1e293b; border-radius:20px; padding:20px; box-shadow:0 12px 30px rgba(0,0,0,.24); }
            .kpi span { display:block; color:#94a3b8; font-weight:900; font-size:12px; text-transform:uppercase; letter-spacing:.07em; }
            .kpi strong { display:block; color:white; margin-top:10px; font-size:28px; }
            .layout { display:grid; grid-template-columns:1.15fr .85fr; gap:20px; }
            .panel { background:#0f172a; border:1px solid #1e293b; border-radius:22px; padding:22px; box-shadow:0 12px 30px rgba(0,0,0,.24); margin-bottom:20px; }
            .panel h2 { margin-top:0; color:white; }
            table { width:100%; border-collapse:collapse; }
            th { background:#111827; color:#93c5fd; text-align:left; padding:12px; font-size:12px; }
            td { border-bottom:1px solid #1e293b; padding:12px; font-size:13px; color:#d1d5db; vertical-align:top; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .LIVE, .LOW { background:#064e3b; color:#bbf7d0; }
            .MEDIUM, .P2, .WATCH { background:#78350f; color:#fde68a; }
            .HIGH, .P1 { background:#7f1d1d; color:#fecaca; }
            .module-grid { display:grid; grid-template-columns:repeat(2,1fr); gap:14px; }
            .module { background:#111827; border:1px solid #334155; border-radius:18px; padding:16px; }
            .module h3 { margin:0 0 8px; color:white; }
            .module p { color:#94a3b8; font-size:13px; line-height:1.45; }
            .module a { display:inline-block; margin-top:8px; background:#2563eb; color:white; padding:9px 12px; border-radius:10px; text-decoration:none; font-weight:900; font-size:13px; }
            .alert { background:#111827; border-left:5px solid #f59e0b; border-radius:14px; padding:14px; margin-bottom:12px; }
            .alert.HIGH { border-left-color:#ef4444; }
            .alert.MEDIUM { border-left-color:#f59e0b; }
            .alert a { color:#93c5fd; font-weight:900; text-decoration:none; }
            @media(max-width:1200px){ .shell{grid-template-columns:1fr;} .side{height:auto; position:relative;} .layout{grid-template-columns:1fr;} .kpi-grid{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:700px){ .kpi-grid,.module-grid{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <div class="shell">
            <aside class="side">
                <h2>COBIT-Chain™</h2>
                <p>Governance Digital Command Center</p>
                <a href="/enterprise-workspaces">Enterprise Workspaces</a>
                <a href="/executive-mission-control">Mission Control</a>
                <a href="/ai-governance-copilot">AI Copilot</a>
                <a href="/predictive-governance-drift">Predictive Drift</a>
                <a href="/governance-recovery-simulator">Recovery Simulator</a>
                <a href="/governance-scenario-simulator">Scenario Simulator</a>
                <a href="/live-governance-ticker">Live Ticker</a>
                <a href="/platform-health">Platform Health</a>
            </aside>

            <main class="main">
                <section class="hero">
                    <h1>Governance Digital Command Center™</h1>
                    <p>
                        A boardroom-style operational theater view combining mission status, live governance alerts,
                        predictive drift, AI advisory, recovery simulation, scenario war-gaming, blast radius,
                        ServiceNow trust state, and audit readiness in one command interface.
                    </p>
                    <span class="badge">MISSION STATUS: {{ command_kpis.mission_status }}</span>
                    <span class="badge">BOARDROOM MODE</span>
                    <span class="badge">PREDICTIVE GOVERNANCE</span>
                    <span class="badge">SYNTHETIC LIVE DATA</span>
                </section>

                <section class="kpi-grid">
                    <div class="kpi"><span>Governance Confidence</span><strong>{{ command_kpis.governance_confidence }}</strong></div>
                    <div class="kpi"><span>Audit Readiness</span><strong>{{ command_kpis.audit_readiness }}</strong></div>
                    <div class="kpi"><span>Predictive 72h</span><strong>{{ command_kpis.predictive_72h }}</strong></div>
                    <div class="kpi"><span>Recovery Potential</span><strong>{{ command_kpis.recovery_potential }}</strong></div>
                    <div class="kpi"><span>Active Alerts</span><strong>{{ command_kpis.active_alerts }}</strong></div>
                    <div class="kpi"><span>Critical Risk</span><strong>{{ command_kpis.critical_risk }}</strong></div>
                    <div class="kpi"><span>Blast Radius</span><strong>{{ command_kpis.blast_radius }}</strong></div>
                    <div class="kpi"><span>Mission Status</span><strong>{{ command_kpis.mission_status }}</strong></div>
                </section>

                <div class="layout">
                    <div>
                        <section class="panel">
                            <h2>1. Command Modules</h2>
                            <div class="module-grid">
                                {% for m in command_modules %}
                                <div class="module">
                                    <span class="pill {{ m.status }}">{{ m.status }}</span>
                                    <h3>{{ m.name }}</h3>
                                    <p>{{ m.signal }}</p>
                                    <a href="{{ m.route }}">Open</a>
                                </div>
                                {% endfor %}
                            </div>
                        </section>

                        <section class="panel">
                            <h2>2. Trust Heatmap</h2>
                            <table>
                                <tr><th>Domain</th><th>Score</th><th>Risk</th><th>Trend</th></tr>
                                {% for h in trust_heatmap %}
                                <tr>
                                    <td><b>{{ h.domain }}</b></td>
                                    <td>{{ h.score }}</td>
                                    <td><span class="pill {{ h.risk }}">{{ h.risk }}</span></td>
                                    <td>{{ h.trend }}</td>
                                </tr>
                                {% endfor %}
                            </table>
                        </section>
                    </div>

                    <div>
                        <section class="panel">
                            <h2>3. Live Alerts</h2>
                            {% for a in live_alerts %}
                            <div class="alert {{ a.severity }}">
                                <span class="pill {{ a.severity }}">{{ a.severity }}</span>
                                <p>{{ a.message }}</p>
                                <a href="{{ a.route }}">Open related module</a>
                            </div>
                            {% endfor %}
                        </section>

                        <section class="panel">
                            <h2>4. Executive Actions</h2>
                            <table>
                                <tr><th>Priority</th><th>Action</th><th>Impact</th></tr>
                                {% for e in executive_actions %}
                                <tr>
                                    <td><span class="pill {{ e.priority }}">{{ e.priority }}</span></td>
                                    <td><b>{{ e.action }}</b></td>
                                    <td>{{ e.impact }}</td>
                                </tr>
                                {% endfor %}
                            </table>
                        </section>
                    </div>
                </div>
            </main>
        </div>
    </body>
    </html>
    """

    return render_template_string(
        html,
        command_kpis=command_kpis,
        live_alerts=live_alerts,
        command_modules=command_modules,
        trust_heatmap=trust_heatmap,
        executive_actions=executive_actions
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "GOVERNANCE_DIGITAL_COMMAND_CENTER_ACTIVE",
    '@app.route("/governance-digital-command-center")',
    "Governance Digital Command Center",
    "Command Modules",
    "Trust Heatmap"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Governance Digital Command Center added safely at /governance-digital-command-center")
