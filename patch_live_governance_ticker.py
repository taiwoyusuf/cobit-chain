from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "LIVE_GOVERNANCE_TICKER_ACTIVE"

if MARKER in text:
    print("Live Governance Ticker already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# LIVE_GOVERNANCE_TICKER_ACTIVE
# Safe additive route only.
# Adds /live-governance-ticker without modifying protected modules.
# Simulates real-time governance intelligence feed for demo use.
# ============================================================

@app.route("/live-governance-ticker")
def live_governance_ticker():
    ticker_kpis = {
        "current_confidence": "89%",
        "confidence_drift": "-3",
        "active_alerts": "6",
        "critical_alerts": "1",
        "evidence_gaps": "2",
        "overlap_warnings": "1",
        "audit_exposure": "MEDIUM",
        "ticker_mode": "Synthetic Live"
    }

    ticker_events = [
        {
            "time": "07:42",
            "severity": "HIGH",
            "source": "Evidence Integrity",
            "headline": "Audit trail export missing for SYN-INC-10052",
            "impact": "Audit readiness reduced by 6 points",
            "action": "Attach audit trail export before closure"
        },
        {
            "time": "07:39",
            "severity": "MEDIUM",
            "source": "Shift Overlap",
            "headline": "B-to-C incoming owner acknowledgement still pending",
            "impact": "Governance confidence reduced by 3 points",
            "action": "Require incoming technician acknowledgement"
        },
        {
            "time": "07:35",
            "severity": "MEDIUM",
            "source": "ServiceNow Overlay",
            "headline": "Ticket state is In Progress but governance trust state is Exception",
            "impact": "Workflow state and trust state are misaligned",
            "action": "Review ownership, evidence, and supervisor checkpoint"
        },
        {
            "time": "07:30",
            "severity": "LOW",
            "source": "Relationship Graph",
            "headline": "Ticket-to-equipment relationship confirmed",
            "impact": "Lineage strength remains stable",
            "action": "Continue monitoring"
        },
        {
            "time": "07:24",
            "severity": "MEDIUM",
            "source": "Blast Radius",
            "headline": "Evidence gap impacts Supervisor Review and Audit State nodes",
            "impact": "Blast radius elevated to HIGH",
            "action": "Execute containment plan"
        },
        {
            "time": "07:18",
            "severity": "LOW",
            "source": "Platform Health",
            "headline": "Protected route boundary preserved",
            "impact": "No protected module overwrite detected",
            "action": "No action required"
        },
    ]

    drift_history = [
        {"period": "T-5", "confidence": "94", "driver": "All lineage nodes connected"},
        {"period": "T-4", "confidence": "93", "driver": "Evidence pending"},
        {"period": "T-3", "confidence": "91", "driver": "B-to-C acknowledgement delayed"},
        {"period": "T-2", "confidence": "90", "driver": "Audit export still missing"},
        {"period": "T-1", "confidence": "89", "driver": "Blast radius elevated"},
        {"period": "Now", "confidence": "89", "driver": "Awaiting remediation"},
    ]

    recommended_actions = [
        {"priority": "P1", "action": "Attach missing audit trail export", "target": "SYN-INC-10052", "expected_recovery": "+5 confidence"},
        {"priority": "P1", "action": "Capture incoming owner acknowledgement", "target": "B-to-C transition", "expected_recovery": "+3 confidence"},
        {"priority": "P2", "action": "Complete supervisor review checkpoint", "target": "Review queue", "expected_recovery": "+4 confidence"},
        {"priority": "P2", "action": "Recalculate governance confidence", "target": "Confidence Engine", "expected_recovery": "Updated trust state"},
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Live Governance Ticker</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .top { background:#0f172a; color:white; padding:14px 24px; display:flex; justify-content:space-between; align-items:center; gap:18px; flex-wrap:wrap; position:sticky; top:0; z-index:10; }
            .brand { font-weight:900; font-size:18px; }
            .brand span { color:#38bdf8; }
            .nav { display:flex; gap:10px; flex-wrap:wrap; }
            .nav a { color:#dbeafe; text-decoration:none; font-size:12px; font-weight:800; padding:8px 10px; border-radius:999px; background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.12); }
            .nav a:hover { background:#2563eb; color:white; }
            .ticker-strip { background:#111827; color:white; overflow:hidden; white-space:nowrap; border-top:1px solid #334155; border-bottom:1px solid #334155; }
            .ticker-move { display:inline-block; padding:12px 0; animation: ticker 38s linear infinite; }
            .ticker-move span { margin-right:50px; font-weight:800; }
            @keyframes ticker { 0% { transform:translateX(100%); } 100% { transform:translateX(-100%); } }
            .hero { background:linear-gradient(135deg,#111827,#be123c); color:white; padding:36px 44px 78px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:40px; }
            .hero p { color:#ffe4e6; max-width:1120px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1320px; margin:-46px auto 40px; padding:0 24px; }
            .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            .kpi, .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            .kpi span { color:#64748b; font-weight:900; font-size:12px; text-transform:uppercase; letter-spacing:.07em; }
            .kpi strong { display:block; margin-top:9px; font-size:28px; }
            table { width:100%; border-collapse:collapse; }
            th { background:#ffe4e6; color:#9f1239; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .LOW { background:#dcfce7; color:#166534; }
            .MEDIUM { background:#fef3c7; color:#92400e; }
            .HIGH { background:#fee2e2; color:#991b1b; }
            .P1 { background:#fee2e2; color:#991b1b; }
            .P2 { background:#fef3c7; color:#92400e; }
            .note { background:#fff1f2; border:1px solid #fecdd3; color:#9f1239; padding:16px; border-radius:16px; margin-bottom:22px; }
            .drift { display:grid; grid-template-columns:repeat(6,1fr); gap:12px; }
            .drift-card { background:#f8fafc; border:1px solid #e2e8f0; border-radius:16px; padding:16px; }
            .drift-card b { display:block; font-size:22px; color:#be123c; margin-bottom:6px; }
            .drift-card span { color:#64748b; font-size:12px; font-weight:900; }
            @media(max-width:1000px){ .grid4{grid-template-columns:repeat(2,1fr);} .drift{grid-template-columns:repeat(3,1fr);} }
            @media(max-width:650px){ .grid4,.drift{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <div class="top">
            <div class="brand">COBIT-Chain™ <span>Live Governance Ticker</span></div>
            <nav class="nav">
                <a href="/enterprise-workspaces">Workspaces</a>
                <a href="/synthetic-enterprise-datasets">Datasets</a>
                <a href="/governance-relationship-graph">Graph</a>
                <a href="/governance-confidence-engine">Confidence</a>
                <a href="/audit-simulation-engine">Audit</a>
            </nav>
        </div>

        <div class="ticker-strip">
            <div class="ticker-move">
                {% for e in ticker_events %}
                    <span>[{{ e.severity }}] {{ e.source }} — {{ e.headline }} → {{ e.action }}</span>
                {% endfor %}
            </div>
        </div>

        <section class="hero">
            <h1>Live Governance Ticker™</h1>
            <p>
                A synthetic live intelligence feed that makes governance posture feel dynamic:
                confidence drift, evidence gaps, overlap warnings, ServiceNow exceptions, blast radius alerts,
                audit exposure, and remediation actions.
            </p>
            <span class="badge">SYNTHETIC LIVE FEED</span>
            <span class="badge">CONFIDENCE DRIFT</span>
            <span class="badge">AUDIT EXPOSURE</span>
            <span class="badge">REMEDIATION SIGNALS</span>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Executive meaning:</b> Instead of waiting for someone to open a report, the platform continuously surfaces
                governance drift and what action restores trust.
            </div>

            <div class="grid4">
                <div class="kpi"><span>Current Confidence</span><strong>{{ ticker_kpis.current_confidence }}</strong></div>
                <div class="kpi"><span>Confidence Drift</span><strong>{{ ticker_kpis.confidence_drift }}</strong></div>
                <div class="kpi"><span>Active Alerts</span><strong>{{ ticker_kpis.active_alerts }}</strong></div>
                <div class="kpi"><span>Critical Alerts</span><strong>{{ ticker_kpis.critical_alerts }}</strong></div>
            </div>

            <div class="grid4">
                <div class="kpi"><span>Evidence Gaps</span><strong>{{ ticker_kpis.evidence_gaps }}</strong></div>
                <div class="kpi"><span>Overlap Warnings</span><strong>{{ ticker_kpis.overlap_warnings }}</strong></div>
                <div class="kpi"><span>Audit Exposure</span><strong>{{ ticker_kpis.audit_exposure }}</strong></div>
                <div class="kpi"><span>Ticker Mode</span><strong>{{ ticker_kpis.ticker_mode }}</strong></div>
            </div>

            <section class="panel">
                <h2>1. Live Governance Events</h2>
                <table>
                    <tr><th>Time</th><th>Severity</th><th>Source</th><th>Headline</th><th>Impact</th><th>Recommended Action</th></tr>
                    {% for e in ticker_events %}
                    <tr>
                        <td><b>{{ e.time }}</b></td>
                        <td><span class="pill {{ e.severity }}">{{ e.severity }}</span></td>
                        <td>{{ e.source }}</td>
                        <td><b>{{ e.headline }}</b></td>
                        <td>{{ e.impact }}</td>
                        <td>{{ e.action }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>2. Confidence Drift Timeline</h2>
                <div class="drift">
                    {% for d in drift_history %}
                    <div class="drift-card">
                        <span>{{ d.period }}</span>
                        <b>{{ d.confidence }}%</b>
                        <p>{{ d.driver }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="panel">
                <h2>3. Recommended Recovery Actions</h2>
                <table>
                    <tr><th>Priority</th><th>Action</th><th>Target</th><th>Expected Recovery</th></tr>
                    {% for r in recommended_actions %}
                    <tr>
                        <td><span class="pill {{ r.priority }}">{{ r.priority }}</span></td>
                        <td><b>{{ r.action }}</b></td>
                        <td>{{ r.target }}</td>
                        <td>{{ r.expected_recovery }}</td>
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
        ticker_kpis=ticker_kpis,
        ticker_events=ticker_events,
        drift_history=drift_history,
        recommended_actions=recommended_actions
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "LIVE_GOVERNANCE_TICKER_ACTIVE",
    '@app.route("/live-governance-ticker")',
    "Live Governance Ticker",
    "Live Governance Events",
    "Confidence Drift Timeline"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Live Governance Ticker added safely at /live-governance-ticker")
