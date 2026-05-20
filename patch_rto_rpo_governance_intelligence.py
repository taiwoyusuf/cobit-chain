from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# RTO_RPO_GOVERNANCE_INTELLIGENCE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# RTO_RPO_GOVERNANCE_INTELLIGENCE_ACTIVE
@app.route("/rto-rpo-governance-intelligence")
def rto_rpo_governance_intelligence_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>RTO / RPO Governance Intelligence™ | COBIT-Chain™ / AssuranceLayer™</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #f4f7fb;
            color: #172033;
        }
        .shell {
            max-width: 1450px;
            margin: 0 auto;
            padding: 28px 22px 42px;
        }
        .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
            margin-bottom: 22px;
            flex-wrap: wrap;
        }
        .brand {
            font-size: 14px;
            font-weight: 700;
            color: #335caa;
            letter-spacing: .04em;
            text-transform: uppercase;
        }
        .nav-links {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .nav-links a {
            text-decoration: none;
            color: #163a72;
            background: #e8f0ff;
            padding: 9px 12px;
            border-radius: 999px;
            font-size: 13px;
            font-weight: 700;
        }
        .hero {
            background: linear-gradient(135deg, #111827 0%, #1d4ed8 44%, #7c2d12 100%);
            color: #fff;
            border-radius: 26px;
            padding: 28px;
            box-shadow: 0 16px 42px rgba(17, 24, 39, .22);
            margin-bottom: 20px;
        }
        .eyebrow {
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: .08em;
            opacity: .82;
            font-weight: 700;
            margin-bottom: 10px;
        }
        h1 {
            margin: 0 0 10px;
            font-size: 35px;
            line-height: 1.15;
        }
        .hero p {
            max-width: 1140px;
            margin: 0;
            line-height: 1.56;
            font-size: 16px;
            opacity: .95;
        }
        .hero-grid {
            display: grid;
            grid-template-columns: repeat(6, minmax(0, 1fr));
            gap: 12px;
            margin-top: 22px;
        }
        .hero-card {
            background: rgba(255,255,255,.12);
            border: 1px solid rgba(255,255,255,.18);
            border-radius: 18px;
            padding: 15px;
        }
        .hero-label {
            font-size: 12px;
            opacity: .80;
            text-transform: uppercase;
            letter-spacing: .06em;
            margin-bottom: 7px;
        }
        .hero-value {
            font-size: 20px;
            font-weight: 900;
        }
        .hero-note {
            font-size: 12px;
            opacity: .84;
            margin-top: 5px;
            line-height: 1.35;
        }
        .grid-2 {
            display: grid;
            grid-template-columns: 1.08fr .92fr;
            gap: 18px;
            margin-bottom: 18px;
        }
        .grid-3 {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 16px;
            margin-bottom: 18px;
        }
        .panel {
            background: #fff;
            border-radius: 22px;
            padding: 22px;
            box-shadow: 0 10px 28px rgba(22, 42, 74, .08);
        }
        .panel h2 {
            margin: 0 0 15px;
            font-size: 20px;
        }
        .panel p {
            line-height: 1.55;
            margin: 0 0 14px;
            color: #44536b;
        }
        .event-card {
            background: linear-gradient(180deg, #ffffff 0%, #eff6ff 100%);
            border: 1px solid #bfdbfe;
            border-radius: 22px;
            padding: 20px;
        }
        .event-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #1d4ed8;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .event-title {
            font-size: 24px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .event-note {
            color: #4c5b73;
            line-height: 1.55;
            margin-bottom: 16px;
        }
        .event-meta {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .meta-card {
            background: #f7faff;
            border: 1px solid #e2eaf7;
            border-radius: 16px;
            padding: 14px;
        }
        .meta-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 6px;
        }
        .meta-value {
            font-size: 15px;
            font-weight: 900;
        }
        .signal-grid {
            display: grid;
            gap: 12px;
        }
        .signal-row {
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .signal-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 14px;
            margin-bottom: 10px;
        }
        .signal-title {
            font-weight: 900;
        }
        .signal-value {
            font-size: 13px;
            font-weight: 900;
        }
        .bar {
            height: 12px;
            border-radius: 999px;
            background: #e5edf8;
            overflow: hidden;
        }
        .bar-fill {
            height: 100%;
            border-radius: 999px;
        }
        .bar-fill.green {
            background: linear-gradient(90deg, #16a34a 0%, #10b981 100%);
        }
        .bar-fill.amber {
            background: linear-gradient(90deg, #d97706 0%, #f59e0b 100%);
        }
        .bar-fill.red {
            background: linear-gradient(90deg, #dc2626 0%, #ef4444 100%);
        }
        .bar-fill.blue {
            background: linear-gradient(90deg, #2563eb 0%, #38bdf8 100%);
        }
        .signal-note {
            margin-top: 9px;
            color: #53637b;
            line-height: 1.45;
            font-size: 14px;
        }
        .workflow {
            display: grid;
            grid-template-columns: repeat(6, minmax(0, 1fr));
            gap: 12px;
        }
        .step {
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .step-number {
            width: 32px;
            height: 32px;
            border-radius: 11px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #1d4ed8;
            color: #fff;
            font-weight: 900;
            margin-bottom: 12px;
        }
        .step h3 {
            margin: 0 0 8px;
            font-size: 16px;
        }
        .step p {
            margin: 0;
            font-size: 14px;
        }
        .score-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .score-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .score-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .score-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .score-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .score-card.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .score-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .score-value {
            font-size: 28px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .score-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
        }
        .controls {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
            margin-bottom: 16px;
        }
        .filter-btn {
            border: 0;
            cursor: pointer;
            border-radius: 999px;
            padding: 9px 13px;
            font-size: 13px;
            font-weight: 800;
            background: #e8f0ff;
            color: #173f86;
        }
        .filter-btn.active {
            background: #173f86;
            color: #fff;
        }
        .search {
            margin-left: auto;
            min-width: 340px;
            border: 1px solid #d7e1f0;
            border-radius: 999px;
            padding: 10px 14px;
            font-size: 14px;
            outline: none;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            overflow: hidden;
            border-radius: 18px;
        }
        th, td {
            text-align: left;
            padding: 13px 12px;
            border-bottom: 1px solid #e8edf5;
            font-size: 14px;
            vertical-align: top;
        }
        th {
            background: #eff4fb;
            color: #31415b;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: .05em;
        }
        tr:last-child td { border-bottom: none; }
        .pill {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 800;
            white-space: nowrap;
        }
        .pill.green {
            background: #dcfce7;
            color: #166534;
        }
        .pill.amber {
            background: #fef3c7;
            color: #92400e;
        }
        .pill.red {
            background: #fee2e2;
            color: #991b1b;
        }
        .pill.blue {
            background: #dbeafe;
            color: #1d4ed8;
        }
        .pill.indigo {
            background: #e0e7ff;
            color: #3730a3;
        }
        .timeline-grid {
            display: grid;
            gap: 12px;
        }
        .timeline-item {
            display: grid;
            grid-template-columns: 88px 1fr auto;
            gap: 14px;
            align-items: start;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .timeline-time {
            border-radius: 14px;
            background: #1d4ed8;
            color: #fff;
            padding: 10px;
            text-align: center;
            font-weight: 900;
        }
        .timeline-title {
            font-weight: 900;
            margin-bottom: 5px;
        }
        .timeline-note {
            color: #53637b;
            line-height: 1.45;
            font-size: 14px;
        }
        .timeline-state {
            font-size: 12px;
            color: #64748b;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: .05em;
            text-align: right;
        }
        .forecast-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .forecast-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .forecast-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .forecast-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .forecast-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .forecast-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .forecast-value {
            font-size: 25px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .forecast-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
        }
        .builder {
            display: grid;
            grid-template-columns: 1fr .92fr;
            gap: 18px;
        }
        .builder-grid {
            display: grid;
            gap: 12px;
        }
        .builder-row {
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .builder-row label {
            display: block;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .builder-row select {
            width: 100%;
            border: 1px solid #d7e1f0;
            border-radius: 14px;
            padding: 11px 12px;
            font-size: 14px;
            background: #fff;
            color: #172033;
            outline: none;
        }
        .builder-result {
            border-radius: 22px;
            padding: 22px;
            background: #fff7ed;
            border: 1px solid #fed7aa;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        .builder-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .builder-title {
            font-size: 28px;
            font-weight: 900;
            color: #9a3412;
            margin-bottom: 10px;
        }
        .builder-verdict {
            border-radius: 18px;
            background: rgba(255,255,255,.76);
            padding: 16px;
            font-weight: 800;
            line-height: 1.5;
            margin-bottom: 12px;
        }
        .builder-meta {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 10px;
            margin-bottom: 12px;
        }
        .builder-mini {
            background: rgba(255,255,255,.76);
            border-radius: 14px;
            padding: 12px;
        }
        .builder-mini-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 5px;
        }
        .builder-mini-value {
            font-weight: 900;
        }
        .builder-note {
            color: #4d5b73;
            line-height: 1.55;
        }
        .inspector {
            display: grid;
            grid-template-columns: 1fr .9fr;
            gap: 18px;
        }
        .inspector-list {
            display: grid;
            gap: 12px;
        }
        .inspect-btn {
            width: 100%;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
            border-radius: 18px;
            padding: 16px;
            text-align: left;
            cursor: pointer;
        }
        .inspect-btn:hover {
            background: #eff6ff;
        }
        .inspect-btn.active {
            border-color: #93c5fd;
            background: #eff6ff;
        }
        .inspect-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 6px;
        }
        .inspect-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 5px;
            color: #172033;
        }
        .inspect-note {
            color: #53637b;
            line-height: 1.45;
            font-size: 14px;
        }
        .inspector-card {
            border-radius: 22px;
            padding: 22px;
            background: #eff6ff;
            border: 1px solid #93c5fd;
        }
        .inspector-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .inspector-title {
            font-size: 27px;
            font-weight: 900;
            color: #1d4ed8;
            margin-bottom: 10px;
        }
        .inspector-meta {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 10px;
            margin-bottom: 14px;
        }
        .inspector-mini {
            background: rgba(255,255,255,.74);
            border-radius: 14px;
            padding: 12px;
        }
        .inspector-mini-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 5px;
        }
        .inspector-mini-value {
            font-weight: 900;
        }
        .inspector-verdict {
            background: rgba(255,255,255,.78);
            border-radius: 18px;
            padding: 16px;
            font-weight: 800;
            line-height: 1.5;
            margin-bottom: 12px;
        }
        .inspector-note {
            color: #4d5b73;
            line-height: 1.55;
        }
        .action-console {
            display: grid;
            grid-template-columns: 1fr .82fr;
            gap: 18px;
        }
        .action-list {
            display: grid;
            gap: 12px;
        }
        .action-item {
            display: flex;
            justify-content: space-between;
            gap: 14px;
            align-items: center;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .action-item h3 {
            margin: 0 0 5px;
            font-size: 16px;
        }
        .action-item p {
            margin: 0;
            font-size: 14px;
        }
        .action-btn {
            border: 0;
            cursor: pointer;
            border-radius: 999px;
            padding: 10px 14px;
            background: #1d4ed8;
            color: #fff;
            font-weight: 900;
            font-size: 13px;
            white-space: nowrap;
        }
        .console-result {
            border-radius: 22px;
            padding: 22px;
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        .console-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .console-title {
            font-size: 28px;
            font-weight: 900;
            color: #1d4ed8;
            margin-bottom: 10px;
        }
        .console-note {
            color: #4d5b73;
            line-height: 1.55;
        }
        .maturity-card {
            border-left: 5px solid #1d4ed8;
            background: #eff6ff;
            border-radius: 18px;
            padding: 17px;
        }
        .maturity-card h3 {
            margin: 0 0 8px;
            font-size: 16px;
        }
        .maturity-card p {
            margin: 0;
            font-size: 14px;
        }
        .footer-note {
            margin-top: 18px;
            color: #5c6a80;
            font-size: 13px;
            line-height: 1.5;
        }
        @media (max-width: 1260px) {
            .hero-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .grid-2,
            .grid-3,
            .builder,
            .inspector,
            .action-console {
                grid-template-columns: 1fr;
            }
            .workflow {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .score-grid,
            .forecast-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .workflow,
            .score-grid,
            .forecast-grid,
            .event-meta,
            .builder-meta,
            .inspector-meta {
                grid-template-columns: 1fr;
            }
            .search {
                margin-left: 0;
                width: 100%;
                min-width: 0;
            }
            .timeline-item {
                grid-template-columns: 1fr;
            }
            .timeline-state {
                text-align: left;
            }
            .action-item {
                flex-direction: column;
                align-items: flex-start;
            }
            h1 {
                font-size: 28px;
            }
        }
    </style>
</head>
<body>
    <div class="shell">
        <div class="topbar">
            <div class="brand">COBIT-Chain™ / AssuranceLayer™</div>
            <div class="nav-links">
                <a href="/dr-activation-intelligence">DR Activation</a>
                <a href="/predictive-governance-drift">Predictive Drift</a>
                <a href="/governance-decision-engine">Decision Engine</a>
                <a href="/executive-mission-control">Mission Control</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Recovery Threshold Intelligence Layer</div>
            <h1>RTO / RPO Governance Intelligence™</h1>
            <p>
                The live threshold monitor for recovery governance. This module compares actual downtime and estimated
                recoverable data against each system’s defined RTO and RPO, shows how close the enterprise is to escalation,
                forecasts threshold breach, and converts technical recovery drift into governance consequence.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Systems Monitored</div>
                    <div class="hero-value">15</div>
                    <div class="hero-note">Across RC2–RC5</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Safe</div>
                    <div class="hero-value">8</div>
                    <div class="hero-note">Within both thresholds</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">At Risk</div>
                    <div class="hero-value">4</div>
                    <div class="hero-note">Approaching breach</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Breached</div>
                    <div class="hero-value">3</div>
                    <div class="hero-note">Escalation required</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Current Hotspot</div>
                    <div class="hero-value">ERP</div>
                    <div class="hero-note">RTO + RPO failure</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Governance Posture</div>
                    <div class="hero-value">Critical</div>
                    <div class="hero-note">Decision action needed</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Current Threshold Event</h2>
                <div class="event-card">
                    <div class="event-kicker">Threshold Assessment</div>
                    <div class="event-title">ERP / Finance & Supply Chain</div>
                    <div class="event-note">
                        The system has crossed both recovery dimensions: actual downtime is beyond the acceptable RTO window,
                        and estimated recoverable data is below the required RPO target. This is no longer merely a technical
                        restore problem; it is a governance escalation condition.
                    </div>

                    <div class="event-meta">
                        <div class="meta-card">
                            <div class="meta-label">Risk Category</div>
                            <div class="meta-value">RC5</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">RTO Target</div>
                            <div class="meta-value">24–48h</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">RPO Target</div>
                            <div class="meta-value">≥ 99.9%</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Decision</div>
                            <div class="meta-value">Escalate / Hold</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Live Threshold Signals</h2>
                <div class="signal-grid">
                    <div class="signal-row">
                        <div class="signal-top">
                            <div class="signal-title">RTO Consumption</div>
                            <div class="signal-value">106%</div>
                        </div>
                        <div class="bar"><div class="bar-fill red" style="width: 100%;"></div></div>
                        <div class="signal-note">51 hours elapsed against a 48-hour upper recovery boundary.</div>
                    </div>
                    <div class="signal-row">
                        <div class="signal-top">
                            <div class="signal-title">RPO Preservation</div>
                            <div class="signal-value">99.7%</div>
                        </div>
                        <div class="bar"><div class="bar-fill red" style="width: 72%;"></div></div>
                        <div class="signal-note">Estimated recoverable data remains below the 99.9% expectation.</div>
                    </div>
                    <div class="signal-row">
                        <div class="signal-top">
                            <div class="signal-title">Escalation Drift</div>
                            <div class="signal-value">Critical</div>
                        </div>
                        <div class="bar"><div class="bar-fill amber" style="width: 88%;"></div></div>
                        <div class="signal-note">Threshold failure is already affecting governance posture and restart decisioning.</div>
                    </div>
                    <div class="signal-row">
                        <div class="signal-top">
                            <div class="signal-title">Recovery Confidence</div>
                            <div class="signal-value">41%</div>
                        </div>
                        <div class="bar"><div class="bar-fill blue" style="width: 41%;"></div></div>
                        <div class="signal-note">Technical restoration remains incomplete until data reconciliation and QA verification occur.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Threshold Intelligence Workflow</h2>
            <div class="workflow">
                <div class="step">
                    <div class="step-number">1</div>
                    <h3>Read Target</h3>
                    <p>Load system-specific RTO and RPO expectations.</p>
                </div>
                <div class="step">
                    <div class="step-number">2</div>
                    <h3>Measure Reality</h3>
                    <p>Compare elapsed downtime and recoverable data to the approved targets.</p>
                </div>
                <div class="step">
                    <div class="step-number">3</div>
                    <h3>Classify State</h3>
                    <p>Mark safe, at-risk, RTO breach, RPO breach, or combined failure.</p>
                </div>
                <div class="step">
                    <div class="step-number">4</div>
                    <h3>Forecast Drift</h3>
                    <p>Estimate whether the event will cross threshold if the current trend continues.</p>
                </div>
                <div class="step">
                    <div class="step-number">5</div>
                    <h3>Translate Impact</h3>
                    <p>Convert technical drift into GMP, release, and governance consequence.</p>
                </div>
                <div class="step">
                    <div class="step-number">6</div>
                    <h3>Recommend Action</h3>
                    <p>Escalate, hold, accelerate, or continue standard recovery.</p>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Recovery Threshold Portfolio</h2>
            <p>
                The portfolio distinguishes between systems that are safe, drifting, and already forcing governance action.
            </p>

            <div class="score-grid">
                <div class="score-card green">
                    <div class="score-label">Within Threshold</div>
                    <div class="score-value">8</div>
                    <div class="score-note">Systems operating inside both RTO and RPO tolerance.</div>
                </div>
                <div class="score-card amber">
                    <div class="score-label">Approaching RTO</div>
                    <div class="score-value">2</div>
                    <div class="score-note">Recovery time is nearing breach even before data loss is considered.</div>
                </div>
                <div class="score-card amber">
                    <div class="score-label">Approaching RPO</div>
                    <div class="score-value">2</div>
                    <div class="score-note">Data-recovery quality is weakening before formal breach.</div>
                </div>
                <div class="score-card red">
                    <div class="score-label">Combined Failure</div>
                    <div class="score-value">3</div>
                    <div class="score-note">Both time and data conditions now require governance escalation.</div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>RTO / RPO System Register</h2>
            <p>
                Each system is scored against its recovery target, current actuals, and recommended governance action.
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Systems</button>
                <button class="filter-btn" data-filter="safe">Safe</button>
                <button class="filter-btn" data-filter="atrisk">At Risk</button>
                <button class="filter-btn" data-filter="breached">Breached</button>
                <input id="searchInput" class="search" type="text" placeholder="Search system, RC class, RTO, RPO, or governance state...">
            </div>

            <table id="thresholdTable">
                <thead>
                    <tr>
                        <th>System</th>
                        <th>RC</th>
                        <th>RTO</th>
                        <th>RPO Target</th>
                        <th>Actual Downtime</th>
                        <th>Estimated Recovery</th>
                        <th>Threshold State</th>
                        <th>Governance Action</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-state="breached" data-search="erp finance supply chain rc5 24-48 99.9 51 99.7 breached escalate">
                        <td>ERP / Finance & Supply Chain</td>
                        <td><span class="pill red">RC5</span></td>
                        <td>24–48h</td>
                        <td>≥ 99.9%</td>
                        <td>51h</td>
                        <td>99.7%</td>
                        <td><span class="pill red">Combined Failure</span></td>
                        <td>Escalate to DR / Hold restart</td>
                    </tr>
                    <tr data-state="atrisk" data-search="chromatography data system rc5 24-48 99.8 42 99.8 at risk monitor">
                        <td>Chromatography Data System</td>
                        <td><span class="pill red">RC5</span></td>
                        <td>24–48h</td>
                        <td>≥ 99.8%</td>
                        <td>42h</td>
                        <td>99.8%</td>
                        <td><span class="pill amber">Approaching RTO</span></td>
                        <td>Accelerate recovery</td>
                    </tr>
                    <tr data-state="breached" data-search="continuous environmental monitoring rc5 24-48 99.9 37 99.6 breached rpo">
                        <td>Continuous Environmental Monitoring</td>
                        <td><span class="pill red">RC5</span></td>
                        <td>24–48h</td>
                        <td>≥ 99.9%</td>
                        <td>37h</td>
                        <td>99.6%</td>
                        <td><span class="pill red">RPO Breach</span></td>
                        <td>QA assessment / escalate</td>
                    </tr>
                    <tr data-state="safe" data-search="environmental monitoring rc4 24-48 95 18 97.5 safe">
                        <td>Environmental Monitoring</td>
                        <td><span class="pill amber">RC4</span></td>
                        <td>24–48h</td>
                        <td>≥ 95%</td>
                        <td>18h</td>
                        <td>97.5%</td>
                        <td><span class="pill green">Safe</span></td>
                        <td>Continue recovery</td>
                    </tr>
                    <tr data-state="atrisk" data-search="asset calibration management rc3 24-48 95 44 95.2 at risk">
                        <td>Asset & Calibration Management</td>
                        <td><span class="pill blue">RC3</span></td>
                        <td>24–48h</td>
                        <td>≥ 95%</td>
                        <td>44h</td>
                        <td>95.2%</td>
                        <td><span class="pill amber">Approaching RTO</span></td>
                        <td>Prepare escalation</td>
                    </tr>
                    <tr data-state="safe" data-search="weighing instruments rc2 24-48 95 10 99.0 safe">
                        <td>Weighing Instruments</td>
                        <td><span class="pill indigo">RC2</span></td>
                        <td>24–48h</td>
                        <td>≥ 95%</td>
                        <td>10h</td>
                        <td>99.0%</td>
                        <td><span class="pill green">Safe</span></td>
                        <td>Standard response</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Escalation Timeline</h2>
                <div class="timeline-grid">
                    <div class="timeline-item">
                        <div class="timeline-time">T+12h</div>
                        <div>
                            <div class="timeline-title">ERP restore still within tolerance</div>
                            <div class="timeline-note">
                                Standard response remains acceptable; no threshold breach yet.
                            </div>
                        </div>
                        <div class="timeline-state">Monitor</div>
                    </div>
                    <div class="timeline-item">
                        <div class="timeline-time">T+36h</div>
                        <div>
                            <div class="timeline-title">Recovery drift becomes visible</div>
                            <div class="timeline-note">
                                Data-recovery confidence begins weakening; escalation watch opens.
                            </div>
                        </div>
                        <div class="timeline-state">At Risk</div>
                    </div>
                    <div class="timeline-item">
                        <div class="timeline-time">T+48h</div>
                        <div>
                            <div class="timeline-title">RTO upper boundary reached</div>
                            <div class="timeline-note">
                                Any further delay requires formal governance escalation.
                            </div>
                        </div>
                        <div class="timeline-state">Threshold</div>
                    </div>
                    <div class="timeline-item">
                        <div class="timeline-time">T+51h</div>
                        <div>
                            <div class="timeline-title">Combined RTO / RPO failure confirmed</div>
                            <div class="timeline-note">
                                Full DR posture recommended; GMP restart should remain blocked.
                            </div>
                        </div>
                        <div class="timeline-state">Escalate</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Forward-Looking Forecast</h2>
                <div class="forecast-grid">
                    <div class="forecast-card red">
                        <div class="forecast-title">ERP</div>
                        <div class="forecast-value">Already breached</div>
                        <div class="forecast-note">Combined time and data-loss failure.</div>
                    </div>
                    <div class="forecast-card amber">
                        <div class="forecast-title">CDS</div>
                        <div class="forecast-value">6h to RTO edge</div>
                        <div class="forecast-note">Needs acceleration before governance posture worsens.</div>
                    </div>
                    <div class="forecast-card red">
                        <div class="forecast-title">CEM</div>
                        <div class="forecast-value">RPO below target</div>
                        <div class="forecast-note">Data quality issue requires QA attention.</div>
                    </div>
                    <div class="forecast-card green">
                        <div class="forecast-title">Airborne EM</div>
                        <div class="forecast-value">Stable</div>
                        <div class="forecast-note">Current recovery posture remains acceptable.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Interactive Threshold Engine</h2>
            <p>
                This simulation shows how the same recovery event changes governance posture when time, recoverable data, and system class move.
            </p>

            <div class="builder">
                <div class="builder-grid">
                    <div class="builder-row">
                        <label for="systemSelect">System Type</label>
                        <select id="systemSelect">
                            <option value="erp">ERP / Finance & Supply Chain — RC5</option>
                            <option value="cds">Chromatography Data System — RC5</option>
                            <option value="em">Environmental Monitoring — RC4</option>
                            <option value="weighing">Weighing Instruments — RC2</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label for="downtimeSelect">Actual Downtime</label>
                        <select id="downtimeSelect">
                            <option value="12">12 hours</option>
                            <option value="36">36 hours</option>
                            <option value="44">44 hours</option>
                            <option value="51" selected>51 hours</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label for="recoverySelect">Estimated Recoverable Data</label>
                        <select id="recoverySelect">
                            <option value="99.95">99.95%</option>
                            <option value="99.90">99.90%</option>
                            <option value="99.80">99.80%</option>
                            <option value="99.70" selected>99.70%</option>
                            <option value="94.00">94.00%</option>
                        </select>
                    </div>
                </div>

                <div class="builder-result">
                    <div class="builder-label">Threshold Verdict</div>
                    <div id="builderTitle" class="builder-title">Combined Threshold Failure</div>
                    <div id="builderVerdict" class="builder-verdict">
                        The system has breached both recovery time and recovery point expectations. Governance escalation is required.
                    </div>
                    <div class="builder-meta">
                        <div class="builder-mini">
                            <div class="builder-mini-label">RTO State</div>
                            <div id="builderRto" class="builder-mini-value">Breached</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">RPO State</div>
                            <div id="builderRpo" class="builder-mini-value">Breached</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Decision</div>
                            <div id="builderDecision" class="builder-mini-value">Escalate</div>
                        </div>
                    </div>
                    <div id="builderNote" class="builder-note">
                        Once both thresholds fail on a high-risk system, the platform should stop describing the event as ordinary recovery.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Threshold Scenario Inspector</h2>
            <p>
                Select a scenario to inspect the specific governance meaning of RTO drift, RPO drift, or combined failure.
            </p>

            <div class="inspector">
                <div class="inspector-list">
                    <button class="inspect-btn active" data-scenario="combined">
                        <div class="inspect-kicker">Scenario 01</div>
                        <div class="inspect-title">Combined threshold failure</div>
                        <div class="inspect-note">ERP breaches both time and data tolerances.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="rto">
                        <div class="inspect-kicker">Scenario 02</div>
                        <div class="inspect-title">RTO drift only</div>
                        <div class="inspect-note">CDS approaches time threshold while data remains protected.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="rpo">
                        <div class="inspect-kicker">Scenario 03</div>
                        <div class="inspect-title">RPO breach only</div>
                        <div class="inspect-note">Continuous EM data quality falls below target.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="safe">
                        <div class="inspect-kicker">Scenario 04</div>
                        <div class="inspect-title">Within threshold</div>
                        <div class="inspect-note">Airborne EM remains safely recoverable.</div>
                    </button>
                </div>

                <div class="inspector-card">
                    <div class="inspector-label">Selected Scenario</div>
                    <div id="inspectorTitle" class="inspector-title">Combined threshold failure</div>
                    <div class="inspector-meta">
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">System</div>
                            <div id="inspectorSystem" class="inspector-mini-value">ERP / RC5</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">RTO State</div>
                            <div id="inspectorRto" class="inspector-mini-value">Breached</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">RPO State</div>
                            <div id="inspectorRpo" class="inspector-mini-value">Breached</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Decision</div>
                            <div id="inspectorDecision" class="inspector-mini-value">Escalate</div>
                        </div>
                    </div>
                    <div id="inspectorVerdict" class="inspector-verdict">
                        Both recovery time and data preservation have failed. The event now demands DR-level governance, not standard incident handling.
                    </div>
                    <div id="inspectorNote" class="inspector-note">
                        This is the clearest case for mission-control escalation, QA engagement, and restart hold.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Threshold Action Console</h2>
            <p>
                The intelligence layer turns threshold signals into action instead of leaving them as dashboard metrics.
            </p>

            <div class="action-console">
                <div class="action-list">
                    <div class="action-item">
                        <div>
                            <h3>Escalate ERP threshold failure</h3>
                            <p>Send combined RTO / RPO breach into the Decision Engine and Mission Control.</p>
                        </div>
                        <button class="action-btn" data-action="escalate">Escalate</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Accelerate CDS recovery</h3>
                            <p>Trigger pre-breach intervention before the system crosses its time boundary.</p>
                        </div>
                        <button class="action-btn" data-action="accelerate">Accelerate</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Open QA review for CEM</h3>
                            <p>Route RPO degradation for integrity verification and GMP impact assessment.</p>
                        </div>
                        <button class="action-btn" data-action="qa">Open</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Hold restart decision</h3>
                            <p>Block operational restart until threshold failure is resolved and proven.</p>
                        </div>
                        <button class="action-btn" data-action="hold">Hold</button>
                    </div>
                </div>

                <div id="consoleResult" class="console-result">
                    <div class="console-label">Threshold Outcome</div>
                    <div id="consoleTitle" class="console-title">Awaiting Action</div>
                    <div id="consoleNote" class="console-note">
                        Select an action to see how threshold intelligence becomes governance action.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>DR Activation Intelligence</h3>
                <p>
                    Decides whether the event has crossed into formal disaster recovery.
                </p>
            </div>
            <div class="maturity-card">
                <h3>RTO / RPO Intelligence</h3>
                <p>
                    Explains the threshold mechanics, drift, and consequence behind that decision.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    COBIT-Chain™ now converts recovery metrics into decision-ready governance posture.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by RTO / RPO Governance Intelligence</h2>
            <p>
                DR Activation Intelligence™ answers: <strong>“Has the event crossed into DR?”</strong>
            </p>
            <p>
                RTO / RPO Governance Intelligence™ answers:
                <strong>“Exactly which recovery thresholds are safe, drifting, or already breached — and what does that mean for governance action?”</strong>
            </p>
            <p>
                That creates the second layer of the recovery-governance branch. The platform can now move from simple activation
                into recovery threshold monitoring, breach forecasting, and consequence-driven escalation.
            </p>
            <div class="footer-note">
                DR branch: DR Activation Intelligence™ → RTO / RPO Governance Intelligence™ →
                future Recovery Dependency Validation™ → DR Evidence Passport™ → GMP Restart Gate™ →
                Recovery Governance Command Center™ → DR Recovery Certificate™.
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#thresholdTable tbody tr");
        const searchInput = document.getElementById("searchInput");
        let activeFilter = "all";

        function applyFilters() {
            const query = searchInput.value.toLowerCase().trim();

            rows.forEach(row => {
                const state = row.dataset.state;
                const searchable = row.dataset.search;
                const matchesFilter = activeFilter === "all" || state === activeFilter;
                const matchesSearch = searchable.includes(query);
                row.style.display = matchesFilter && matchesSearch ? "" : "none";
            });
        }

        buttons.forEach(button => {
            button.addEventListener("click", () => {
                buttons.forEach(btn => btn.classList.remove("active"));
                button.classList.add("active");
                activeFilter = button.dataset.filter;
                applyFilters();
            });
        });

        searchInput.addEventListener("input", applyFilters);

        const systemSelect = document.getElementById("systemSelect");
        const downtimeSelect = document.getElementById("downtimeSelect");
        const recoverySelect = document.getElementById("recoverySelect");
        const builderTitle = document.getElementById("builderTitle");
        const builderVerdict = document.getElementById("builderVerdict");
        const builderRto = document.getElementById("builderRto");
        const builderRpo = document.getElementById("builderRpo");
        const builderDecision = document.getElementById("builderDecision");
        const builderNote = document.getElementById("builderNote");

        const profiles = {
            erp: { label: "ERP / RC5", rpo: 99.9 },
            cds: { label: "CDS / RC5", rpo: 99.8 },
            em: { label: "Environmental Monitoring / RC4", rpo: 95.0 },
            weighing: { label: "Weighing Instruments / RC2", rpo: 95.0 }
        };

        function updateBuilder() {
            const profile = profiles[systemSelect.value];
            const downtime = Number(downtimeSelect.value);
            const recovery = Number(recoverySelect.value);

            const rtoState = downtime > 48 ? "Breached" : downtime >= 42 ? "At Risk" : "Safe";
            const rpoState = recovery < profile.rpo ? "Breached" : recovery === profile.rpo ? "At Threshold" : "Safe";

            builderRto.textContent = rtoState;
            builderRpo.textContent = rpoState;

            if (rtoState === "Breached" && rpoState === "Breached") {
                builderTitle.textContent = "Combined Threshold Failure";
                builderVerdict.textContent = "The system has breached both recovery time and recovery point expectations. Governance escalation is required.";
                builderDecision.textContent = "Escalate";
                builderNote.textContent = "Once both thresholds fail on a high-risk system, the platform should stop describing the event as ordinary recovery.";
            } else if (rtoState === "Breached" || rpoState === "Breached") {
                builderTitle.textContent = "Single Threshold Breach";
                builderVerdict.textContent = "One recovery dimension has failed. Formal review and escalation are required before restart confidence can be restored.";
                builderDecision.textContent = "Review / escalate";
                builderNote.textContent = "A single RTO or RPO failure can still be enough to change governance posture materially.";
            } else if (rtoState === "At Risk" || rpoState === "At Threshold") {
                builderTitle.textContent = "Threshold Drift";
                builderVerdict.textContent = "The system is not yet in formal breach, but it is approaching a governance boundary and should be actively managed.";
                builderDecision.textContent = "Intervene";
                builderNote.textContent = "The value of intelligence is acting before a threshold becomes an audit or restart problem.";
            } else {
                builderTitle.textContent = "Within Threshold";
                builderVerdict.textContent = "Both recovery time and recoverable data remain within approved tolerance.";
                builderDecision.textContent = "Continue";
                builderNote.textContent = "Standard recovery may continue while both dimensions remain safe.";
            }
        }

        [systemSelect, downtimeSelect, recoverySelect].forEach(element => {
            element.addEventListener("change", updateBuilder);
        });

        updateBuilder();

        const inspectButtons = document.querySelectorAll(".inspect-btn");
        const inspectorTitle = document.getElementById("inspectorTitle");
        const inspectorSystem = document.getElementById("inspectorSystem");
        const inspectorRto = document.getElementById("inspectorRto");
        const inspectorRpo = document.getElementById("inspectorRpo");
        const inspectorDecision = document.getElementById("inspectorDecision");
        const inspectorVerdict = document.getElementById("inspectorVerdict");
        const inspectorNote = document.getElementById("inspectorNote");

        const scenarios = {
            combined: {
                title: "Combined threshold failure",
                system: "ERP / RC5",
                rto: "Breached",
                rpo: "Breached",
                decision: "Escalate",
                verdict: "Both recovery time and data preservation have failed. The event now demands DR-level governance, not standard incident handling.",
                note: "This is the clearest case for mission-control escalation, QA engagement, and restart hold."
            },
            rto: {
                title: "RTO drift only",
                system: "CDS / RC5",
                rto: "At Risk",
                rpo: "Safe",
                decision: "Intervene",
                verdict: "The system still protects data adequately, but time-to-recovery is moving toward breach.",
                note: "The right governance move is early acceleration before a preventable time failure becomes a formal DR issue."
            },
            rpo: {
                title: "RPO breach only",
                system: "Continuous EM / RC5",
                rto: "Safe",
                rpo: "Breached",
                decision: "QA review",
                verdict: "Recovery speed may look acceptable, but data integrity posture has already failed the approved expectation.",
                note: "This is exactly why time alone cannot define recovery success in a GMP environment."
            },
            safe: {
                title: "Within threshold",
                system: "Airborne EM / RC4",
                rto: "Safe",
                rpo: "Safe",
                decision: "Continue",
                verdict: "The system remains within approved recovery tolerance across both dimensions.",
                note: "The platform should prevent overreaction as well as underreaction."
            }
        };

        inspectButtons.forEach(button => {
            button.addEventListener("click", () => {
                inspectButtons.forEach(btn => btn.classList.remove("active"));
                button.classList.add("active");

                const item = scenarios[button.dataset.scenario];
                inspectorTitle.textContent = item.title;
                inspectorSystem.textContent = item.system;
                inspectorRto.textContent = item.rto;
                inspectorRpo.textContent = item.rpo;
                inspectorDecision.textContent = item.decision;
                inspectorVerdict.textContent = item.verdict;
                inspectorNote.textContent = item.note;
            });
        });

        const actionButtons = document.querySelectorAll(".action-btn");
        const consoleResult = document.getElementById("consoleResult");
        const consoleTitle = document.getElementById("consoleTitle");
        const consoleNote = document.getElementById("consoleNote");

        const outcomes = {
            escalate: {
                title: "ERP Escalation Routed",
                note: "The combined threshold failure has been sent to the Decision Engine and Executive Mission Control."
            },
            accelerate: {
                title: "CDS Recovery Accelerated",
                note: "A pre-breach intervention has been opened before the time threshold is crossed."
            },
            qa: {
                title: "QA Review Opened",
                note: "Continuous Environmental Monitoring has been routed for integrity verification because RPO is below target."
            },
            hold: {
                title: "Restart Held",
                note: "Restart remains blocked until threshold failure is resolved and the recovery posture is proven."
            }
        };

        actionButtons.forEach(button => {
            button.addEventListener("click", () => {
                const outcome = outcomes[button.dataset.action];
                consoleTitle.textContent = outcome.title;
                consoleNote.textContent = outcome.note;
                consoleResult.style.background = "#ecfdf5";
                consoleResult.style.borderColor = "#a7f3d0";
                consoleTitle.style.color = "#166534";
            });
        });
    </script>
</body>
</html>
    """)
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: RTO_RPO_GOVERNANCE_INTELLIGENCE_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/rto-rpo-governance-intelligence")',
        "RTO / RPO Governance Intelligence™",
        "RTO / RPO System Register",
        "Interactive Threshold Engine",
        "Threshold Scenario Inspector",
        "Threshold Action Console",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /rto-rpo-governance-intelligence route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
