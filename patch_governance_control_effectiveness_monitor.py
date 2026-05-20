from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# GOVERNANCE_CONTROL_EFFECTIVENESS_MONITOR_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# GOVERNANCE_CONTROL_EFFECTIVENESS_MONITOR_ACTIVE
@app.route("/governance-control-effectiveness-monitor")
def governance_control_effectiveness_monitor_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Governance Control Effectiveness Monitor™ | COBIT-Chain™ / AssuranceLayer™</title>
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
            background: linear-gradient(135deg, #0f172a 0%, #075985 48%, #0f766e 100%);
            color: #fff;
            border-radius: 26px;
            padding: 28px;
            box-shadow: 0 16px 42px rgba(15, 23, 42, .22);
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
            max-width: 1100px;
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
        .portfolio-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .portfolio-card {
            border-radius: 20px;
            padding: 18px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .portfolio-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .portfolio-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .portfolio-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .portfolio-card.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .portfolio-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .portfolio-value {
            font-size: 28px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .portfolio-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
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
            gap: 14px;
            align-items: center;
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
            min-width: 330px;
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
        .health-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .health-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .health-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .health-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .health-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .health-card.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .health-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .health-value {
            font-size: 27px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .health-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
        }
        .review-grid {
            display: grid;
            gap: 12px;
        }
        .review-item {
            display: grid;
            grid-template-columns: 60px 1fr auto;
            gap: 14px;
            align-items: start;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .review-priority {
            width: 44px;
            height: 44px;
            border-radius: 14px;
            background: #173f86;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 900;
        }
        .review-title {
            font-weight: 900;
            margin-bottom: 5px;
        }
        .review-note {
            color: #53637b;
            line-height: 1.45;
            font-size: 14px;
        }
        .review-owner {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            text-align: right;
        }
        .inspector {
            display: grid;
            grid-template-columns: 1fr .88fr;
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
            background: #eef4ff;
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
            background: #eef2ff;
            border: 1px solid #c7d2fe;
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
            color: #3730a3;
            margin-bottom: 10px;
        }
        .inspector-meta {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 10px;
            margin-bottom: 14px;
        }
        .inspector-mini {
            background: rgba(255,255,255,.72);
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
            border-radius: 18px;
            background: rgba(255,255,255,.76);
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
            background: #075985;
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
            border-left: 5px solid #075985;
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
            .inspector,
            .action-console {
                grid-template-columns: 1fr;
            }
            .portfolio-grid,
            .health-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .portfolio-grid,
            .health-grid,
            .inspector-meta {
                grid-template-columns: 1fr;
            }
            .search {
                margin-left: 0;
                width: 100%;
                min-width: 0;
            }
            .review-item {
                grid-template-columns: 1fr;
            }
            .review-owner {
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
                <a href="/governance-control-library">Control Library</a>
                <a href="/governance-rule-factory">Rule Factory</a>
                <a href="/predictive-governance-drift">Predictive Drift</a>
                <a href="/executive-mission-control">Mission Control</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Post-Deployment Control Assurance</div>
            <h1>Governance Control Effectiveness Monitor™</h1>
            <p>
                The layer that proves whether published controls continue to work after deployment.
                It tracks which controls are preventing real risk, which controls are creating unnecessary noise,
                which controls are weakening over time, and where leadership must tune, strengthen, or retire logic
                before the control environment becomes stale.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Controls Monitored</div>
                    <div class="hero-value">24</div>
                    <div class="hero-note">Across active library</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Effective Controls</div>
                    <div class="hero-value">18</div>
                    <div class="hero-note">Performing as intended</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Attention Required</div>
                    <div class="hero-value">4</div>
                    <div class="hero-note">Tune or strengthen</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Retirement Candidates</div>
                    <div class="hero-value">2</div>
                    <div class="hero-note">Low value / high noise</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Prevention Yield</div>
                    <div class="hero-value">83%</div>
                    <div class="hero-note">Risk caught before failure</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Control Drift Index</div>
                    <div class="hero-value">11%</div>
                    <div class="hero-note">Currently within tolerance</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Control Portfolio Health</h2>
                <p>
                    The monitor distinguishes between controls that merely exist and controls that are still producing
                    meaningful assurance value in the live governance environment.
                </p>

                <div class="portfolio-grid">
                    <div class="portfolio-card green">
                        <div class="portfolio-label">Working Well</div>
                        <div class="portfolio-value">18</div>
                        <div class="portfolio-note">High prevention value and low noise.</div>
                    </div>
                    <div class="portfolio-card amber">
                        <div class="portfolio-label">Needs Tuning</div>
                        <div class="portfolio-value">3</div>
                        <div class="portfolio-note">Useful but generating avoidable friction.</div>
                    </div>
                    <div class="portfolio-card red">
                        <div class="portfolio-label">Weakening</div>
                        <div class="portfolio-value">1</div>
                        <div class="portfolio-note">Missed-risk pattern now visible.</div>
                    </div>
                    <div class="portfolio-card blue">
                        <div class="portfolio-label">Under Review</div>
                        <div class="portfolio-value">2</div>
                        <div class="portfolio-note">Potential retirement or redesign.</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Signal Quality</h2>
                <div class="signal-grid">
                    <div class="signal-row">
                        <div class="signal-top">
                            <div class="signal-title">True-Positive Precision</div>
                            <div class="signal-value">87%</div>
                        </div>
                        <div class="bar"><div class="bar-fill green" style="width: 87%;"></div></div>
                        <div class="signal-note">Most alerts represent genuine governance conditions worth intervention.</div>
                    </div>
                    <div class="signal-row">
                        <div class="signal-top">
                            <div class="signal-title">False-Positive Burden</div>
                            <div class="signal-value">13%</div>
                        </div>
                        <div class="bar"><div class="bar-fill amber" style="width: 13%;"></div></div>
                        <div class="signal-note">Noise remains controlled, but three rules need threshold refinement.</div>
                    </div>
                    <div class="signal-row">
                        <div class="signal-top">
                            <div class="signal-title">Missed-Risk Exposure</div>
                            <div class="signal-value">6%</div>
                        </div>
                        <div class="bar"><div class="bar-fill red" style="width: 6%;"></div></div>
                        <div class="signal-note">One release-chain pattern escaped early detection this cycle.</div>
                    </div>
                    <div class="signal-row">
                        <div class="signal-top">
                            <div class="signal-title">Coverage Completeness</div>
                            <div class="signal-value">91%</div>
                        </div>
                        <div class="bar"><div class="bar-fill blue" style="width: 91%;"></div></div>
                        <div class="signal-note">Most critical workflows now have at least one active preventive control.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Control Effectiveness Scorecard</h2>
            <p>
                Each control is assessed by real prevention value, alert quality, recurrence reduction, and whether it
                still fits the risk pattern it was designed to control.
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Controls</button>
                <button class="filter-btn" data-filter="effective">Effective</button>
                <button class="filter-btn" data-filter="tune">Tune</button>
                <button class="filter-btn" data-filter="weakening">Weakening</button>
                <button class="filter-btn" data-filter="retire">Retire</button>
                <input id="searchInput" class="search" type="text" placeholder="Search control, system, family, or issue...">
            </div>

            <table id="effectivenessTable">
                <thead>
                    <tr>
                        <th>Control</th>
                        <th>Family</th>
                        <th>Primary Outcome</th>
                        <th>True Positives</th>
                        <th>False Positives</th>
                        <th>Missed Risks</th>
                        <th>Effectiveness</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-state="effective" data-search="gcl-001 closure blocker open capa release servicenow veeva effective">
                        <td>GCL-001<br><strong>Closure Blocker with Open CAPA</strong></td>
                        <td>Closure Integrity</td>
                        <td>4 false closures prevented</td>
                        <td>11</td>
                        <td>1</td>
                        <td>0</td>
                        <td><span class="pill green">Effective</span></td>
                        <td>Maintain</td>
                    </tr>
                    <tr data-state="effective" data-search="gcl-002 approved role granted role myaccess servicenow access drift effective">
                        <td>GCL-002<br><strong>Approved Role = Granted Role</strong></td>
                        <td>Access Governance</td>
                        <td>6 mismatches caught early</td>
                        <td>9</td>
                        <td>2</td>
                        <td>0</td>
                        <td><span class="pill green">Effective</span></td>
                        <td>Maintain</td>
                    </tr>
                    <tr data-state="tune" data-search="gcl-003 veeva blue mountain reconciliation release sensitive tune false positives">
                        <td>GCL-003<br><strong>Release-Sensitive Record Reconciliation</strong></td>
                        <td>Reconciliation</td>
                        <td>3 true breaks identified</td>
                        <td>7</td>
                        <td>4</td>
                        <td>0</td>
                        <td><span class="pill amber">Tune</span></td>
                        <td>Refine threshold</td>
                    </tr>
                    <tr data-state="effective" data-search="gcl-004 certificate required before pattern exit closure assurance register effective">
                        <td>GCL-004<br><strong>Certificate Required Before Pattern Exit</strong></td>
                        <td>Closure Integrity</td>
                        <td>5 risky exits prevented</td>
                        <td>5</td>
                        <td>0</td>
                        <td>0</td>
                        <td><span class="pill green">Effective</span></td>
                        <td>Maintain</td>
                    </tr>
                    <tr data-state="weakening" data-search="gcl-005 downstream release confirmation middleware lis qc release weakening missed risk">
                        <td>GCL-005<br><strong>Downstream Release Confirmation</strong></td>
                        <td>Release Assurance</td>
                        <td>1 late blocker missed</td>
                        <td>6</td>
                        <td>1</td>
                        <td>1</td>
                        <td><span class="pill red">Weakening</span></td>
                        <td>Strengthen rule</td>
                    </tr>
                    <tr data-state="tune" data-search="gcl-006 privileged account owner review myaccess access quarterly review tune noise">
                        <td>GCL-006<br><strong>Privileged Account Owner Review</strong></td>
                        <td>Access Governance</td>
                        <td>Useful but noisy</td>
                        <td>8</td>
                        <td>5</td>
                        <td>0</td>
                        <td><span class="pill amber">Tune</span></td>
                        <td>Reduce noise</td>
                    </tr>
                    <tr data-state="retire" data-search="gcl-009 duplicate email reminder low value retire closure legacy">
                        <td>GCL-009<br><strong>Legacy Closure Reminder</strong></td>
                        <td>Closure Integrity</td>
                        <td>No unique prevention value</td>
                        <td>1</td>
                        <td>6</td>
                        <td>0</td>
                        <td><span class="pill blue">Retire</span></td>
                        <td>Replace</td>
                    </tr>
                    <tr data-state="retire" data-search="gcl-010 generic equipment notification blue mountain low signal retire">
                        <td>GCL-010<br><strong>Generic Equipment Notification</strong></td>
                        <td>Reconciliation</td>
                        <td>Too broad for action</td>
                        <td>2</td>
                        <td>7</td>
                        <td>0</td>
                        <td><span class="pill blue">Retire</span></td>
                        <td>Redesign</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Control Signal Health</h2>
                <div class="health-grid">
                    <div class="health-card green">
                        <div class="health-title">True Positives</div>
                        <div class="health-value">49</div>
                        <div class="health-note">
                            Genuine issues surfaced before deviation, audit finding, or release failure.
                        </div>
                    </div>
                    <div class="health-card amber">
                        <div class="health-title">False Positives</div>
                        <div class="health-value">17</div>
                        <div class="health-note">
                            Alerts that consumed review time without exposing real governance risk.
                        </div>
                    </div>
                    <div class="health-card red">
                        <div class="health-title">Missed Risks</div>
                        <div class="health-value">2</div>
                        <div class="health-note">
                            Cases where control logic failed to detect a real condition early enough.
                        </div>
                    </div>
                    <div class="health-card blue">
                        <div class="health-title">Coverage Gaps</div>
                        <div class="health-value">3</div>
                        <div class="health-note">
                            Important workflow areas with insufficient preventive control coverage.
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Executive Review Queue</h2>
                <div class="review-grid">
                    <div class="review-item">
                        <div class="review-priority">P1</div>
                        <div>
                            <div class="review-title">Strengthen GCL-005 downstream release logic</div>
                            <div class="review-note">
                                One release-chain blocker escaped early detection; add middleware event confirmation before final sign-off.
                            </div>
                        </div>
                        <div class="review-owner">QC / Governance</div>
                    </div>
                    <div class="review-item">
                        <div class="review-priority">P2</div>
                        <div>
                            <div class="review-title">Tune GCL-003 reconciliation threshold</div>
                            <div class="review-note">
                                Control remains useful, but four false positives suggest the mismatch tolerance is too sensitive.
                            </div>
                        </div>
                        <div class="review-owner">QA Systems</div>
                    </div>
                    <div class="review-item">
                        <div class="review-priority">P3</div>
                        <div>
                            <div class="review-title">Retire or redesign GCL-010</div>
                            <div class="review-note">
                                Generic equipment notifications create noise without enough actionable value.
                            </div>
                        </div>
                        <div class="review-owner">Engineering</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Control Effectiveness Inspector</h2>
            <p>
                Select a control to inspect why it is considered effective, noisy, weakening, or ready for retirement.
            </p>

            <div class="inspector">
                <div class="inspector-list">
                    <button class="inspect-btn active" data-control="closure">
                        <div class="inspect-kicker">GCL-001</div>
                        <div class="inspect-title">Closure Blocker with Open CAPA</div>
                        <div class="inspect-note">High prevention value, very low noise.</div>
                    </button>
                    <button class="inspect-btn" data-control="reconciliation">
                        <div class="inspect-kicker">GCL-003</div>
                        <div class="inspect-title">Release-Sensitive Record Reconciliation</div>
                        <div class="inspect-note">Useful, but producing avoidable false positives.</div>
                    </button>
                    <button class="inspect-btn" data-control="release">
                        <div class="inspect-kicker">GCL-005</div>
                        <div class="inspect-title">Downstream Release Confirmation</div>
                        <div class="inspect-note">Still valuable, but missed one late blocker.</div>
                    </button>
                    <button class="inspect-btn" data-control="legacy">
                        <div class="inspect-kicker">GCL-009</div>
                        <div class="inspect-title">Legacy Closure Reminder</div>
                        <div class="inspect-note">Low unique value and excessive noise.</div>
                    </button>
                </div>

                <div class="inspector-card">
                    <div class="inspector-label">Selected Control</div>
                    <div id="inspectorTitle" class="inspector-title">Closure Blocker with Open CAPA</div>
                    <div class="inspector-meta">
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Effectiveness</div>
                            <div id="inspectorEffectiveness" class="inspector-mini-value">Effective</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Prevention Yield</div>
                            <div id="inspectorYield" class="inspector-mini-value">92%</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Signal Quality</div>
                            <div id="inspectorSignal" class="inspector-mini-value">High</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Recommended Action</div>
                            <div id="inspectorAction" class="inspector-mini-value">Maintain</div>
                        </div>
                    </div>
                    <div id="inspectorVerdict" class="inspector-verdict">
                        The control is performing as intended: it has prevented four repeat false-closure scenarios and has produced only one false positive.
                    </div>
                    <div id="inspectorNote" class="inspector-note">
                        This rule should remain active without material change. It is one of the strongest examples of a learned failure pattern becoming durable control value.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Effectiveness Action Console</h2>
            <p>
                The monitor does not only report health; it routes controls into the appropriate next action.
            </p>

            <div class="action-console">
                <div class="action-list">
                    <div class="action-item">
                        <div>
                            <h3>Strengthen a weakening control</h3>
                            <p>Add a middleware event requirement to GCL-005 after one missed release blocker.</p>
                        </div>
                        <button class="action-btn" data-action="strengthen">Strengthen</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Tune a noisy control</h3>
                            <p>Adjust the mismatch threshold on GCL-003 to reduce avoidable escalations.</p>
                        </div>
                        <button class="action-btn" data-action="tune">Tune</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Retire low-value logic</h3>
                            <p>Remove GCL-009 after confirming no unique prevention value remains.</p>
                        </div>
                        <button class="action-btn" data-action="retire">Retire</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Promote a new coverage need</h3>
                            <p>Send an uncovered workflow gap back to the Rule Factory for control design.</p>
                        </div>
                        <button class="action-btn" data-action="promote">Promote</button>
                    </div>
                </div>

                <div id="consoleResult" class="console-result">
                    <div class="console-label">Effectiveness Outcome</div>
                    <div id="consoleTitle" class="console-title">Awaiting Action</div>
                    <div id="consoleNote" class="console-note">
                        Select an action to see how the monitor keeps the control environment current rather than static.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>Control Library</h3>
                <p>
                    Shows which approved controls exist and where they are deployed.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Effectiveness Monitor</h3>
                <p>
                    Proves whether those controls continue to create real assurance value after deployment.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    COBIT-Chain™ now monitors the health of the control environment itself, not just the workflows beneath it.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by the Effectiveness Monitor</h2>
            <p>
                The Governance Control Library™ answers: <strong>“Which approved controls exist?”</strong>
            </p>
            <p>
                The Governance Control Effectiveness Monitor™ answers: <strong>“Are those controls still effective, efficient, and worth keeping?”</strong>
            </p>
            <p>
                That is a materially more mature governance position. The platform no longer assumes that because a rule
                was once approved, it remains useful forever. It watches the controls themselves for drift, noise, missed risk,
                and coverage gaps — exactly what an enterprise control environment needs if it is going to stay credible over time.
            </p>
            <div class="footer-note">
                Simulation chain: pain point detection → dependency validation → reconciliation → decision intelligence →
                Governance Passport™ → Governance Assurance Register™ → Governance Intervention Workbench™ →
                Governance Re-Closure Gate™ → Governance Closure Certificate™ → Governance Learning Loop™ →
                Governance Rule Factory™ → Governance Control Library™ → Governance Control Effectiveness Monitor™.
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#effectivenessTable tbody tr");
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

        const inspectButtons = document.querySelectorAll(".inspect-btn");
        const inspectorTitle = document.getElementById("inspectorTitle");
        const inspectorEffectiveness = document.getElementById("inspectorEffectiveness");
        const inspectorYield = document.getElementById("inspectorYield");
        const inspectorSignal = document.getElementById("inspectorSignal");
        const inspectorAction = document.getElementById("inspectorAction");
        const inspectorVerdict = document.getElementById("inspectorVerdict");
        const inspectorNote = document.getElementById("inspectorNote");

        const controls = {
            closure: {
                title: "Closure Blocker with Open CAPA",
                effectiveness: "Effective",
                yield: "92%",
                signal: "High",
                action: "Maintain",
                verdict: "The control is performing as intended: it has prevented four repeat false-closure scenarios and has produced only one false positive.",
                note: "This rule should remain active without material change. It is one of the strongest examples of a learned failure pattern becoming durable control value."
            },
            reconciliation: {
                title: "Release-Sensitive Record Reconciliation",
                effectiveness: "Tune",
                yield: "71%",
                signal: "Moderate",
                action: "Refine threshold",
                verdict: "The control remains useful, but four false positives indicate that its mismatch threshold is too sensitive for some low-risk state differences.",
                note: "Keep the control, but route it back through tuning so it preserves real prevention value without creating avoidable QA review burden."
            },
            release: {
                title: "Downstream Release Confirmation",
                effectiveness: "Weakening",
                yield: "68%",
                signal: "Variable",
                action: "Strengthen",
                verdict: "The control still catches real risk, but it missed one late middleware-linked release blocker this cycle.",
                note: "Add a middleware event confirmation step and re-test the rule before the next release-sensitive review cycle."
            },
            legacy: {
                title: "Legacy Closure Reminder",
                effectiveness: "Retire",
                yield: "18%",
                signal: "Low",
                action: "Replace",
                verdict: "The control produces more noise than unique assurance value and is now duplicated by stronger closure-integrity controls.",
                note: "Retire or redesign the rule so the platform does not preserve low-value logic merely because it existed first."
            }
        };

        inspectButtons.forEach(button => {
            button.addEventListener("click", () => {
                inspectButtons.forEach(btn => btn.classList.remove("active"));
                button.classList.add("active");

                const control = controls[button.dataset.control];
                inspectorTitle.textContent = control.title;
                inspectorEffectiveness.textContent = control.effectiveness;
                inspectorYield.textContent = control.yield;
                inspectorSignal.textContent = control.signal;
                inspectorAction.textContent = control.action;
                inspectorVerdict.textContent = control.verdict;
                inspectorNote.textContent = control.note;
            });
        });

        const actionButtons = document.querySelectorAll(".action-btn");
        const consoleResult = document.getElementById("consoleResult");
        const consoleTitle = document.getElementById("consoleTitle");
        const consoleNote = document.getElementById("consoleNote");

        const outcomes = {
            strengthen: {
                title: "Strengthening Routed",
                note: "GCL-005 has been sent back for stronger downstream release logic after one missed blocker."
            },
            tune: {
                title: "Tuning Requested",
                note: "GCL-003 will be threshold-adjusted to preserve prevention value while reducing avoidable false positives."
            },
            retire: {
                title: "Retirement Review Opened",
                note: "GCL-009 has been marked for controlled retirement because it no longer provides unique assurance value."
            },
            promote: {
                title: "Coverage Gap Promoted",
                note: "An uncovered workflow need has been returned to the Governance Rule Factory™ for new control design."
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
        print("SKIP: GOVERNANCE_CONTROL_EFFECTIVENESS_MONITOR_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/governance-control-effectiveness-monitor")',
        "Governance Control Effectiveness Monitor™",
        "Control Effectiveness Scorecard",
        "Control Signal Health",
        "Control Effectiveness Inspector",
        "Effectiveness Action Console",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /governance-control-effectiveness-monitor route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
