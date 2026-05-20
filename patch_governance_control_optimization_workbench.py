from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# GOVERNANCE_CONTROL_OPTIMIZATION_WORKBENCH_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# GOVERNANCE_CONTROL_OPTIMIZATION_WORKBENCH_ACTIVE
@app.route("/governance-control-optimization-workbench")
def governance_control_optimization_workbench_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Governance Control Optimization Workbench™ | COBIT-Chain™ / AssuranceLayer™</title>
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
            background: linear-gradient(135deg, #111827 0%, #7c2d12 48%, #0f766e 100%);
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
        .queue-grid {
            display: grid;
            gap: 12px;
        }
        .queue-item {
            display: grid;
            grid-template-columns: 64px 1fr auto;
            gap: 14px;
            align-items: start;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .queue-priority {
            width: 46px;
            height: 46px;
            border-radius: 15px;
            background: #7c2d12;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 900;
        }
        .queue-title {
            font-weight: 900;
            margin-bottom: 5px;
        }
        .queue-note {
            color: #53637b;
            line-height: 1.45;
            font-size: 14px;
        }
        .queue-state {
            text-align: right;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
        }
        .before-after {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 14px;
        }
        .metric-card {
            border-radius: 20px;
            padding: 18px;
            border: 1px solid #e2eaf7;
        }
        .metric-card.before {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .metric-card.after {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .metric-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .metric-value {
            font-size: 32px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .metric-card.before .metric-value {
            color: #991b1b;
        }
        .metric-card.after .metric-value {
            color: #166534;
        }
        .metric-note {
            color: #53637b;
            line-height: 1.45;
            font-size: 14px;
        }
        .workflow {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
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
            background: #7c2d12;
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
        .lab {
            display: grid;
            grid-template-columns: 1fr .9fr;
            gap: 18px;
        }
        .lab-controls {
            display: grid;
            gap: 12px;
        }
        .lab-row {
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .lab-row label {
            display: block;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .lab-row select,
        .lab-row input[type="range"] {
            width: 100%;
        }
        .lab-row select {
            border: 1px solid #d7e1f0;
            border-radius: 14px;
            padding: 11px 12px;
            font-size: 14px;
            background: #fff;
            color: #172033;
            outline: none;
        }
        .range-meta {
            display: flex;
            justify-content: space-between;
            gap: 12px;
            margin-top: 8px;
            font-size: 13px;
            color: #53637b;
            font-weight: 700;
        }
        .lab-result {
            border-radius: 22px;
            padding: 22px;
            background: #fff7ed;
            border: 1px solid #fed7aa;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        .lab-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .lab-title {
            font-size: 28px;
            font-weight: 900;
            color: #9a3412;
            margin-bottom: 10px;
        }
        .lab-rule {
            border-radius: 18px;
            background: rgba(255,255,255,.76);
            padding: 16px;
            font-weight: 800;
            line-height: 1.5;
            margin-bottom: 12px;
        }
        .lab-metrics {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 10px;
            margin-bottom: 12px;
        }
        .lab-mini {
            background: rgba(255,255,255,.76);
            border-radius: 14px;
            padding: 12px;
        }
        .lab-mini-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 5px;
        }
        .lab-mini-value {
            font-weight: 900;
        }
        .lab-note {
            color: #4d5b73;
            line-height: 1.55;
        }
        .compare-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .compare-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .compare-card.before {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .compare-card.after {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .compare-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .compare-value {
            font-size: 27px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .compare-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
        }
        .path-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .path-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .path-card h3 {
            margin: 0 0 8px;
            font-size: 16px;
        }
        .path-card p {
            margin: 0 0 12px;
            font-size: 14px;
        }
        .path-state {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            background: #e0e7ff;
            color: #3730a3;
            font-size: 12px;
            font-weight: 900;
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
            background: #7c2d12;
            color: #fff;
            font-weight: 900;
            font-size: 13px;
            white-space: nowrap;
        }
        .console-result {
            border-radius: 22px;
            padding: 22px;
            background: #fff7ed;
            border: 1px solid #fed7aa;
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
            color: #9a3412;
            margin-bottom: 10px;
        }
        .console-note {
            color: #4d5b73;
            line-height: 1.55;
        }
        .maturity-card {
            border-left: 5px solid #7c2d12;
            background: #fff7ed;
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
            .lab,
            .action-console {
                grid-template-columns: 1fr;
            }
            .workflow {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .compare-grid,
            .path-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .workflow,
            .compare-grid,
            .path-grid,
            .before-after,
            .lab-metrics {
                grid-template-columns: 1fr;
            }
            .search {
                margin-left: 0;
                width: 100%;
                min-width: 0;
            }
            .queue-item {
                grid-template-columns: 1fr;
            }
            .queue-state {
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
                <a href="/governance-control-effectiveness-monitor">Effectiveness Monitor</a>
                <a href="/governance-control-library">Control Library</a>
                <a href="/governance-rule-factory">Rule Factory</a>
                <a href="/governance-learning-loop">Learning Loop</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Self-Correcting Control Environment</div>
            <h1>Governance Control Optimization Workbench™</h1>
            <p>
                The workbench where weak, noisy, or aging controls are actively improved after the Effectiveness Monitor
                identifies them. COBIT-Chain™ can tune thresholds, strengthen missed-risk logic, redesign low-value rules,
                compare before-versus-after performance, and return optimized controls to the governed library with a
                clearer, stronger assurance profile.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Controls in Workbench</div>
                    <div class="hero-value">6</div>
                    <div class="hero-note">Tune, strengthen, or retire</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Priority Control</div>
                    <div class="hero-value">GCL-005</div>
                    <div class="hero-note">Downstream release logic</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">False Positives to Reduce</div>
                    <div class="hero-value">-35%</div>
                    <div class="hero-note">Projected after tuning</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Missed-Risk Target</div>
                    <div class="hero-value">0</div>
                    <div class="hero-note">For strengthened rules</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Retirement Candidates</div>
                    <div class="hero-value">2</div>
                    <div class="hero-note">Low-value controls</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Optimization State</div>
                    <div class="hero-value">Active</div>
                    <div class="hero-note">Control environment evolving</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Optimization Queue</h2>
                <div class="queue-grid">
                    <div class="queue-item">
                        <div class="queue-priority">P1</div>
                        <div>
                            <div class="queue-title">Strengthen GCL-005 — Downstream Release Confirmation</div>
                            <div class="queue-note">
                                One late blocker was missed. Add middleware event confirmation before final release sign-off.
                            </div>
                        </div>
                        <div class="queue-state">Weakening</div>
                    </div>
                    <div class="queue-item">
                        <div class="queue-priority">P2</div>
                        <div>
                            <div class="queue-title">Tune GCL-003 — Release-Sensitive Record Reconciliation</div>
                            <div class="queue-note">
                                Useful control, but four false positives show the mismatch threshold is too sensitive.
                            </div>
                        </div>
                        <div class="queue-state">Noisy</div>
                    </div>
                    <div class="queue-item">
                        <div class="queue-priority">P3</div>
                        <div>
                            <div class="queue-title">Retire GCL-009 — Legacy Closure Reminder</div>
                            <div class="queue-note">
                                The rule is now duplicated by stronger closure controls and no longer adds unique value.
                            </div>
                        </div>
                        <div class="queue-state">Low Value</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Selected Optimization Case</h2>
                <p>
                    GCL-005 still catches real release risk, but one missed blocker shows its logic is no longer complete
                    enough for the current workflow. The target is not to discard it; the target is to make it stronger.
                </p>
                <div class="before-after">
                    <div class="metric-card before">
                        <div class="metric-label">Before Optimization</div>
                        <div class="metric-value">68%</div>
                        <div class="metric-note">
                            Prevention yield with one missed middleware-linked blocker.
                        </div>
                    </div>
                    <div class="metric-card after">
                        <div class="metric-label">Projected After</div>
                        <div class="metric-value">89%</div>
                        <div class="metric-note">
                            Stronger release assurance after middleware confirmation is added.
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Optimization Workflow</h2>
            <div class="workflow">
                <div class="step">
                    <div class="step-number">1</div>
                    <h3>Diagnose</h3>
                    <p>Use effectiveness data to identify noise, drift, missed risk, or low value.</p>
                </div>
                <div class="step">
                    <div class="step-number">2</div>
                    <h3>Choose Path</h3>
                    <p>Decide whether to tune, strengthen, redesign, or retire the control.</p>
                </div>
                <div class="step">
                    <div class="step-number">3</div>
                    <h3>Simulate</h3>
                    <p>Model the likely before-versus-after impact before changing live logic.</p>
                </div>
                <div class="step">
                    <div class="step-number">4</div>
                    <h3>Approve</h3>
                    <p>Route the optimized control through governed review and versioning.</p>
                </div>
                <div class="step">
                    <div class="step-number">5</div>
                    <h3>Re-Deploy</h3>
                    <p>Return the stronger control to the library and continue monitoring.</p>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Optimization Register</h2>
            <p>
                The register shows which controls are being improved, why, and what outcome is expected after optimization.
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Controls</button>
                <button class="filter-btn" data-filter="strengthen">Strengthen</button>
                <button class="filter-btn" data-filter="tune">Tune</button>
                <button class="filter-btn" data-filter="retire">Retire</button>
                <button class="filter-btn" data-filter="redesign">Redesign</button>
                <input id="searchInput" class="search" type="text" placeholder="Search control, issue, family, or optimization path...">
            </div>

            <table id="optimizationTable">
                <thead>
                    <tr>
                        <th>Control</th>
                        <th>Current Issue</th>
                        <th>Optimization Path</th>
                        <th>Current Yield</th>
                        <th>Projected Yield</th>
                        <th>False Positives</th>
                        <th>Next Version</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-path="strengthen" data-search="gcl-005 downstream release confirmation missed risk strengthen release assurance middleware">
                        <td>GCL-005<br><strong>Downstream Release Confirmation</strong></td>
                        <td>One missed late blocker</td>
                        <td><span class="pill red">Strengthen</span></td>
                        <td>68%</td>
                        <td>89%</td>
                        <td>1 → 1</td>
                        <td>v1.3</td>
                        <td><span class="pill amber">In Design</span></td>
                    </tr>
                    <tr data-path="tune" data-search="gcl-003 release-sensitive record reconciliation false positives threshold tune reconciliation">
                        <td>GCL-003<br><strong>Release-Sensitive Record Reconciliation</strong></td>
                        <td>Threshold too sensitive</td>
                        <td><span class="pill amber">Tune</span></td>
                        <td>71%</td>
                        <td>84%</td>
                        <td>4 → 2</td>
                        <td>v1.1</td>
                        <td><span class="pill blue">Simulation</span></td>
                    </tr>
                    <tr data-path="retire" data-search="gcl-009 legacy closure reminder duplicate low value retire closure integrity">
                        <td>GCL-009<br><strong>Legacy Closure Reminder</strong></td>
                        <td>No unique assurance value</td>
                        <td><span class="pill blue">Retire</span></td>
                        <td>18%</td>
                        <td>Removed</td>
                        <td>6 → 0</td>
                        <td>Retired</td>
                        <td><span class="pill indigo">Review</span></td>
                    </tr>
                    <tr data-path="redesign" data-search="gcl-010 generic equipment notification broad low signal redesign equipment reconciliation">
                        <td>GCL-010<br><strong>Generic Equipment Notification</strong></td>
                        <td>Too broad for action</td>
                        <td><span class="pill green">Redesign</span></td>
                        <td>24%</td>
                        <td>76%</td>
                        <td>7 → 2</td>
                        <td>v2.0</td>
                        <td><span class="pill amber">In Design</span></td>
                    </tr>
                    <tr data-path="tune" data-search="gcl-006 privileged account owner review myaccess noisy access governance tune">
                        <td>GCL-006<br><strong>Privileged Account Owner Review</strong></td>
                        <td>Useful but noisy</td>
                        <td><span class="pill amber">Tune</span></td>
                        <td>74%</td>
                        <td>82%</td>
                        <td>5 → 3</td>
                        <td>v2.2</td>
                        <td><span class="pill blue">Simulation</span></td>
                    </tr>
                    <tr data-path="strengthen" data-search="gcl-008 erp mes lims release chain coverage gap strengthen batch disposition">
                        <td>GCL-008<br><strong>ERP → MES → LIMS Release Chain</strong></td>
                        <td>Coverage incomplete</td>
                        <td><span class="pill red">Strengthen</span></td>
                        <td>63%</td>
                        <td>86%</td>
                        <td>2 → 2</td>
                        <td>v1.0</td>
                        <td><span class="pill amber">In Design</span></td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Interactive Optimization Lab</h2>
            <p>
                This simulation shows how a weak control can be altered before it is republished into the control library.
            </p>

            <div class="lab">
                <div class="lab-controls">
                    <div class="lab-row">
                        <label for="controlSelect">Control Under Optimization</label>
                        <select id="controlSelect">
                            <option value="gcl005">GCL-005 — Downstream Release Confirmation</option>
                            <option value="gcl003">GCL-003 — Release-Sensitive Record Reconciliation</option>
                            <option value="gcl009">GCL-009 — Legacy Closure Reminder</option>
                        </select>
                    </div>
                    <div class="lab-row">
                        <label for="pathSelect">Optimization Path</label>
                        <select id="pathSelect">
                            <option value="strengthen">Strengthen logic</option>
                            <option value="tune">Tune threshold</option>
                            <option value="retire">Retire control</option>
                        </select>
                    </div>
                    <div class="lab-row">
                        <label for="sensitivityRange">Sensitivity / Strictness</label>
                        <input id="sensitivityRange" type="range" min="1" max="5" value="4">
                        <div class="range-meta">
                            <span>Lower friction</span>
                            <span id="sensitivityValue">4 / 5</span>
                            <span>Higher assurance</span>
                        </div>
                    </div>
                </div>

                <div class="lab-result">
                    <div class="lab-label">Projected Optimization Outcome</div>
                    <div id="labTitle" class="lab-title">Strengthened Control</div>
                    <div id="labRule" class="lab-rule">
                        Add middleware event confirmation before downstream release is accepted as complete.
                    </div>
                    <div class="lab-metrics">
                        <div class="lab-mini">
                            <div class="lab-mini-label">Projected Yield</div>
                            <div id="labYield" class="lab-mini-value">89%</div>
                        </div>
                        <div class="lab-mini">
                            <div class="lab-mini-label">False Positives</div>
                            <div id="labNoise" class="lab-mini-value">1</div>
                        </div>
                        <div class="lab-mini">
                            <div class="lab-mini-label">Recommended Version</div>
                            <div id="labVersion" class="lab-mini-value">v1.3</div>
                        </div>
                    </div>
                    <div id="labNote" class="lab-note">
                        This path closes the missed-risk gap while preserving low alert noise.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Before vs After Optimization</h2>
            <div class="compare-grid">
                <div class="compare-card before">
                    <div class="compare-label">Before — Prevention Yield</div>
                    <div class="compare-value">68%</div>
                    <div class="compare-note">Missed one release blocker.</div>
                </div>
                <div class="compare-card after">
                    <div class="compare-label">After — Prevention Yield</div>
                    <div class="compare-value">89%</div>
                    <div class="compare-note">Stronger release assurance.</div>
                </div>
                <div class="compare-card before">
                    <div class="compare-label">Before — Missed Risks</div>
                    <div class="compare-value">1</div>
                    <div class="compare-note">Late middleware event escaped detection.</div>
                </div>
                <div class="compare-card after">
                    <div class="compare-label">After — Missed Risks</div>
                    <div class="compare-value">0</div>
                    <div class="compare-note">Projected after added event gate.</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Optimization Paths</h2>
                <div class="path-grid">
                    <div class="path-card">
                        <h3>Tune</h3>
                        <p>Reduce noise by adjusting thresholds without changing the control’s core intent.</p>
                        <div class="path-state">For noisy controls</div>
                    </div>
                    <div class="path-card">
                        <h3>Strengthen</h3>
                        <p>Add missing conditions or evidence gates when a real risk escaped detection.</p>
                        <div class="path-state">For weakening controls</div>
                    </div>
                    <div class="path-card">
                        <h3>Redesign</h3>
                        <p>Rewrite controls whose current shape is too broad or no longer aligned to the risk.</p>
                        <div class="path-state">For low-signal controls</div>
                    </div>
                    <div class="path-card">
                        <h3>Retire</h3>
                        <p>Remove controls that no longer add unique assurance value or are fully superseded.</p>
                        <div class="path-state">For obsolete controls</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Return Path to the Library</h2>
                <p>
                    Optimization is not an informal tweak. Once an improved control is accepted, it must be versioned,
                    approved, and returned to the Governance Control Library™ as a governed asset.
                </p>
                <table>
                    <thead>
                        <tr>
                            <th>Stage</th>
                            <th>Required Evidence</th>
                            <th>Outcome</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Design</td>
                            <td>Optimization rationale + expected effect</td>
                            <td><span class="pill amber">Draft</span></td>
                        </tr>
                        <tr>
                            <td>Simulation</td>
                            <td>Before/after impact model</td>
                            <td><span class="pill blue">Tested</span></td>
                        </tr>
                        <tr>
                            <td>Approval</td>
                            <td>QA / governance sign-off</td>
                            <td><span class="pill indigo">Authorized</span></td>
                        </tr>
                        <tr>
                            <td>Library Return</td>
                            <td>Versioned control record</td>
                            <td><span class="pill green">Republished</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Optimization Action Console</h2>
            <p>
                The workbench routes each control toward the right governance outcome rather than treating every control the same.
            </p>

            <div class="action-console">
                <div class="action-list">
                    <div class="action-item">
                        <div>
                            <h3>Approve strengthened GCL-005</h3>
                            <p>Advance the middleware-confirmation version for controlled publication.</p>
                        </div>
                        <button class="action-btn" data-action="approve">Approve</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Send GCL-003 to threshold tuning</h3>
                            <p>Reduce false positives while preserving reconciliation value.</p>
                        </div>
                        <button class="action-btn" data-action="tune">Tune</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Open retirement review for GCL-009</h3>
                            <p>Remove legacy logic that no longer creates unique assurance value.</p>
                        </div>
                        <button class="action-btn" data-action="retire">Retire</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Return optimized rule to library</h3>
                            <p>Publish a versioned, approved control back into active governance use.</p>
                        </div>
                        <button class="action-btn" data-action="return">Return</button>
                    </div>
                </div>

                <div id="consoleResult" class="console-result">
                    <div class="console-label">Optimization Outcome</div>
                    <div id="consoleTitle" class="console-title">Awaiting Action</div>
                    <div id="consoleNote" class="console-note">
                        Select an action to see how the workbench improves, retires, or republishes controls.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>Effectiveness Monitor</h3>
                <p>
                    Detects which controls are strong, noisy, weakening, or obsolete.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Optimization Workbench</h3>
                <p>
                    Converts effectiveness findings into deliberate control improvement.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    COBIT-Chain™ now shows a self-correcting control environment, not a static rules catalogue.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by the Optimization Workbench</h2>
            <p>
                The Governance Control Effectiveness Monitor™ answers: <strong>“Which controls are still working well?”</strong>
            </p>
            <p>
                The Governance Control Optimization Workbench™ answers: <strong>“How do we make weak or noisy controls better before they damage confidence?”</strong>
            </p>
            <p>
                That is the difference between monitoring a control environment and actively governing its evolution.
                COBIT-Chain™ now demonstrates that controls can be learned, approved, deployed, measured, and then improved
                again based on live performance — a full lifecycle for enterprise governance logic itself.
            </p>
            <div class="footer-note">
                Simulation chain: pain point detection → dependency validation → reconciliation → decision intelligence →
                Governance Passport™ → Governance Assurance Register™ → Governance Intervention Workbench™ →
                Governance Re-Closure Gate™ → Governance Closure Certificate™ → Governance Learning Loop™ →
                Governance Rule Factory™ → Governance Control Library™ → Governance Control Effectiveness Monitor™ →
                Governance Control Optimization Workbench™.
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#optimizationTable tbody tr");
        const searchInput = document.getElementById("searchInput");
        let activeFilter = "all";

        function applyFilters() {
            const query = searchInput.value.toLowerCase().trim();

            rows.forEach(row => {
                const path = row.dataset.path;
                const searchable = row.dataset.search;
                const matchesFilter = activeFilter === "all" || path === activeFilter;
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

        const controlSelect = document.getElementById("controlSelect");
        const pathSelect = document.getElementById("pathSelect");
        const sensitivityRange = document.getElementById("sensitivityRange");
        const sensitivityValue = document.getElementById("sensitivityValue");
        const labTitle = document.getElementById("labTitle");
        const labRule = document.getElementById("labRule");
        const labYield = document.getElementById("labYield");
        const labNoise = document.getElementById("labNoise");
        const labVersion = document.getElementById("labVersion");
        const labNote = document.getElementById("labNote");

        const labProfiles = {
            gcl005: {
                strengthen: {
                    title: "Strengthened Control",
                    rule: "Add middleware event confirmation before downstream release is accepted as complete.",
                    yield: "89%",
                    noise: "1",
                    version: "v1.3",
                    note: "This path closes the missed-risk gap while preserving low alert noise."
                },
                tune: {
                    title: "Threshold Tuned",
                    rule: "Reduce escalation on low-consequence release variances while preserving blocker detection.",
                    yield: "81%",
                    noise: "0",
                    version: "v1.3-t",
                    note: "This path reduces friction, but does not fully solve the missed-risk problem."
                },
                retire: {
                    title: "Retirement Not Recommended",
                    rule: "Do not retire a control that still prevents genuine release risk.",
                    yield: "0%",
                    noise: "0",
                    version: "N/A",
                    note: "Retirement would remove necessary release assurance and is not recommended."
                }
            },
            gcl003: {
                strengthen: {
                    title: "Stronger Reconciliation Rule",
                    rule: "Add state-criticality weighting before accepting release-sensitive mismatches.",
                    yield: "86%",
                    noise: "3",
                    version: "v1.1-s",
                    note: "Stronger logic improves risk separation but may still create some review burden."
                },
                tune: {
                    title: "Threshold Tuned",
                    rule: "Ignore low-risk cosmetic differences and escalate only material reconciliation breaks.",
                    yield: "84%",
                    noise: "2",
                    version: "v1.1",
                    note: "This is the recommended path for GCL-003 because it preserves value while reducing noise."
                },
                retire: {
                    title: "Retirement Not Recommended",
                    rule: "Do not retire a control that still identifies real reconciliation breaks.",
                    yield: "0%",
                    noise: "0",
                    version: "N/A",
                    note: "The control remains useful; tuning is preferable to retirement."
                }
            },
            gcl009: {
                strengthen: {
                    title: "Strengthening Not Useful",
                    rule: "Legacy reminder logic is already superseded by stronger closure controls.",
                    yield: "22%",
                    noise: "5",
                    version: "v1.1",
                    note: "Adding complexity would preserve a low-value control rather than improve the environment."
                },
                tune: {
                    title: "Tuning Offers Limited Value",
                    rule: "Reduce repetitive reminder frequency while preserving only unique triggers.",
                    yield: "29%",
                    noise: "3",
                    version: "v1.1-t",
                    note: "Tuning lowers noise but still leaves weak unique assurance value."
                },
                retire: {
                    title: "Retirement Recommended",
                    rule: "Retire the legacy reminder and rely on stronger closure-integrity controls.",
                    yield: "Removed",
                    noise: "0",
                    version: "Retired",
                    note: "This is the strongest outcome because the control is duplicated and no longer needed."
                }
            }
        };

        function updateLab() {
            sensitivityValue.textContent = sensitivityRange.value + " / 5";
            const profile = labProfiles[controlSelect.value][pathSelect.value];
            labTitle.textContent = profile.title;
            labRule.textContent = profile.rule;
            labYield.textContent = profile.yield;
            labNoise.textContent = profile.noise;
            labVersion.textContent = profile.version;
            labNote.textContent = profile.note;
        }

        controlSelect.addEventListener("change", updateLab);
        pathSelect.addEventListener("change", updateLab);
        sensitivityRange.addEventListener("input", updateLab);
        updateLab();

        const actionButtons = document.querySelectorAll(".action-btn");
        const consoleResult = document.getElementById("consoleResult");
        const consoleTitle = document.getElementById("consoleTitle");
        const consoleNote = document.getElementById("consoleNote");

        const outcomes = {
            approve: {
                title: "GCL-005 Approved for Versioning",
                note: "The strengthened downstream-release control may now proceed toward controlled publication as v1.3."
            },
            tune: {
                title: "GCL-003 Sent to Tuning",
                note: "The reconciliation control will be adjusted to reduce false positives without weakening material mismatch detection."
            },
            retire: {
                title: "GCL-009 Retirement Review Opened",
                note: "The legacy closure reminder has been routed for controlled retirement because it no longer adds unique value."
            },
            return: {
                title: "Optimized Control Returned",
                note: "The approved control version has been sent back to the Governance Control Library™ for governed re-deployment."
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
        print("SKIP: GOVERNANCE_CONTROL_OPTIMIZATION_WORKBENCH_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/governance-control-optimization-workbench")',
        "Governance Control Optimization Workbench™",
        "Optimization Register",
        "Interactive Optimization Lab",
        "Before vs After Optimization",
        "Optimization Action Console",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /governance-control-optimization-workbench route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
