from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# GOVERNANCE_CONTROL_CHANGE_LEDGER_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# GOVERNANCE_CONTROL_CHANGE_LEDGER_ACTIVE
@app.route("/governance-control-change-ledger")
def governance_control_change_ledger_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Governance Control Change Ledger™ | COBIT-Chain™ / AssuranceLayer™</title>
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
            background: linear-gradient(135deg, #111827 0%, #334155 42%, #0f766e 100%);
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
            max-width: 1110px;
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
        .ledger-card {
            background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
            border: 1px solid #dbe7f8;
            border-radius: 22px;
            padding: 20px;
        }
        .ledger-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #0f766e;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .ledger-title {
            font-size: 24px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .ledger-note {
            color: #4c5b73;
            line-height: 1.55;
            margin-bottom: 16px;
        }
        .ledger-meta {
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
        .integrity-box {
            background: #0f172a;
            color: #e2e8f0;
            border-radius: 22px;
            padding: 22px;
        }
        .integrity-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #93c5fd;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .integrity-value {
            font-family: Consolas, "Courier New", monospace;
            word-break: break-all;
            font-size: 14px;
            line-height: 1.55;
            margin-bottom: 14px;
        }
        .verify-row {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
        }
        .verify-btn {
            border: 0;
            cursor: pointer;
            border-radius: 999px;
            padding: 10px 14px;
            background: #10b981;
            color: #062f25;
            font-weight: 900;
            font-size: 13px;
        }
        .verify-state {
            display: inline-block;
            border-radius: 999px;
            padding: 8px 12px;
            background: rgba(255,255,255,.12);
            font-size: 13px;
            font-weight: 800;
        }
        .chain-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 12px;
        }
        .chain-step {
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .chain-no {
            width: 32px;
            height: 32px;
            border-radius: 11px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #0f766e;
            color: #fff;
            font-weight: 900;
            margin-bottom: 12px;
        }
        .chain-step h3 {
            margin: 0 0 8px;
            font-size: 16px;
        }
        .chain-step p {
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
        .pill.blue {
            background: #dbeafe;
            color: #1d4ed8;
        }
        .pill.indigo {
            background: #e0e7ff;
            color: #3730a3;
        }
        .pill.red {
            background: #fee2e2;
            color: #991b1b;
        }
        .approval-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .approval-card {
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 17px;
        }
        .approval-role {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 7px;
        }
        .approval-name {
            font-size: 17px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .approval-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
        }
        .version-grid {
            display: grid;
            gap: 12px;
        }
        .version-item {
            display: grid;
            grid-template-columns: 88px 1fr auto;
            gap: 14px;
            align-items: start;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .version-tag {
            border-radius: 14px;
            background: #0f766e;
            color: #fff;
            padding: 10px;
            text-align: center;
            font-weight: 900;
        }
        .version-title {
            font-weight: 900;
            margin-bottom: 5px;
        }
        .version-note {
            color: #53637b;
            line-height: 1.45;
            font-size: 14px;
        }
        .version-date {
            font-size: 12px;
            color: #64748b;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: .05em;
            text-align: right;
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
            background: #eef4ff;
        }
        .inspect-btn.active {
            border-color: #99f6e4;
            background: #f0fdfa;
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
            background: #f0fdfa;
            border: 1px solid #99f6e4;
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
            color: #115e59;
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
        .inspector-change {
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
        .ledger-map {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .map-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .map-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .map-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
            margin-bottom: 11px;
        }
        .map-state {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            background: #ccfbf1;
            color: #115e59;
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
            background: #0f766e;
            color: #fff;
            font-weight: 900;
            font-size: 13px;
            white-space: nowrap;
        }
        .console-result {
            border-radius: 22px;
            padding: 22px;
            background: #f0fdfa;
            border: 1px solid #99f6e4;
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
            color: #115e59;
            margin-bottom: 10px;
        }
        .console-note {
            color: #4d5b73;
            line-height: 1.55;
        }
        .maturity-card {
            border-left: 5px solid #0f766e;
            background: #f0fdfa;
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
            .chain-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .approval-grid,
            .ledger-map {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .chain-grid,
            .approval-grid,
            .ledger-map,
            .ledger-meta,
            .inspector-meta {
                grid-template-columns: 1fr;
            }
            .search {
                margin-left: 0;
                width: 100%;
                min-width: 0;
            }
            .version-item {
                grid-template-columns: 1fr;
            }
            .version-date {
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
                <a href="/governance-control-release-orchestrator">Release Orchestrator</a>
                <a href="/governance-control-library">Control Library</a>
                <a href="/governance-control-optimization-workbench">Optimization Workbench</a>
                <a href="/governance-closure-certificate">Closure Certificate</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Immutable Control Evolution Record</div>
            <h1>Governance Control Change Ledger™</h1>
            <p>
                The permanent governed record of how the enterprise control environment itself changes over time.
                Every approved control release is captured with its source lesson, prior version, new version, approval chain,
                release package, affected modules, rollback posture, and integrity proof so that control evolution is as auditable
                as the business workflows those controls protect.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Ledger Entries</div>
                    <div class="hero-value">37</div>
                    <div class="hero-note">Versioned control changes</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Latest Entry</div>
                    <div class="hero-value">CCL-2026-037</div>
                    <div class="hero-note">RLS-2026-014 bundle</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Controls Changed</div>
                    <div class="hero-value">3</div>
                    <div class="hero-note">In latest release package</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Integrity State</div>
                    <div class="hero-value">Verified</div>
                    <div class="hero-note">Hash chain intact</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Rollback Recorded</div>
                    <div class="hero-value">Yes</div>
                    <div class="hero-note">Prior versions preserved</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Audit Readiness</div>
                    <div class="hero-value">Complete</div>
                    <div class="hero-note">Control change traceable</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Latest Ledger Entry</h2>
                <div class="ledger-card">
                    <div class="ledger-kicker">Control Change Ledger Entry</div>
                    <div class="ledger-title">CCL-2026-037 — RLS-2026-014</div>
                    <div class="ledger-note">
                        Captures the governed promotion of strengthened GCL-005 v1.3, tuned GCL-003 v1.1,
                        and the controlled retirement of GCL-009 after formal optimization and release review.
                    </div>

                    <div class="ledger-meta">
                        <div class="meta-card">
                            <div class="meta-label">Release Package</div>
                            <div class="meta-value">RLS-2026-014</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Primary Change</div>
                            <div class="meta-value">GCL-005 v1.2 → v1.3</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Approved By</div>
                            <div class="meta-value">Governance Review Board</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Ledger Date</div>
                            <div class="meta-value">2026-05-09</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Integrity Proof</h2>
                <div class="integrity-box">
                    <div class="integrity-label">Entry Hash</div>
                    <div class="integrity-value">
                        37d48b2e8fa3c98d0af6f8d1257e4a91b3cc7df40d7b2ea9f114c8b4f2059a61
                    </div>
                    <div class="integrity-label">Previous Hash</div>
                    <div class="integrity-value">
                        8ac229d7b0f4e6a13dc849c2052b76f0eb1a55c3d9f17ac667b4e6f98701c245
                    </div>
                    <div class="integrity-label">Ledger Anchor</div>
                    <div class="integrity-value">
                        ACL-TX-20260509-CCL2026037-BE7A41D9
                    </div>
                    <div class="verify-row">
                        <button id="verifyBtn" class="verify-btn">Verify Ledger Entry</button>
                        <span id="verifyState" class="verify-state">Awaiting verification</span>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Control Change Lineage</h2>
            <p>
                The ledger does not record only the final version. It preserves the full reason-for-change path.
            </p>

            <div class="chain-grid">
                <div class="chain-step">
                    <div class="chain-no">1</div>
                    <h3>Effectiveness Finding</h3>
                    <p>GCL-005 missed one late release blocker in monitoring.</p>
                </div>
                <div class="chain-step">
                    <div class="chain-no">2</div>
                    <h3>Optimization</h3>
                    <p>Middleware confirmation added in the Optimization Workbench.</p>
                </div>
                <div class="chain-step">
                    <div class="chain-no">3</div>
                    <h3>Release Package</h3>
                    <p>RLS-2026-014 bundled the approved improved controls.</p>
                </div>
                <div class="chain-step">
                    <div class="chain-no">4</div>
                    <h3>Approval</h3>
                    <p>Governance Review Board authorized promotion and retirement.</p>
                </div>
                <div class="chain-step">
                    <div class="chain-no">5</div>
                    <h3>Ledger Entry</h3>
                    <p>CCL-2026-037 sealed the final control-environment change.</p>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Control Change Register</h2>
            <p>
                Searchable history of changes to the control environment itself.
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Changes</button>
                <button class="filter-btn" data-filter="strengthen">Strengthen</button>
                <button class="filter-btn" data-filter="tune">Tune</button>
                <button class="filter-btn" data-filter="retire">Retire</button>
                <button class="filter-btn" data-filter="publish">Publish</button>
                <input id="searchInput" class="search" type="text" placeholder="Search ledger entry, control, release package, or approver...">
            </div>

            <table id="ledgerTable">
                <thead>
                    <tr>
                        <th>Ledger Entry</th>
                        <th>Control</th>
                        <th>Change Type</th>
                        <th>Version Change</th>
                        <th>Reason</th>
                        <th>Release Package</th>
                        <th>Approver</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-type="strengthen" data-search="ccl-2026-037 gcl-005 downstream release confirmation strengthen v1.2 v1.3 rls-2026-014 governance review board">
                        <td>CCL-2026-037</td>
                        <td>GCL-005 — Downstream Release Confirmation</td>
                        <td><span class="pill red">Strengthen</span></td>
                        <td>v1.2 → v1.3</td>
                        <td>Missed one middleware-linked blocker</td>
                        <td>RLS-2026-014</td>
                        <td>Governance Review Board</td>
                        <td><span class="pill green">Sealed</span></td>
                    </tr>
                    <tr data-type="tune" data-search="ccl-2026-036 gcl-003 release-sensitive record reconciliation tune v1.0 v1.1 rls-2026-014 qa systems">
                        <td>CCL-2026-036</td>
                        <td>GCL-003 — Release-Sensitive Record Reconciliation</td>
                        <td><span class="pill amber">Tune</span></td>
                        <td>v1.0 → v1.1</td>
                        <td>Reduce avoidable false positives</td>
                        <td>RLS-2026-014</td>
                        <td>QA Systems</td>
                        <td><span class="pill green">Sealed</span></td>
                    </tr>
                    <tr data-type="retire" data-search="ccl-2026-035 gcl-009 legacy closure reminder retire rls-2026-014 closure integrity">
                        <td>CCL-2026-035</td>
                        <td>GCL-009 — Legacy Closure Reminder</td>
                        <td><span class="pill blue">Retire</span></td>
                        <td>v1.0 → Retired</td>
                        <td>Superseded by stronger controls</td>
                        <td>RLS-2026-014</td>
                        <td>Governance Review Board</td>
                        <td><span class="pill green">Sealed</span></td>
                    </tr>
                    <tr data-type="publish" data-search="ccl-2026-034 gcl-006 privileged account owner review publish v2.1 v2.2 rls-2026-016 it security">
                        <td>CCL-2026-034</td>
                        <td>GCL-006 — Privileged Account Owner Review</td>
                        <td><span class="pill indigo">Publish</span></td>
                        <td>v2.1 → v2.2</td>
                        <td>Access-review noise reduction</td>
                        <td>RLS-2026-016</td>
                        <td>IT Security</td>
                        <td><span class="pill green">Sealed</span></td>
                    </tr>
                    <tr data-type="strengthen" data-search="ccl-2026-033 gcl-008 erp mes lims release chain strengthen v0.9 v1.0 rls-2026-015 blocked">
                        <td>CCL-2026-033</td>
                        <td>GCL-008 — ERP → MES → LIMS Release Chain</td>
                        <td><span class="pill red">Strengthen</span></td>
                        <td>v0.9 → v1.0</td>
                        <td>Coverage gap in batch-disposition chain</td>
                        <td>RLS-2026-015</td>
                        <td>Pending</td>
                        <td><span class="pill amber">Pending</span></td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Approval Chain</h2>
                <div class="approval-grid">
                    <div class="approval-card">
                        <div class="approval-role">Control Owner</div>
                        <div class="approval-name">QC Governance</div>
                        <div class="approval-note">
                            Confirmed strengthened release logic was necessary after missed-risk evidence.
                        </div>
                    </div>
                    <div class="approval-card">
                        <div class="approval-role">QA Reviewer</div>
                        <div class="approval-name">QA Systems</div>
                        <div class="approval-note">
                            Reviewed risk impact, false-positive change, and validation evidence.
                        </div>
                    </div>
                    <div class="approval-card">
                        <div class="approval-role">Release Authority</div>
                        <div class="approval-name">Governance Review Board</div>
                        <div class="approval-note">
                            Approved package-level promotion, tuning, and retirement decision.
                        </div>
                    </div>
                    <div class="approval-card">
                        <div class="approval-role">Ledger Authority</div>
                        <div class="approval-name">AssuranceLayer™</div>
                        <div class="approval-note">
                            Sealed the final change record and preserved the integrity chain.
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Version History Snapshot</h2>
                <div class="version-grid">
                    <div class="version-item">
                        <div class="version-tag">v1.3</div>
                        <div>
                            <div class="version-title">GCL-005 strengthened</div>
                            <div class="version-note">
                                Added middleware event confirmation after one missed release blocker.
                            </div>
                        </div>
                        <div class="version-date">May 2026</div>
                    </div>
                    <div class="version-item">
                        <div class="version-tag">v1.2</div>
                        <div>
                            <div class="version-title">GCL-005 prior active version</div>
                            <div class="version-note">
                                Preserved as rollback-ready baseline before release package RLS-2026-014.
                            </div>
                        </div>
                        <div class="version-date">Apr 2026</div>
                    </div>
                    <div class="version-item">
                        <div class="version-tag">v1.1</div>
                        <div>
                            <div class="version-title">GCL-005 initial refinement</div>
                            <div class="version-note">
                                Expanded downstream confirmation to LIS-linked release dependencies.
                            </div>
                        </div>
                        <div class="version-date">Mar 2026</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Control Change Inspector</h2>
            <p>
                Select a ledger entry to inspect the governance logic behind the change.
            </p>

            <div class="inspector">
                <div class="inspector-list">
                    <button class="inspect-btn active" data-entry="strengthen">
                        <div class="inspect-kicker">CCL-2026-037</div>
                        <div class="inspect-title">GCL-005 Strengthened</div>
                        <div class="inspect-note">Missed-risk gap closed through middleware confirmation.</div>
                    </button>
                    <button class="inspect-btn" data-entry="tune">
                        <div class="inspect-kicker">CCL-2026-036</div>
                        <div class="inspect-title">GCL-003 Tuned</div>
                        <div class="inspect-note">False-positive burden reduced through threshold refinement.</div>
                    </button>
                    <button class="inspect-btn" data-entry="retire">
                        <div class="inspect-kicker">CCL-2026-035</div>
                        <div class="inspect-title">GCL-009 Retired</div>
                        <div class="inspect-note">Low-value legacy logic removed after supersession.</div>
                    </button>
                    <button class="inspect-btn" data-entry="publish">
                        <div class="inspect-kicker">CCL-2026-034</div>
                        <div class="inspect-title">GCL-006 Republished</div>
                        <div class="inspect-note">Access-governance review control versioned after tuning.</div>
                    </button>
                </div>

                <div class="inspector-card">
                    <div class="inspector-label">Selected Ledger Entry</div>
                    <div id="inspectorTitle" class="inspector-title">GCL-005 Strengthened</div>
                    <div class="inspector-meta">
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Ledger Entry</div>
                            <div id="inspectorEntry" class="inspector-mini-value">CCL-2026-037</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Version Change</div>
                            <div id="inspectorVersion" class="inspector-mini-value">v1.2 → v1.3</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Release Package</div>
                            <div id="inspectorRelease" class="inspector-mini-value">RLS-2026-014</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Decision</div>
                            <div id="inspectorDecision" class="inspector-mini-value">Strengthen</div>
                        </div>
                    </div>
                    <div id="inspectorChange" class="inspector-change">
                        Added middleware event confirmation before downstream release is accepted as complete.
                    </div>
                    <div id="inspectorNote" class="inspector-note">
                        The change was justified by one missed release blocker observed in the Control Effectiveness Monitor™ and approved through the Release Orchestrator™.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Ledger Coverage Map</h2>
                <div class="ledger-map">
                    <div class="map-card">
                        <div class="map-title">Rule Origin</div>
                        <div class="map-note">
                            Each change traces back to a lesson, effectiveness finding, or governance need.
                        </div>
                        <div class="map-state">Traceable</div>
                    </div>
                    <div class="map-card">
                        <div class="map-title">Version Change</div>
                        <div class="map-note">
                            Prior and replacement versions are preserved for audit and rollback.
                        </div>
                        <div class="map-state">Versioned</div>
                    </div>
                    <div class="map-card">
                        <div class="map-title">Approval Logic</div>
                        <div class="map-note">
                            Control-owner and governance-board decisions are linked to the change.
                        </div>
                        <div class="map-state">Approved</div>
                    </div>
                    <div class="map-card">
                        <div class="map-title">Integrity Proof</div>
                        <div class="map-note">
                            Entry hash, previous hash, and ledger anchor preserve tamper evidence.
                        </div>
                        <div class="map-state">Sealed</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Why This Matters</h2>
                <p>
                    In a mature control environment, it is not enough to know what the current rule is.
                    You must be able to show <strong>how it became that rule</strong>, what evidence justified the change,
                    who authorized it, and what historical version it replaced.
                </p>
                <p>
                    That is what makes the control environment itself auditable rather than informal.
                </p>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Ledger Action Console</h2>
            <p>
                The ledger can be queried, verified, and used to prove the governed history of the control environment.
            </p>

            <div class="action-console">
                <div class="action-list">
                    <div class="action-item">
                        <div>
                            <h3>Verify latest ledger entry</h3>
                            <p>Confirm that CCL-2026-037 still matches the stored integrity chain.</p>
                        </div>
                        <button class="action-btn" data-action="verify">Verify</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Trace release package lineage</h3>
                            <p>Show how RLS-2026-014 linked optimization, approval, and final ledger seal.</p>
                        </div>
                        <button class="action-btn" data-action="trace">Trace</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Retrieve rollback baseline</h3>
                            <p>Surface the preserved prior version for GCL-005 before v1.3 promotion.</p>
                        </div>
                        <button class="action-btn" data-action="rollback">Retrieve</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Export audit summary</h3>
                            <p>Prepare the governed history of the latest control-change bundle for review.</p>
                        </div>
                        <button class="action-btn" data-action="export">Export</button>
                    </div>
                </div>

                <div id="consoleResult" class="console-result">
                    <div class="console-label">Ledger Outcome</div>
                    <div id="consoleTitle" class="console-title">Awaiting Action</div>
                    <div id="consoleNote" class="console-note">
                        Select an action to see how control-change history remains provable after deployment.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>Release Orchestrator</h3>
                <p>
                    Moves improved control logic into live use under governed release discipline.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Change Ledger</h3>
                <p>
                    Preserves the immutable history of how the control environment changed.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    COBIT-Chain™ governs not only business evidence, but the evidence of its own governance controls.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by the Change Ledger</h2>
            <p>
                The Governance Control Release Orchestrator™ answers: <strong>“How do we safely deploy an improved control?”</strong>
            </p>
            <p>
                The Governance Control Change Ledger™ answers: <strong>“Can we prove exactly how and why the control environment changed?”</strong>
            </p>
            <p>
                That is a major enterprise distinction. The platform now shows a complete lifecycle where governance controls are
                learned, designed, approved, monitored, optimized, released, and then permanently recorded with traceability and
                tamper-evident proof.
            </p>
            <div class="footer-note">
                Simulation chain: pain point detection → dependency validation → reconciliation → decision intelligence →
                Governance Passport™ → Governance Assurance Register™ → Governance Intervention Workbench™ →
                Governance Re-Closure Gate™ → Governance Closure Certificate™ → Governance Learning Loop™ →
                Governance Rule Factory™ → Governance Control Library™ → Governance Control Effectiveness Monitor™ →
                Governance Control Optimization Workbench™ → Governance Control Release Orchestrator™ →
                Governance Control Change Ledger™.
            </div>
        </section>
    </div>

    <script>
        const verifyBtn = document.getElementById("verifyBtn");
        const verifyState = document.getElementById("verifyState");

        verifyBtn.addEventListener("click", () => {
            verifyState.textContent = "Verified — entry hash matches prior chain and ledger anchor";
            verifyState.style.background = "rgba(16,185,129,.18)";
            verifyState.style.color = "#d1fae5";
        });

        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#ledgerTable tbody tr");
        const searchInput = document.getElementById("searchInput");
        let activeFilter = "all";

        function applyFilters() {
            const query = searchInput.value.toLowerCase().trim();

            rows.forEach(row => {
                const type = row.dataset.type;
                const searchable = row.dataset.search;
                const matchesFilter = activeFilter === "all" || type === activeFilter;
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
        const inspectorEntry = document.getElementById("inspectorEntry");
        const inspectorVersion = document.getElementById("inspectorVersion");
        const inspectorRelease = document.getElementById("inspectorRelease");
        const inspectorDecision = document.getElementById("inspectorDecision");
        const inspectorChange = document.getElementById("inspectorChange");
        const inspectorNote = document.getElementById("inspectorNote");

        const entries = {
            strengthen: {
                title: "GCL-005 Strengthened",
                entry: "CCL-2026-037",
                version: "v1.2 → v1.3",
                release: "RLS-2026-014",
                decision: "Strengthen",
                change: "Added middleware event confirmation before downstream release is accepted as complete.",
                note: "The change was justified by one missed release blocker observed in the Control Effectiveness Monitor™ and approved through the Release Orchestrator™."
            },
            tune: {
                title: "GCL-003 Tuned",
                entry: "CCL-2026-036",
                version: "v1.0 → v1.1",
                release: "RLS-2026-014",
                decision: "Tune",
                change: "Adjusted the reconciliation threshold to ignore low-risk cosmetic differences and escalate material mismatches.",
                note: "The change reduced avoidable false positives while preserving the control’s ability to detect true release-sensitive breaks."
            },
            retire: {
                title: "GCL-009 Retired",
                entry: "CCL-2026-035",
                version: "v1.0 → Retired",
                release: "RLS-2026-014",
                decision: "Retire",
                change: "Removed a duplicated low-value reminder control after stronger closure controls became active.",
                note: "The retirement was governed, not accidental: it was approved after proving that the legacy rule no longer added unique assurance value."
            },
            publish: {
                title: "GCL-006 Republished",
                entry: "CCL-2026-034",
                version: "v2.1 → v2.2",
                release: "RLS-2026-016",
                decision: "Publish",
                change: "Republished privileged-account owner review logic with a narrower, lower-noise trigger set.",
                note: "This version retained access-governance value while reducing unnecessary review burden."
            }
        };

        inspectButtons.forEach(button => {
            button.addEventListener("click", () => {
                inspectButtons.forEach(btn => btn.classList.remove("active"));
                button.classList.add("active");

                const entry = entries[button.dataset.entry];
                inspectorTitle.textContent = entry.title;
                inspectorEntry.textContent = entry.entry;
                inspectorVersion.textContent = entry.version;
                inspectorRelease.textContent = entry.release;
                inspectorDecision.textContent = entry.decision;
                inspectorChange.textContent = entry.change;
                inspectorNote.textContent = entry.note;
            });
        });

        const actionButtons = document.querySelectorAll(".action-btn");
        const consoleResult = document.getElementById("consoleResult");
        const consoleTitle = document.getElementById("consoleTitle");
        const consoleNote = document.getElementById("consoleNote");

        const outcomes = {
            verify: {
                title: "Latest Entry Verified",
                note: "CCL-2026-037 matches the stored hash chain, prior entry, and ledger anchor."
            },
            trace: {
                title: "Release Lineage Traced",
                note: "RLS-2026-014 is linked from optimization finding through approval, deployment, and final ledger seal."
            },
            rollback: {
                title: "Rollback Baseline Retrieved",
                note: "GCL-005 v1.2 is preserved as the approved fallback version before v1.3 promotion."
            },
            export: {
                title: "Audit Summary Prepared",
                note: "The latest control-change bundle is ready for review with rationale, approvals, versions, and integrity proof."
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
        print("SKIP: GOVERNANCE_CONTROL_CHANGE_LEDGER_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/governance-control-change-ledger")',
        "Governance Control Change Ledger™",
        "Control Change Register",
        "Control Change Inspector",
        "Ledger Action Console",
        "Verified — entry hash matches prior chain and ledger anchor",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /governance-control-change-ledger route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
