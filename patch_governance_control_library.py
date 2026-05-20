from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# GOVERNANCE_CONTROL_LIBRARY_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# GOVERNANCE_CONTROL_LIBRARY_ACTIVE
@app.route("/governance-control-library")
def governance_control_library_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Governance Control Library™ | COBIT-Chain™ / AssuranceLayer™</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #f4f7fb;
            color: #172033;
        }
        .shell {
            max-width: 1440px;
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
            background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 48%, #0f766e 100%);
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
            max-width: 1080px;
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
        .library-summary {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .summary-card {
            border-radius: 20px;
            padding: 18px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .summary-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .summary-card.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .summary-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .summary-card.indigo {
            background: #eef2ff;
            border-color: #c7d2fe;
        }
        .summary-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .summary-value {
            font-size: 28px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .summary-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
        }
        .family-grid {
            display: grid;
            gap: 12px;
        }
        .family-row {
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .family-top {
            display: flex;
            justify-content: space-between;
            gap: 14px;
            align-items: center;
            margin-bottom: 10px;
        }
        .family-title {
            font-weight: 900;
        }
        .family-count {
            font-size: 13px;
            font-weight: 900;
            color: #1d4ed8;
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
            background: linear-gradient(90deg, #2563eb 0%, #0f766e 100%);
        }
        .family-note {
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
            min-width: 320px;
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
        .pill.blue {
            background: #dbeafe;
            color: #1d4ed8;
        }
        .pill.amber {
            background: #fef3c7;
            color: #92400e;
        }
        .pill.indigo {
            background: #e0e7ff;
            color: #3730a3;
        }
        .deployment-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .deployment-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .deployment-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .deployment-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
            margin-bottom: 11px;
        }
        .deployment-state {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            background: #dbeafe;
            color: #1d4ed8;
            font-size: 12px;
            font-weight: 900;
        }
        .version-grid {
            display: grid;
            gap: 12px;
        }
        .version-item {
            display: grid;
            grid-template-columns: 86px 1fr auto;
            gap: 14px;
            align-items: start;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .version-tag {
            border-radius: 14px;
            background: #173f86;
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
        .lineage-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 12px;
        }
        .lineage-step {
            border-radius: 18px;
            padding: 16px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .lineage-no {
            width: 32px;
            height: 32px;
            border-radius: 11px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #173f86;
            color: #fff;
            font-weight: 900;
            margin-bottom: 12px;
        }
        .lineage-step h3 {
            margin: 0 0 8px;
            font-size: 16px;
        }
        .lineage-step p {
            margin: 0;
            font-size: 14px;
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
            font-size: 28px;
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
        .inspector-rule {
            background: rgba(255,255,255,.76);
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
        .maturity-card {
            border-left: 5px solid #173f86;
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
        @media (max-width: 1240px) {
            .hero-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .grid-2,
            .grid-3,
            .inspector {
                grid-template-columns: 1fr;
            }
            .library-summary,
            .deployment-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
            .lineage-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .library-summary,
            .deployment-grid,
            .lineage-grid,
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
                <a href="/governance-rule-factory">Rule Factory</a>
                <a href="/governance-learning-loop">Learning Loop</a>
                <a href="/governance-assurance-register">Assurance Register</a>
                <a href="/governance-decision-engine">Decision Engine</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Living Enterprise Control Repository</div>
            <h1>Governance Control Library™</h1>
            <p>
                The governed repository where approved rules become durable enterprise controls.
                The library shows what each control does, where it came from, which systems and workflows it protects,
                how it is versioned, and where it is currently deployed across the AssuranceLayer™ environment.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Active Controls</div>
                    <div class="hero-value">24</div>
                    <div class="hero-note">Approved and available</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Published This Cycle</div>
                    <div class="hero-value">4</div>
                    <div class="hero-note">From recent learning patterns</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Source Certificates</div>
                    <div class="hero-value">11</div>
                    <div class="hero-note">Learning-backed lineage</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Control Families</div>
                    <div class="hero-value">6</div>
                    <div class="hero-note">Closure, access, release, audit...</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Deployed Layers</div>
                    <div class="hero-value">7</div>
                    <div class="hero-note">Across the platform</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Versioned</div>
                    <div class="hero-value">100%</div>
                    <div class="hero-note">Auditable control history</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Library Overview</h2>
                <p>
                    The library makes the platform look less like a collection of smart one-off features and more like a
                    governed control environment. Every approved rule has a source lesson, ownership, deployment scope,
                    version, and audit lineage.
                </p>

                <div class="library-summary">
                    <div class="summary-card green">
                        <div class="summary-label">Release Controls</div>
                        <div class="summary-value">7</div>
                        <div class="summary-note">Batch disposition and QC release protection.</div>
                    </div>
                    <div class="summary-card blue">
                        <div class="summary-label">Access Controls</div>
                        <div class="summary-value">5</div>
                        <div class="summary-note">Role approvals, entitlements, and privileged drift.</div>
                    </div>
                    <div class="summary-card amber">
                        <div class="summary-label">Reconciliation Controls</div>
                        <div class="summary-value">6</div>
                        <div class="summary-note">Cross-system truth alignment and mismatch handling.</div>
                    </div>
                    <div class="summary-card indigo">
                        <div class="summary-label">Closure Controls</div>
                        <div class="summary-value">6</div>
                        <div class="summary-note">False closure prevention and re-closure discipline.</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Control Family Coverage</h2>
                <div class="family-grid">
                    <div class="family-row">
                        <div class="family-top">
                            <div class="family-title">Release Assurance</div>
                            <div class="family-count">7 controls</div>
                        </div>
                        <div class="bar"><div class="bar-fill" style="width: 92%;"></div></div>
                        <div class="family-note">Strongest coverage: batch disposition, CAPA dependency, LIS confirmation.</div>
                    </div>
                    <div class="family-row">
                        <div class="family-top">
                            <div class="family-title">Access Governance</div>
                            <div class="family-count">5 controls</div>
                        </div>
                        <div class="bar"><div class="bar-fill" style="width: 76%;"></div></div>
                        <div class="family-note">Covers request, approval, granted role, and privileged-account drift.</div>
                    </div>
                    <div class="family-row">
                        <div class="family-top">
                            <div class="family-title">Cross-System Reconciliation</div>
                            <div class="family-count">6 controls</div>
                        </div>
                        <div class="bar"><div class="bar-fill" style="width: 84%;"></div></div>
                        <div class="family-note">Expanding across Veeva, Blue Mountain, ServiceNow, and myAccess.</div>
                    </div>
                    <div class="family-row">
                        <div class="family-top">
                            <div class="family-title">Closure Integrity</div>
                            <div class="family-count">6 controls</div>
                        </div>
                        <div class="bar"><div class="bar-fill" style="width: 88%;"></div></div>
                        <div class="family-note">Controls false closure, re-closure gates, and final certificate issuance.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Active Control Register</h2>
            <p>
                Approved rules move out of the Rule Factory and into a durable, searchable control library.
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Controls</button>
                <button class="filter-btn" data-filter="release">Release</button>
                <button class="filter-btn" data-filter="access">Access</button>
                <button class="filter-btn" data-filter="reconciliation">Reconciliation</button>
                <button class="filter-btn" data-filter="closure">Closure</button>
                <input id="searchInput" class="search" type="text" placeholder="Search control, source lesson, system, or workflow...">
            </div>

            <table id="controlTable">
                <thead>
                    <tr>
                        <th>Control ID</th>
                        <th>Control Name</th>
                        <th>Family</th>
                        <th>Source Lesson</th>
                        <th>Target Systems</th>
                        <th>Version</th>
                        <th>Status</th>
                        <th>Deployment</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-family="closure" data-search="gcl-001 closure blocker false closure gcc-2026-001 servicenow veeva release dependency validation">
                        <td>GCL-001</td>
                        <td>Closure Blocker with Open CAPA</td>
                        <td><span class="pill indigo">Closure</span></td>
                        <td>GCC-2026-001</td>
                        <td>ServiceNow / Veeva</td>
                        <td>v1.0</td>
                        <td><span class="pill green">Active</span></td>
                        <td>Dependency Validation</td>
                    </tr>
                    <tr data-family="access" data-search="gcl-002 access truth drift role approved granted myaccess servicenow gcc-2026-001 predictive drift">
                        <td>GCL-002</td>
                        <td>Approved Role = Granted Role</td>
                        <td><span class="pill blue">Access</span></td>
                        <td>GCC-2026-001</td>
                        <td>ServiceNow / myAccess</td>
                        <td>v1.0</td>
                        <td><span class="pill green">Active</span></td>
                        <td>Predictive Drift</td>
                    </tr>
                    <tr data-family="reconciliation" data-search="gcl-003 veeva blue mountain reconciliation release sensitive closure gcc-2026-001 reconciliation layer">
                        <td>GCL-003</td>
                        <td>Release-Sensitive Record Reconciliation</td>
                        <td><span class="pill amber">Reconciliation</span></td>
                        <td>GCC-2026-001</td>
                        <td>Veeva / Blue Mountain</td>
                        <td>v1.0</td>
                        <td><span class="pill green">Active</span></td>
                        <td>Reconciliation Layer</td>
                    </tr>
                    <tr data-family="closure" data-search="gcl-004 closure certificate requirement repeat pattern watchlist assurance register governance closure certificate">
                        <td>GCL-004</td>
                        <td>Certificate Required Before Pattern Exit</td>
                        <td><span class="pill indigo">Closure</span></td>
                        <td>GCC-2026-001</td>
                        <td>Assurance Register</td>
                        <td>v1.0</td>
                        <td><span class="pill green">Active</span></td>
                        <td>Assurance Register</td>
                    </tr>
                    <tr data-family="release" data-search="gcl-005 lis middleware downstream release assurance batch disposition qc release certificate">
                        <td>GCL-005</td>
                        <td>Downstream Release Confirmation</td>
                        <td><span class="pill green">Release</span></td>
                        <td>GCC-2026-003</td>
                        <td>Middleware / LIS</td>
                        <td>v1.2</td>
                        <td><span class="pill green">Active</span></td>
                        <td>Decision Engine</td>
                    </tr>
                    <tr data-family="access" data-search="gcl-006 privileged account owner review myaccess access governance quarterly user access review">
                        <td>GCL-006</td>
                        <td>Privileged Account Owner Review</td>
                        <td><span class="pill blue">Access</span></td>
                        <td>GCC-2026-004</td>
                        <td>myAccess</td>
                        <td>v2.1</td>
                        <td><span class="pill green">Active</span></td>
                        <td>Access Governance</td>
                    </tr>
                    <tr data-family="reconciliation" data-search="gcl-007 blue mountain veeva periodic review mismatch engineering equipment review">
                        <td>GCL-007</td>
                        <td>Periodic Review Evidence Match</td>
                        <td><span class="pill amber">Reconciliation</span></td>
                        <td>GCC-2026-006</td>
                        <td>Blue Mountain / Veeva</td>
                        <td>v1.3</td>
                        <td><span class="pill blue">Pilot</span></td>
                        <td>Reconciliation Layer</td>
                    </tr>
                    <tr data-family="release" data-search="gcl-008 erp mes lims batch disposition dependency chain release assurance">
                        <td>GCL-008</td>
                        <td>ERP → MES → LIMS Release Chain</td>
                        <td><span class="pill green">Release</span></td>
                        <td>GCC-2026-008</td>
                        <td>ERP / MES / LIMS</td>
                        <td>v0.9</td>
                        <td><span class="pill amber">Review</span></td>
                        <td>Dependency Validation</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Deployment Map</h2>
                <div class="deployment-grid">
                    <div class="deployment-card">
                        <div class="deployment-title">Dependency Validation</div>
                        <div class="deployment-note">
                            Receives release blockers, CAPA logic, and downstream dependency controls.
                        </div>
                        <div class="deployment-state">5 controls deployed</div>
                    </div>
                    <div class="deployment-card">
                        <div class="deployment-title">Predictive Drift</div>
                        <div class="deployment-note">
                            Receives mismatch, recurrence, and early-warning controls.
                        </div>
                        <div class="deployment-state">4 controls deployed</div>
                    </div>
                    <div class="deployment-card">
                        <div class="deployment-title">Reconciliation Layer</div>
                        <div class="deployment-note">
                            Receives cross-system consistency and evidence-alignment controls.
                        </div>
                        <div class="deployment-state">6 controls deployed</div>
                    </div>
                    <div class="deployment-card">
                        <div class="deployment-title">Assurance Register</div>
                        <div class="deployment-note">
                            Receives watchlist, closure, and pattern-retention controls.
                        </div>
                        <div class="deployment-state">3 controls deployed</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Recent Version History</h2>
                <div class="version-grid">
                    <div class="version-item">
                        <div class="version-tag">v1.0</div>
                        <div>
                            <div class="version-title">GCL-001 published</div>
                            <div class="version-note">
                                Closure blocker added after false-closure pattern from GCC-2026-001.
                            </div>
                        </div>
                        <div class="version-date">May 2026</div>
                    </div>
                    <div class="version-item">
                        <div class="version-tag">v1.2</div>
                        <div>
                            <div class="version-title">GCL-005 strengthened</div>
                            <div class="version-note">
                                Downstream release confirmation expanded to middleware / LIS chains.
                            </div>
                        </div>
                        <div class="version-date">Apr 2026</div>
                    </div>
                    <div class="version-item">
                        <div class="version-tag">v2.1</div>
                        <div>
                            <div class="version-title">GCL-006 revised</div>
                            <div class="version-note">
                                Privileged account owner review rule updated after myAccess edge-case discovery.
                            </div>
                        </div>
                        <div class="version-date">Mar 2026</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Control Lineage</h2>
            <p>
                Every active control can be traced backward to its governance origin and forward to where it now acts.
            </p>

            <div class="lineage-grid">
                <div class="lineage-step">
                    <div class="lineage-no">1</div>
                    <h3>Failure Pattern</h3>
                    <p>False closure detected in a release-sensitive workflow.</p>
                </div>
                <div class="lineage-step">
                    <div class="lineage-no">2</div>
                    <h3>Certificate</h3>
                    <p>GCC-2026-001 proves the repaired end state.</p>
                </div>
                <div class="lineage-step">
                    <div class="lineage-no">3</div>
                    <h3>Learning</h3>
                    <p>The Learning Loop extracts “local closure ≠ enterprise truth.”</p>
                </div>
                <div class="lineage-step">
                    <div class="lineage-no">4</div>
                    <h3>Rule</h3>
                    <p>The Rule Factory creates closure-blocker logic.</p>
                </div>
                <div class="lineage-step">
                    <div class="lineage-no">5</div>
                    <h3>Library</h3>
                    <p>The approved rule becomes a reusable active control.</p>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Control Inspector</h2>
            <p>
                Select a control to inspect its source, logic, deployment, and governance purpose.
            </p>

            <div class="inspector">
                <div class="inspector-list">
                    <button class="inspect-btn active" data-control="closure">
                        <div class="inspect-kicker">GCL-001</div>
                        <div class="inspect-title">Closure Blocker with Open CAPA</div>
                        <div class="inspect-note">Prevents false closure on release-sensitive records.</div>
                    </button>
                    <button class="inspect-btn" data-control="access">
                        <div class="inspect-kicker">GCL-002</div>
                        <div class="inspect-title">Approved Role = Granted Role</div>
                        <div class="inspect-note">Detects privileged-access evidence drift.</div>
                    </button>
                    <button class="inspect-btn" data-control="reconciliation">
                        <div class="inspect-kicker">GCL-003</div>
                        <div class="inspect-title">Release-Sensitive Record Reconciliation</div>
                        <div class="inspect-note">Requires Veeva ↔ Blue Mountain truth alignment.</div>
                    </button>
                    <button class="inspect-btn" data-control="certificate">
                        <div class="inspect-kicker">GCL-004</div>
                        <div class="inspect-title">Certificate Required Before Pattern Exit</div>
                        <div class="inspect-note">Keeps repeat-pattern cases active until fully certified.</div>
                    </button>
                </div>

                <div class="inspector-card">
                    <div class="inspector-label">Selected Control</div>
                    <div id="inspectorTitle" class="inspector-title">Closure Blocker with Open CAPA</div>
                    <div class="inspector-meta">
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Source Lesson</div>
                            <div id="inspectorSource" class="inspector-mini-value">GCC-2026-001</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Deployment</div>
                            <div id="inspectorDeployment" class="inspector-mini-value">Dependency Validation</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Family</div>
                            <div id="inspectorFamily" class="inspector-mini-value">Closure Integrity</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Version</div>
                            <div id="inspectorVersion" class="inspector-mini-value">v1.0</div>
                        </div>
                    </div>
                    <div id="inspectorRule" class="inspector-rule">
                        When a release-sensitive workflow is marked closed, if a linked CAPA remains open, block closure and route to QA review.
                    </div>
                    <div id="inspectorNote" class="inspector-note">
                        This control was promoted after GCC-2026-001 proved that a locally closed workflow can still be unsafe at enterprise level.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>Rule Factory</h3>
                <p>
                    Produces candidate preventive controls from learned patterns.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Control Library</h3>
                <p>
                    Stores the approved controls with source, scope, deployment, and version lineage.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    COBIT-Chain™ now grows a governed control environment, not just a set of screens.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by the Control Library</h2>
            <p>
                The Governance Rule Factory™ answers: <strong>“How is a lesson converted into a control?”</strong>
            </p>
            <p>
                The Governance Control Library™ answers: <strong>“Where do approved controls live, how are they governed, and where are they active?”</strong>
            </p>
            <p>
                That gives the platform enterprise seriousness. It shows that learned controls are not temporary ideas;
                they are versioned, auditable, deployable assets that become part of the organization's living governance architecture.
            </p>
            <div class="footer-note">
                Simulation chain: pain point detection → dependency validation → reconciliation → decision intelligence →
                Governance Passport™ → Governance Assurance Register™ → Governance Intervention Workbench™ →
                Governance Re-Closure Gate™ → Governance Closure Certificate™ → Governance Learning Loop™ →
                Governance Rule Factory™ → Governance Control Library™.
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#controlTable tbody tr");
        const searchInput = document.getElementById("searchInput");
        let activeFilter = "all";

        function applyFilters() {
            const query = searchInput.value.toLowerCase().trim();

            rows.forEach(row => {
                const family = row.dataset.family;
                const searchable = row.dataset.search;
                const matchesFilter = activeFilter === "all" || family === activeFilter;
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
        const inspectorSource = document.getElementById("inspectorSource");
        const inspectorDeployment = document.getElementById("inspectorDeployment");
        const inspectorFamily = document.getElementById("inspectorFamily");
        const inspectorVersion = document.getElementById("inspectorVersion");
        const inspectorRule = document.getElementById("inspectorRule");
        const inspectorNote = document.getElementById("inspectorNote");

        const controls = {
            closure: {
                title: "Closure Blocker with Open CAPA",
                source: "GCC-2026-001",
                deployment: "Dependency Validation",
                family: "Closure Integrity",
                version: "v1.0",
                rule: "When a release-sensitive workflow is marked closed, if a linked CAPA remains open, block closure and route to QA review.",
                note: "This control was promoted after GCC-2026-001 proved that a locally closed workflow can still be unsafe at enterprise level."
            },
            access: {
                title: "Approved Role = Granted Role",
                source: "GCC-2026-001",
                deployment: "Predictive Drift",
                family: "Access Governance",
                version: "v1.0",
                rule: "When a privileged role change is processed, if the approved role does not match the granted role, raise a drift alert and require evidence reconciliation.",
                note: "This control reduces privileged-access ambiguity by forcing the approved and actual entitlement states to agree."
            },
            reconciliation: {
                title: "Release-Sensitive Record Reconciliation",
                source: "GCC-2026-001",
                deployment: "Reconciliation Layer",
                family: "Cross-System Truth",
                version: "v1.0",
                rule: "Before release-sensitive re-closure, require Veeva and Blue Mountain records to resolve to one consistent governed state.",
                note: "This control prevents operational decisions from being made while document truth and equipment truth remain split."
            },
            certificate: {
                title: "Certificate Required Before Pattern Exit",
                source: "GCC-2026-001",
                deployment: "Assurance Register",
                family: "Closure Integrity",
                version: "v1.0",
                rule: "When a repeat-pattern case is remediated, keep it active until a Governance Closure Certificate™ is issued.",
                note: "This control prevents risky cases from disappearing from oversight merely because local tasks were completed."
            }
        };

        inspectButtons.forEach(button => {
            button.addEventListener("click", () => {
                inspectButtons.forEach(btn => btn.classList.remove("active"));
                button.classList.add("active");

                const control = controls[button.dataset.control];
                inspectorTitle.textContent = control.title;
                inspectorSource.textContent = control.source;
                inspectorDeployment.textContent = control.deployment;
                inspectorFamily.textContent = control.family;
                inspectorVersion.textContent = control.version;
                inspectorRule.textContent = control.rule;
                inspectorNote.textContent = control.note;
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
        print("SKIP: GOVERNANCE_CONTROL_LIBRARY_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/governance-control-library")',
        "Governance Control Library™",
        "Active Control Register",
        "Control Lineage",
        "Control Inspector",
        "Closure Blocker with Open CAPA",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /governance-control-library route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
