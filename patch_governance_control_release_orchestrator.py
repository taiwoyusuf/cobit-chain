from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# GOVERNANCE_CONTROL_RELEASE_ORCHESTRATOR_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# GOVERNANCE_CONTROL_RELEASE_ORCHESTRATOR_ACTIVE
@app.route("/governance-control-release-orchestrator")
def governance_control_release_orchestrator_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Governance Control Release Orchestrator™ | COBIT-Chain™ / AssuranceLayer™</title>
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
            background: linear-gradient(135deg, #111827 0%, #1d4ed8 48%, #0f766e 100%);
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
        .release-card {
            border-radius: 22px;
            padding: 20px;
            background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
            border: 1px solid #dbe7f8;
        }
        .release-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #1d4ed8;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .release-title {
            font-size: 24px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .release-note {
            color: #4c5b73;
            line-height: 1.55;
            margin-bottom: 16px;
        }
        .release-meta {
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
        .release-readiness {
            display: grid;
            gap: 12px;
        }
        .readiness-row {
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .readiness-top {
            display: flex;
            justify-content: space-between;
            gap: 14px;
            align-items: center;
            margin-bottom: 10px;
        }
        .readiness-title {
            font-weight: 900;
        }
        .readiness-value {
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
        .bar-fill.blue {
            background: linear-gradient(90deg, #2563eb 0%, #38bdf8 100%);
        }
        .bar-fill.amber {
            background: linear-gradient(90deg, #d97706 0%, #f59e0b 100%);
        }
        .readiness-note {
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
        .gate-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .gate-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .gate-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .gate-card.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .gate-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .gate-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .gate-status {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
            margin-bottom: 10px;
        }
        .gate-status.green {
            background: #dcfce7;
            color: #166534;
        }
        .gate-status.blue {
            background: #dbeafe;
            color: #1d4ed8;
        }
        .gate-status.amber {
            background: #fef3c7;
            color: #92400e;
        }
        .gate-note {
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
        .map-grid {
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
            background: #dbeafe;
            color: #1d4ed8;
            font-size: 12px;
            font-weight: 900;
        }
        .rollout {
            display: grid;
            gap: 12px;
        }
        .rollout-item {
            display: grid;
            grid-template-columns: 70px 1fr auto;
            gap: 14px;
            align-items: start;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .rollout-wave {
            border-radius: 14px;
            background: #1d4ed8;
            color: #fff;
            padding: 10px;
            text-align: center;
            font-weight: 900;
        }
        .rollout-title {
            font-weight: 900;
            margin-bottom: 5px;
        }
        .rollout-note {
            color: #53637b;
            line-height: 1.45;
            font-size: 14px;
        }
        .rollout-state {
            font-size: 12px;
            color: #64748b;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: .05em;
            text-align: right;
        }
        .builder {
            display: grid;
            grid-template-columns: 1fr .9fr;
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
            background: #eff6ff;
            border: 1px solid #bfdbfe;
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
            color: #1d4ed8;
            margin-bottom: 10px;
        }
        .builder-plan {
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
        .rollback-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .rollback-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .rollback-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .rollback-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .rollback-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .rollback-value {
            font-size: 26px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .rollback-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
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
            .action-console {
                grid-template-columns: 1fr;
            }
            .workflow {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .gate-grid,
            .map-grid,
            .rollback-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .workflow,
            .gate-grid,
            .map-grid,
            .rollback-grid,
            .release-meta,
            .builder-meta {
                grid-template-columns: 1fr;
            }
            .search {
                margin-left: 0;
                width: 100%;
                min-width: 0;
            }
            .rollout-item {
                grid-template-columns: 1fr;
            }
            .rollout-state {
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
                <a href="/governance-control-optimization-workbench">Optimization Workbench</a>
                <a href="/governance-control-library">Control Library</a>
                <a href="/governance-control-effectiveness-monitor">Effectiveness Monitor</a>
                <a href="/governance-rule-factory">Rule Factory</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Governed Control Deployment Layer</div>
            <h1>Governance Control Release Orchestrator™</h1>
            <p>
                The formal release layer for optimized control logic. Once a control has been tuned, strengthened,
                redesigned, or approved for redeployment, the orchestrator validates the version, confirms affected modules,
                sequences rollout, preserves rollback readiness, and only then promotes the control into live enterprise use.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Release Package</div>
                    <div class="hero-value">RLS-2026-014</div>
                    <div class="hero-note">Optimized control bundle</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Controls Included</div>
                    <div class="hero-value">3</div>
                    <div class="hero-note">Strengthen / tune / retire</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Release Readiness</div>
                    <div class="hero-value">92%</div>
                    <div class="hero-note">All major gates cleared</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Affected Modules</div>
                    <div class="hero-value">4</div>
                    <div class="hero-note">Dependency, drift, library, register</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Rollback Ready</div>
                    <div class="hero-value">Yes</div>
                    <div class="hero-note">Previous versions preserved</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Release State</div>
                    <div class="hero-value">Staged</div>
                    <div class="hero-note">Awaiting promotion</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Selected Release Package</h2>
                <div class="release-card">
                    <div class="release-kicker">Controlled Release</div>
                    <div class="release-title">RLS-2026-014 — Control Optimization Bundle</div>
                    <div class="release-note">
                        This package moves the strengthened GCL-005 downstream-release rule, the tuned GCL-003
                        reconciliation rule, and the controlled retirement of GCL-009 into the governed release path.
                    </div>

                    <div class="release-meta">
                        <div class="meta-card">
                            <div class="meta-label">Primary Change</div>
                            <div class="meta-value">GCL-005 v1.3</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Secondary Change</div>
                            <div class="meta-value">GCL-003 v1.1</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Retired Control</div>
                            <div class="meta-value">GCL-009</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Release Owner</div>
                            <div class="meta-value">Governance Review Board</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Release Readiness</h2>
                <div class="release-readiness">
                    <div class="readiness-row">
                        <div class="readiness-top">
                            <div class="readiness-title">Design Validation</div>
                            <div class="readiness-value">100%</div>
                        </div>
                        <div class="bar"><div class="bar-fill green" style="width: 100%;"></div></div>
                        <div class="readiness-note">Optimization rationale, impact model, and control lineage complete.</div>
                    </div>
                    <div class="readiness-row">
                        <div class="readiness-top">
                            <div class="readiness-title">Approval Coverage</div>
                            <div class="readiness-value">100%</div>
                        </div>
                        <div class="bar"><div class="bar-fill green" style="width: 100%;"></div></div>
                        <div class="readiness-note">Required QA, governance, and control-owner approvals obtained.</div>
                    </div>
                    <div class="readiness-row">
                        <div class="readiness-top">
                            <div class="readiness-title">Deployment Preparation</div>
                            <div class="readiness-value">88%</div>
                        </div>
                        <div class="bar"><div class="bar-fill blue" style="width: 88%;"></div></div>
                        <div class="readiness-note">Wave plan complete; final dependency-map confirmation pending.</div>
                    </div>
                    <div class="readiness-row">
                        <div class="readiness-top">
                            <div class="readiness-title">Rollback Readiness</div>
                            <div class="readiness-value">80%</div>
                        </div>
                        <div class="bar"><div class="bar-fill amber" style="width: 80%;"></div></div>
                        <div class="readiness-note">Rollback packages exist; one monitoring trigger still awaiting sign-off.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Governed Release Workflow</h2>
            <div class="workflow">
                <div class="step">
                    <div class="step-number">1</div>
                    <h3>Package</h3>
                    <p>Bundle optimized controls with rationale, lineage, and version metadata.</p>
                </div>
                <div class="step">
                    <div class="step-number">2</div>
                    <h3>Validate</h3>
                    <p>Confirm test results, impact, compatibility, and rollback logic.</p>
                </div>
                <div class="step">
                    <div class="step-number">3</div>
                    <h3>Approve</h3>
                    <p>Obtain required control-owner and governance-board sign-off.</p>
                </div>
                <div class="step">
                    <div class="step-number">4</div>
                    <h3>Stage</h3>
                    <p>Prepare deployment waves across affected modules and workflows.</p>
                </div>
                <div class="step">
                    <div class="step-number">5</div>
                    <h3>Promote</h3>
                    <p>Move the new control version into live governed use.</p>
                </div>
                <div class="step">
                    <div class="step-number">6</div>
                    <h3>Observe</h3>
                    <p>Monitor early performance and trigger rollback if needed.</p>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Release Validation Gates</h2>
            <p>
                Optimized controls do not move live simply because they look better in simulation.
                They pass through explicit gates before promotion.
            </p>

            <div class="gate-grid">
                <div class="gate-card green">
                    <div class="gate-title">Lineage Gate</div>
                    <div class="gate-status green">PASS</div>
                    <div class="gate-note">Every changed control is tied back to source lesson, version, and approval history.</div>
                </div>
                <div class="gate-card green">
                    <div class="gate-title">Impact Gate</div>
                    <div class="gate-status green">PASS</div>
                    <div class="gate-note">Before/after performance evidence is complete and reviewed.</div>
                </div>
                <div class="gate-card blue">
                    <div class="gate-title">Dependency Gate</div>
                    <div class="gate-status blue">READY</div>
                    <div class="gate-note">Affected modules mapped; final dependency confirmation pending.</div>
                </div>
                <div class="gate-card amber">
                    <div class="gate-title">Rollback Gate</div>
                    <div class="gate-status amber">PARTIAL</div>
                    <div class="gate-note">Previous versions preserved; one trigger still needs owner sign-off.</div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Release Queue</h2>
            <p>
                The queue shows which optimized controls are moving toward live use, which are staged, and which still carry blockers.
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Releases</button>
                <button class="filter-btn" data-filter="staged">Staged</button>
                <button class="filter-btn" data-filter="ready">Ready</button>
                <button class="filter-btn" data-filter="blocked">Blocked</button>
                <button class="filter-btn" data-filter="retire">Retire</button>
                <input id="searchInput" class="search" type="text" placeholder="Search package, control, version, or module...">
            </div>

            <table id="releaseTable">
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>Control Change</th>
                        <th>Version</th>
                        <th>Affected Modules</th>
                        <th>Release Type</th>
                        <th>Readiness</th>
                        <th>Status</th>
                        <th>Decision</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-state="staged" data-search="rls-2026-014 gcl-005 downstream release confirmation v1.3 dependency validation release assurance staged">
                        <td>RLS-2026-014</td>
                        <td>GCL-005 — Downstream Release Confirmation</td>
                        <td>v1.3</td>
                        <td>Dependency Validation / Decision Engine</td>
                        <td>Strengthen</td>
                        <td>92%</td>
                        <td><span class="pill blue">Staged</span></td>
                        <td>Promote after final gate</td>
                    </tr>
                    <tr data-state="ready" data-search="rls-2026-014 gcl-003 reconciliation v1.1 reconciliation layer predictive drift ready tune">
                        <td>RLS-2026-014</td>
                        <td>GCL-003 — Release-Sensitive Record Reconciliation</td>
                        <td>v1.1</td>
                        <td>Reconciliation Layer / Predictive Drift</td>
                        <td>Tune</td>
                        <td>96%</td>
                        <td><span class="pill green">Ready</span></td>
                        <td>Publish in Wave 1</td>
                    </tr>
                    <tr data-state="retire" data-search="rls-2026-014 gcl-009 legacy closure reminder retired assurance register closure integrity">
                        <td>RLS-2026-014</td>
                        <td>GCL-009 — Legacy Closure Reminder</td>
                        <td>Retired</td>
                        <td>Assurance Register</td>
                        <td>Retire</td>
                        <td>100%</td>
                        <td><span class="pill indigo">Retire</span></td>
                        <td>Remove in Wave 2</td>
                    </tr>
                    <tr data-state="blocked" data-search="rls-2026-015 gcl-008 erp mes lims release chain v1.0 blocked dependency map">
                        <td>RLS-2026-015</td>
                        <td>GCL-008 — ERP → MES → LIMS Release Chain</td>
                        <td>v1.0</td>
                        <td>Dependency Validation / Mission Control</td>
                        <td>Strengthen</td>
                        <td>71%</td>
                        <td><span class="pill red">Blocked</span></td>
                        <td>Resolve impact review</td>
                    </tr>
                    <tr data-state="ready" data-search="rls-2026-016 gcl-006 privileged account owner review v2.2 access governance ready tune">
                        <td>RLS-2026-016</td>
                        <td>GCL-006 — Privileged Account Owner Review</td>
                        <td>v2.2</td>
                        <td>Access Governance / myAccess</td>
                        <td>Tune</td>
                        <td>94%</td>
                        <td><span class="pill green">Ready</span></td>
                        <td>Publish in Wave 2</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Affected Module Map</h2>
                <div class="map-grid">
                    <div class="map-card">
                        <div class="map-title">Dependency Validation</div>
                        <div class="map-note">
                            Receives strengthened GCL-005 logic for release-chain confirmation.
                        </div>
                        <div class="map-state">Directly affected</div>
                    </div>
                    <div class="map-card">
                        <div class="map-title">Reconciliation Layer</div>
                        <div class="map-note">
                            Receives tuned GCL-003 threshold logic for material mismatches.
                        </div>
                        <div class="map-state">Directly affected</div>
                    </div>
                    <div class="map-card">
                        <div class="map-title">Assurance Register</div>
                        <div class="map-note">
                            Removes legacy GCL-009 reminder once stronger controls are active.
                        </div>
                        <div class="map-state">Indirectly affected</div>
                    </div>
                    <div class="map-card">
                        <div class="map-title">Control Library</div>
                        <div class="map-note">
                            Receives versioned control records after successful promotion.
                        </div>
                        <div class="map-state">System of governance record</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Rollout Sequence</h2>
                <div class="rollout">
                    <div class="rollout-item">
                        <div class="rollout-wave">Wave 1</div>
                        <div>
                            <div class="rollout-title">Publish GCL-003 v1.1</div>
                            <div class="rollout-note">
                                Low-risk threshold tuning first; monitor false-positive reduction.
                            </div>
                        </div>
                        <div class="rollout-state">Ready</div>
                    </div>
                    <div class="rollout-item">
                        <div class="rollout-wave">Wave 2</div>
                        <div>
                            <div class="rollout-title">Promote GCL-005 v1.3 and retire GCL-009</div>
                            <div class="rollout-note">
                                Strengthened release logic goes live once rollback trigger sign-off is complete.
                            </div>
                        </div>
                        <div class="rollout-state">Staged</div>
                    </div>
                    <div class="rollout-item">
                        <div class="rollout-wave">Wave 3</div>
                        <div>
                            <div class="rollout-title">Observe early performance</div>
                            <div class="rollout-note">
                                Compare live prevention yield, noise, and missed-risk rate against projections.
                            </div>
                        </div>
                        <div class="rollout-state">Planned</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Interactive Release Builder</h2>
            <p>
                This simulation shows how the orchestrator changes the deployment plan based on release type, rollout strategy, and rollback posture.
            </p>

            <div class="builder">
                <div class="builder-grid">
                    <div class="builder-row">
                        <label for="controlSelect">Control Change</label>
                        <select id="controlSelect">
                            <option value="gcl005">GCL-005 v1.3 — Strengthened release logic</option>
                            <option value="gcl003">GCL-003 v1.1 — Tuned reconciliation threshold</option>
                            <option value="gcl009">GCL-009 — Controlled retirement</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label for="strategySelect">Rollout Strategy</label>
                        <select id="strategySelect">
                            <option value="phased">Phased rollout</option>
                            <option value="pilot">Pilot first</option>
                            <option value="direct">Direct publish</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label for="rollbackSelect">Rollback Posture</label>
                        <select id="rollbackSelect">
                            <option value="full">Full rollback ready</option>
                            <option value="partial">Partial rollback ready</option>
                            <option value="none">No rollback package</option>
                        </select>
                    </div>
                </div>

                <div class="builder-result">
                    <div class="builder-label">Recommended Release Plan</div>
                    <div id="builderTitle" class="builder-title">Staged Promotion</div>
                    <div id="builderPlan" class="builder-plan">
                        Use phased rollout for GCL-005 v1.3 with full rollback readiness before live promotion.
                    </div>
                    <div class="builder-meta">
                        <div class="builder-mini">
                            <div class="builder-mini-label">Risk</div>
                            <div id="builderRisk" class="builder-mini-value">Moderate</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Recommended Wave</div>
                            <div id="builderWave" class="builder-mini-value">Wave 2</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Gate Result</div>
                            <div id="builderGate" class="builder-mini-value">Stage only</div>
                        </div>
                    </div>
                    <div id="builderNote" class="builder-note">
                        Strengthened release logic affects high-consequence workflows, so controlled sequencing is preferred.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Rollback Readiness</h2>
                <div class="rollback-grid">
                    <div class="rollback-card green">
                        <div class="rollback-title">Prior Version Stored</div>
                        <div class="rollback-value">Yes</div>
                        <div class="rollback-note">GCL-005 v1.2 preserved for immediate restoration.</div>
                    </div>
                    <div class="rollback-card green">
                        <div class="rollback-title">Monitoring Trigger</div>
                        <div class="rollback-value">Defined</div>
                        <div class="rollback-note">Rollback if live false positives exceed approved tolerance.</div>
                    </div>
                    <div class="rollback-card amber">
                        <div class="rollback-title">Owner Sign-Off</div>
                        <div class="rollback-value">Pending</div>
                        <div class="rollback-note">One final release owner approval remains open.</div>
                    </div>
                    <div class="rollback-card green">
                        <div class="rollback-title">Evidence Pack</div>
                        <div class="rollback-value">Ready</div>
                        <div class="rollback-note">Release rationale, test proof, and lineage preserved.</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Promotion Evidence Pack</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Evidence Item</th>
                            <th>Purpose</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Optimization Rationale</td>
                            <td>Why the control changed</td>
                            <td><span class="pill green">Ready</span></td>
                        </tr>
                        <tr>
                            <td>Before / After Simulation</td>
                            <td>Expected control-performance impact</td>
                            <td><span class="pill green">Ready</span></td>
                        </tr>
                        <tr>
                            <td>Approval Record</td>
                            <td>Authorized governance decision</td>
                            <td><span class="pill green">Ready</span></td>
                        </tr>
                        <tr>
                            <td>Rollback Trigger</td>
                            <td>Safe reversal condition</td>
                            <td><span class="pill amber">Pending sign-off</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Release Action Console</h2>
            <p>
                The orchestrator does not simply publish rules. It manages the next controlled release action according to readiness and governance evidence.
            </p>

            <div class="action-console">
                <div class="action-list">
                    <div class="action-item">
                        <div>
                            <h3>Approve rollback trigger</h3>
                            <p>Clear the final blocker preventing GCL-005 v1.3 from live promotion.</p>
                        </div>
                        <button class="action-btn" data-action="rollback">Approve</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Publish GCL-003 v1.1</h3>
                            <p>Release tuned reconciliation logic through the first low-risk wave.</p>
                        </div>
                        <button class="action-btn" data-action="publish">Publish</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Stage GCL-005 v1.3</h3>
                            <p>Prepare strengthened release logic for Wave 2 deployment.</p>
                        </div>
                        <button class="action-btn" data-action="stage">Stage</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Retire GCL-009</h3>
                            <p>Remove superseded low-value logic after stronger controls are active.</p>
                        </div>
                        <button class="action-btn" data-action="retire">Retire</button>
                    </div>
                </div>

                <div id="consoleResult" class="console-result">
                    <div class="console-label">Release Outcome</div>
                    <div id="consoleTitle" class="console-title">Awaiting Action</div>
                    <div id="consoleNote" class="console-note">
                        Select a release action to see how optimized controls are governed into live use.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>Optimization Workbench</h3>
                <p>
                    Improves control logic based on effectiveness findings.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Release Orchestrator</h3>
                <p>
                    Moves improved controls into production with validation, approvals, sequencing, and rollback readiness.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    Even governance controls themselves are changed under governance, not by casual edits.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by the Release Orchestrator</h2>
            <p>
                The Governance Control Optimization Workbench™ answers: <strong>“How do we improve a control?”</strong>
            </p>
            <p>
                The Governance Control Release Orchestrator™ answers: <strong>“How do we safely move that improved control into live use?”</strong>
            </p>
            <p>
                That completes a serious enterprise-control lifecycle. COBIT-Chain™ now shows that control logic can be learned,
                designed, approved, monitored, optimized, and then redeployed through a governed release process with traceability
                and rollback discipline.
            </p>
            <div class="footer-note">
                Simulation chain: pain point detection → dependency validation → reconciliation → decision intelligence →
                Governance Passport™ → Governance Assurance Register™ → Governance Intervention Workbench™ →
                Governance Re-Closure Gate™ → Governance Closure Certificate™ → Governance Learning Loop™ →
                Governance Rule Factory™ → Governance Control Library™ → Governance Control Effectiveness Monitor™ →
                Governance Control Optimization Workbench™ → Governance Control Release Orchestrator™.
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#releaseTable tbody tr");
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

        const controlSelect = document.getElementById("controlSelect");
        const strategySelect = document.getElementById("strategySelect");
        const rollbackSelect = document.getElementById("rollbackSelect");
        const builderTitle = document.getElementById("builderTitle");
        const builderPlan = document.getElementById("builderPlan");
        const builderRisk = document.getElementById("builderRisk");
        const builderWave = document.getElementById("builderWave");
        const builderGate = document.getElementById("builderGate");
        const builderNote = document.getElementById("builderNote");

        function updateBuilder() {
            const control = controlSelect.value;
            const strategy = strategySelect.value;
            const rollback = rollbackSelect.value;

            let title = "Staged Promotion";
            let plan = "";
            let risk = "Moderate";
            let wave = "Wave 2";
            let gate = "Stage only";
            let note = "";

            if (control === "gcl005") {
                plan = "Use " + strategy.replace("-", " ") + " for GCL-005 v1.3 before live release.";
                risk = strategy === "direct" ? "High" : "Moderate";
                wave = strategy === "pilot" ? "Pilot" : "Wave 2";
                note = "Strengthened release logic touches high-consequence workflows, so controlled sequencing is preferred.";
            } else if (control === "gcl003") {
                title = "Low-Risk Publication";
                plan = "Use " + strategy.replace("-", " ") + " for GCL-003 v1.1 tuned reconciliation logic.";
                risk = "Low";
                wave = strategy === "direct" ? "Wave 1" : "Wave 1";
                note = "Threshold tuning is lower risk and can be promoted earlier with short observation.";
            } else {
                title = "Controlled Retirement";
                plan = "Retire GCL-009 only after replacement controls are confirmed active.";
                risk = "Low";
                wave = "Wave 2";
                note = "Retirement should follow stronger replacement controls, not precede them.";
            }

            if (rollback === "full") {
                gate = control === "gcl003" ? "Ready to publish" : "Promotion eligible";
            } else if (rollback === "partial") {
                gate = "Stage only";
                title = control === "gcl003" ? "Staged Promotion" : title;
            } else {
                gate = "Blocked";
                risk = "High";
                title = "Release Blocked";
                note = "No optimized control should move live without a viable rollback posture.";
            }

            builderTitle.textContent = title;
            builderPlan.textContent = plan;
            builderRisk.textContent = risk;
            builderWave.textContent = wave;
            builderGate.textContent = gate;
            builderNote.textContent = note;
        }

        controlSelect.addEventListener("change", updateBuilder);
        strategySelect.addEventListener("change", updateBuilder);
        rollbackSelect.addEventListener("change", updateBuilder);
        updateBuilder();

        const actionButtons = document.querySelectorAll(".action-btn");
        const consoleResult = document.getElementById("consoleResult");
        const consoleTitle = document.getElementById("consoleTitle");
        const consoleNote = document.getElementById("consoleNote");

        const outcomes = {
            rollback: {
                title: "Rollback Trigger Approved",
                note: "The final rollback-readiness blocker is cleared; GCL-005 v1.3 can move from staged to promotion-eligible."
            },
            publish: {
                title: "GCL-003 v1.1 Published",
                note: "The tuned reconciliation control has entered Wave 1 with monitoring for false-positive reduction."
            },
            stage: {
                title: "GCL-005 v1.3 Staged",
                note: "The strengthened downstream-release control is prepared for Wave 2 deployment after final release confirmation."
            },
            retire: {
                title: "GCL-009 Retirement Authorized",
                note: "The superseded legacy reminder may be removed once stronger closure controls are confirmed active."
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
        print("SKIP: GOVERNANCE_CONTROL_RELEASE_ORCHESTRATOR_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/governance-control-release-orchestrator")',
        "Governance Control Release Orchestrator™",
        "Release Validation Gates",
        "Release Queue",
        "Interactive Release Builder",
        "Release Action Console",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /governance-control-release-orchestrator route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
