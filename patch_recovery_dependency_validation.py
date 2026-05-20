from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# RECOVERY_DEPENDENCY_VALIDATION_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# RECOVERY_DEPENDENCY_VALIDATION_ACTIVE
@app.route("/recovery-dependency-validation")
def recovery_dependency_validation_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Recovery Dependency Validation™ | COBIT-Chain™ / AssuranceLayer™</title>
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
            background: linear-gradient(135deg, #111827 0%, #0f766e 43%, #991b1b 100%);
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
            background: linear-gradient(180deg, #ffffff 0%, #f0fdfa 100%);
            border: 1px solid #99f6e4;
            border-radius: 22px;
            padding: 20px;
        }
        .event-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #0f766e;
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
        .truth-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .truth-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .truth-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .truth-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .truth-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .truth-card.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .truth-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .truth-value {
            font-size: 26px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .truth-note {
            color: #516078;
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
            background: #0f766e;
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
            min-width: 350px;
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
        .chain-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 12px;
        }
        .chain-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .chain-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .chain-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .chain-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .chain-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .chain-state {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
            margin-bottom: 10px;
        }
        .chain-state.green {
            background: #dcfce7;
            color: #166534;
        }
        .chain-state.amber {
            background: #fef3c7;
            color: #92400e;
        }
        .chain-state.red {
            background: #fee2e2;
            color: #991b1b;
        }
        .chain-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
        }
        .evidence-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 12px;
        }
        .evidence-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .evidence-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .evidence-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
            margin-bottom: 11px;
        }
        .evidence-state {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
        }
        .evidence-state.green {
            background: #dcfce7;
            color: #166534;
        }
        .evidence-state.amber {
            background: #fef3c7;
            color: #92400e;
        }
        .evidence-state.red {
            background: #fee2e2;
            color: #991b1b;
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
        .check-grid {
            display: grid;
            gap: 10px;
        }
        .check-row {
            display: flex;
            align-items: center;
            gap: 10px;
            background: #fff;
            border-radius: 14px;
            padding: 11px 12px;
            border: 1px solid #e2eaf7;
            font-size: 14px;
            font-weight: 700;
        }
        .check-row input {
            width: 18px;
            height: 18px;
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
            background: #f0fdfa;
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
            .builder,
            .inspector,
            .action-console {
                grid-template-columns: 1fr;
            }
            .workflow {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .truth-grid,
            .chain-grid,
            .evidence-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .workflow,
            .truth-grid,
            .chain-grid,
            .evidence-grid,
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
                <a href="/rto-rpo-governance-intelligence">RTO / RPO Intelligence</a>
                <a href="/dr-activation-intelligence">DR Activation</a>
                <a href="/cross-system-dependency-validation">Dependency Validation</a>
                <a href="/governance-reconciliation-layer">Reconciliation Layer</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Recovery Truth Assurance Layer</div>
            <h1>Recovery Dependency Validation™</h1>
            <p>
                The module that prevents false recovery closure. Technical restoration is not enough if the restore log exists
                but data reconciliation is incomplete, if the database is online but CSQA integrity verification is missing,
                or if the system is available while BQA has not cleared GMP impact. Recovery becomes governably complete only
                when every technical, data, quality, and approval dependency is satisfied.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Recovery Case</div>
                    <div class="hero-value">RCV-2026-014</div>
                    <div class="hero-note">ERP recovery event</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Technical Restore</div>
                    <div class="hero-value">Complete</div>
                    <div class="hero-note">Server and DB online</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Open Dependencies</div>
                    <div class="hero-value">3</div>
                    <div class="hero-note">Reconciliation / CSQA / BQA</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">False Closure Risk</div>
                    <div class="hero-value">High</div>
                    <div class="hero-note">Cannot call recovered yet</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Restart State</div>
                    <div class="hero-value">Blocked</div>
                    <div class="hero-note">GMP approval missing</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Governance Verdict</div>
                    <div class="hero-value">Not Complete</div>
                    <div class="hero-note">Recovery truth failed</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Selected Recovery Case</h2>
                <div class="event-card">
                    <div class="event-kicker">Recovery Validation Case</div>
                    <div class="event-title">ERP / Finance & Supply Chain Restore</div>
                    <div class="event-note">
                        The ERP application and database have been restored, but the recovery cannot be closed because
                        the required Data Reconciliation Matrix is incomplete, CSQA integrity verification is still pending,
                        and BQA has not yet completed the GMP impact assessment needed before resumption.
                    </div>

                    <div class="event-meta">
                        <div class="meta-card">
                            <div class="meta-label">Technical State</div>
                            <div class="meta-value">Restored</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Data State</div>
                            <div class="meta-value">Unreconciled</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">QA State</div>
                            <div class="meta-value">Pending</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Closure State</div>
                            <div class="meta-value">Blocked</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Recovery Truth Snapshot</h2>
                <div class="truth-grid">
                    <div class="truth-card green">
                        <div class="truth-label">Backup Restore Log</div>
                        <div class="truth-value">Present</div>
                        <div class="truth-note">Timestamps and restore outcome documented.</div>
                    </div>
                    <div class="truth-card red">
                        <div class="truth-label">Data Reconciliation</div>
                        <div class="truth-value">Missing</div>
                        <div class="truth-note">GMP gaps versus paper records not yet cleared.</div>
                    </div>
                    <div class="truth-card amber">
                        <div class="truth-label">CSQA Integrity</div>
                        <div class="truth-value">Pending</div>
                        <div class="truth-note">Audit trail and Part 11 verification incomplete.</div>
                    </div>
                    <div class="truth-card red">
                        <div class="truth-label">BQA GMP Impact</div>
                        <div class="truth-value">Not Approved</div>
                        <div class="truth-note">Restart cannot be accepted yet.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Recovery Dependency Workflow</h2>
            <div class="workflow">
                <div class="step">
                    <div class="step-number">1</div>
                    <h3>Restore</h3>
                    <p>Recover infrastructure, application, database, and backups.</p>
                </div>
                <div class="step">
                    <div class="step-number">2</div>
                    <h3>Reconcile</h3>
                    <p>Compare restored data to expected GMP, batch, and paper records.</p>
                </div>
                <div class="step">
                    <div class="step-number">3</div>
                    <h3>Verify Integrity</h3>
                    <p>CSQA confirms audit trails, Part 11 posture, and system integrity.</p>
                </div>
                <div class="step">
                    <div class="step-number">4</div>
                    <h3>Assess GMP Impact</h3>
                    <p>BQA determines batch, material, and business consequences.</p>
                </div>
                <div class="step">
                    <div class="step-number">5</div>
                    <h3>Validate Dependencies</h3>
                    <p>Check upstream and downstream systems before closure.</p>
                </div>
                <div class="step">
                    <div class="step-number">6</div>
                    <h3>Authorize Recovery</h3>
                    <p>Only then may recovery be considered complete and restart reviewed.</p>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Recovery Truth Chain</h2>
            <p>
                The chain must be complete end to end. A single missing dependency blocks truthful recovery closure.
            </p>

            <div class="chain-grid">
                <div class="chain-card green">
                    <div class="chain-title">01. Restore Complete</div>
                    <div class="chain-state green">PASS</div>
                    <div class="chain-note">Application and database restored from validated backup set.</div>
                </div>
                <div class="chain-card red">
                    <div class="chain-title">02. Data Reconciled</div>
                    <div class="chain-state red">FAIL</div>
                    <div class="chain-note">Reconciliation matrix not yet approved against GMP source records.</div>
                </div>
                <div class="chain-card amber">
                    <div class="chain-title">03. CSQA Verified</div>
                    <div class="chain-state amber">PENDING</div>
                    <div class="chain-note">Integrity review remains open after technical restore.</div>
                </div>
                <div class="chain-card red">
                    <div class="chain-title">04. BQA Cleared</div>
                    <div class="chain-state red">FAIL</div>
                    <div class="chain-note">GMP impact assessment has not authorized resumption.</div>
                </div>
                <div class="chain-card red">
                    <div class="chain-title">05. Recovery Closed</div>
                    <div class="chain-state red">BLOCKED</div>
                    <div class="chain-note">False closure prevented because required dependencies remain incomplete.</div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Recovery Dependency Register</h2>
            <p>
                Every recovery item is tested across technical, data, QA, business, and downstream dependencies.
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Cases</button>
                <button class="filter-btn" data-filter="complete">Complete</button>
                <button class="filter-btn" data-filter="partial">Partial</button>
                <button class="filter-btn" data-filter="blocked">Blocked</button>
                <input id="searchInput" class="search" type="text" placeholder="Search system, dependency, owner, or recovery state...">
            </div>

            <table id="dependencyTable">
                <thead>
                    <tr>
                        <th>Recovery Case</th>
                        <th>System</th>
                        <th>Technical Restore</th>
                        <th>Data Reconciliation</th>
                        <th>CSQA Integrity</th>
                        <th>BQA GMP Impact</th>
                        <th>Downstream Dependency</th>
                        <th>Recovery Verdict</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-state="blocked" data-search="rcv-2026-014 erp technical restore complete data reconciliation missing csqa pending bqa not approved downstream supply chain blocked">
                        <td>RCV-2026-014</td>
                        <td>ERP / Finance & Supply Chain</td>
                        <td><span class="pill green">Complete</span></td>
                        <td><span class="pill red">Missing</span></td>
                        <td><span class="pill amber">Pending</span></td>
                        <td><span class="pill red">Not Approved</span></td>
                        <td><span class="pill red">Open</span></td>
                        <td><span class="pill red">Blocked</span></td>
                    </tr>
                    <tr data-state="partial" data-search="rcv-2026-015 lims restore complete reconciliation complete csqa pending bqa pending qc release partial">
                        <td>RCV-2026-015</td>
                        <td>LIMS / QC</td>
                        <td><span class="pill green">Complete</span></td>
                        <td><span class="pill green">Complete</span></td>
                        <td><span class="pill amber">Pending</span></td>
                        <td><span class="pill amber">Pending</span></td>
                        <td><span class="pill amber">QC release hold</span></td>
                        <td><span class="pill amber">Partial</span></td>
                    </tr>
                    <tr data-state="complete" data-search="rcv-2026-016 continuous environmental monitoring restore complete reconciliation complete csqa verified bqa approved complete">
                        <td>RCV-2026-016</td>
                        <td>Continuous Environmental Monitoring</td>
                        <td><span class="pill green">Complete</span></td>
                        <td><span class="pill green">Complete</span></td>
                        <td><span class="pill green">Verified</span></td>
                        <td><span class="pill green">Approved</span></td>
                        <td><span class="pill green">Clear</span></td>
                        <td><span class="pill green">Complete</span></td>
                    </tr>
                    <tr data-state="blocked" data-search="rcv-2026-017 building automation monitoring restore complete reconciliation manual logs pending csqa pending bqa not approved hvac dependency blocked">
                        <td>RCV-2026-017</td>
                        <td>Building Automation / Monitoring</td>
                        <td><span class="pill green">Complete</span></td>
                        <td><span class="pill amber">Manual logs pending</span></td>
                        <td><span class="pill amber">Pending</span></td>
                        <td><span class="pill red">Not Approved</span></td>
                        <td><span class="pill red">HVAC dependency</span></td>
                        <td><span class="pill red">Blocked</span></td>
                    </tr>
                    <tr data-state="complete" data-search="rcv-2026-018 filter integrity testing restore complete reconciliation complete csqa verified bqa approved complete">
                        <td>RCV-2026-018</td>
                        <td>Filter Integrity Testing</td>
                        <td><span class="pill green">Complete</span></td>
                        <td><span class="pill green">Complete</span></td>
                        <td><span class="pill green">Verified</span></td>
                        <td><span class="pill green">Approved</span></td>
                        <td><span class="pill green">Clear</span></td>
                        <td><span class="pill green">Complete</span></td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Required Recovery Evidence</h2>
                <div class="evidence-grid">
                    <div class="evidence-card">
                        <div class="evidence-title">Damage Assessment Report</div>
                        <div class="evidence-note">
                            Documents trigger, impacted systems, and recovery consequence.
                        </div>
                        <div class="evidence-state green">Attached</div>
                    </div>
                    <div class="evidence-card">
                        <div class="evidence-title">Backup Restore Log</div>
                        <div class="evidence-note">
                            Proves restore timestamps, source, and success/failure status.
                        </div>
                        <div class="evidence-state green">Attached</div>
                    </div>
                    <div class="evidence-card">
                        <div class="evidence-title">Data Reconciliation Matrix</div>
                        <div class="evidence-note">
                            Confirms restored data against GMP gaps and paper records.
                        </div>
                        <div class="evidence-state red">Missing</div>
                    </div>
                    <div class="evidence-card">
                        <div class="evidence-title">CSQA Integrity Verification</div>
                        <div class="evidence-note">
                            Verifies audit trails, Part 11 posture, and system integrity.
                        </div>
                        <div class="evidence-state amber">Pending</div>
                    </div>
                    <div class="evidence-card">
                        <div class="evidence-title">BQA GMP Impact Assessment</div>
                        <div class="evidence-note">
                            Determines batch hold, release impact, and restart readiness.
                        </div>
                        <div class="evidence-state red">Not Approved</div>
                    </div>
                    <div class="evidence-card">
                        <div class="evidence-title">Root Cause Analysis</div>
                        <div class="evidence-note">
                            Preserves the post-recovery reason and prevention plan.
                        </div>
                        <div class="evidence-state amber">Pending</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>False Closure Patterns</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Pattern</th>
                            <th>Why It Is False</th>
                            <th>Required Correction</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Backup restored</td>
                            <td>Data may still be unreconciled</td>
                            <td>Complete reconciliation matrix</td>
                        </tr>
                        <tr>
                            <td>Database online</td>
                            <td>Integrity has not been verified</td>
                            <td>Obtain CSQA verification</td>
                        </tr>
                        <tr>
                            <td>Ticket closed</td>
                            <td>GMP impact may remain open</td>
                            <td>Obtain BQA disposition</td>
                        </tr>
                        <tr>
                            <td>System available</td>
                            <td>Downstream dependency may still fail</td>
                            <td>Validate recovery chain</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Interactive Recovery Truth Builder</h2>
            <p>
                This simulation shows why technical restoration alone should never be enough to declare a regulated recovery complete.
            </p>

            <div class="builder">
                <div class="builder-grid">
                    <div class="builder-row">
                        <label>Recovery Dependency Checks</label>
                        <div class="check-grid">
                            <label class="check-row">
                                <input id="checkRestore" type="checkbox" checked>
                                Technical restore completed
                            </label>
                            <label class="check-row">
                                <input id="checkReconcile" type="checkbox">
                                Data reconciliation matrix approved
                            </label>
                            <label class="check-row">
                                <input id="checkCsqa" type="checkbox">
                                CSQA integrity verification completed
                            </label>
                            <label class="check-row">
                                <input id="checkBqa" type="checkbox">
                                BQA GMP impact assessment approved
                            </label>
                            <label class="check-row">
                                <input id="checkDownstream" type="checkbox">
                                Downstream dependencies confirmed clear
                            </label>
                        </div>
                    </div>
                </div>

                <div class="builder-result">
                    <div class="builder-label">Recovery Verdict</div>
                    <div id="builderTitle" class="builder-title">False Recovery Closure</div>
                    <div id="builderVerdict" class="builder-verdict">
                        Technical restore is complete, but recovery truth is not. Required governance dependencies remain open.
                    </div>
                    <div class="builder-meta">
                        <div class="builder-mini">
                            <div class="builder-mini-label">Checks Passed</div>
                            <div id="builderChecks" class="builder-mini-value">1 / 5</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Closure State</div>
                            <div id="builderClosure" class="builder-mini-value">Blocked</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Restart State</div>
                            <div id="builderRestart" class="builder-mini-value">Hold</div>
                        </div>
                    </div>
                    <div id="builderNote" class="builder-note">
                        A restored server is only one dependency in a regulated recovery chain.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Recovery Scenario Inspector</h2>
            <p>
                Select a scenario to inspect why a recovery is complete, partial, or falsely closed.
            </p>

            <div class="inspector">
                <div class="inspector-list">
                    <button class="inspect-btn active" data-scenario="false">
                        <div class="inspect-kicker">Scenario 01</div>
                        <div class="inspect-title">Backup restored, QA not signed off</div>
                        <div class="inspect-note">Technical success does not equal governed recovery.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="reconcile">
                        <div class="inspect-kicker">Scenario 02</div>
                        <div class="inspect-title">DB online, reconciliation incomplete</div>
                        <div class="inspect-note">Data truth still unproven.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="downstream">
                        <div class="inspect-kicker">Scenario 03</div>
                        <div class="inspect-title">System restored, downstream blocked</div>
                        <div class="inspect-note">Cross-system dependency still broken.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="complete">
                        <div class="inspect-kicker">Scenario 04</div>
                        <div class="inspect-title">End-to-end recovery complete</div>
                        <div class="inspect-note">All technical and governance dependencies cleared.</div>
                    </button>
                </div>

                <div class="inspector-card">
                    <div class="inspector-label">Selected Scenario</div>
                    <div id="inspectorTitle" class="inspector-title">Backup restored, QA not signed off</div>
                    <div class="inspector-meta">
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Technical State</div>
                            <div id="inspectorTechnical" class="inspector-mini-value">Restored</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Open Dependency</div>
                            <div id="inspectorDependency" class="inspector-mini-value">CSQA / BQA</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Verdict</div>
                            <div id="inspectorVerdictState" class="inspector-mini-value">Blocked</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Restart</div>
                            <div id="inspectorRestart" class="inspector-mini-value">Hold</div>
                        </div>
                    </div>
                    <div id="inspectorVerdict" class="inspector-verdict">
                        Recovery cannot be declared complete while post-restore integrity and GMP impact approvals remain open.
                    </div>
                    <div id="inspectorNote" class="inspector-note">
                        This is exactly the false-closure pattern the module is designed to expose.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Recovery Action Console</h2>
            <p>
                The module turns dependency gaps into the next required governance action.
            </p>

            <div class="action-console">
                <div class="action-list">
                    <div class="action-item">
                        <div>
                            <h3>Request reconciliation matrix</h3>
                            <p>Require GMP record comparison before recovery can advance.</p>
                        </div>
                        <button class="action-btn" data-action="reconcile">Request</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Route to CSQA verification</h3>
                            <p>Open integrity review for audit trails and Part 11 posture.</p>
                        </div>
                        <button class="action-btn" data-action="csqa">Route</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Open BQA GMP assessment</h3>
                            <p>Evaluate batch hold, release impact, and restart readiness.</p>
                        </div>
                        <button class="action-btn" data-action="bqa">Open</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Block premature recovery closure</h3>
                            <p>Keep the case open until all dependencies are proven complete.</p>
                        </div>
                        <button class="action-btn" data-action="block">Block</button>
                    </div>
                </div>

                <div id="consoleResult" class="console-result">
                    <div class="console-label">Recovery Outcome</div>
                    <div id="consoleTitle" class="console-title">Awaiting Action</div>
                    <div id="consoleNote" class="console-note">
                        Select an action to see how dependency validation prevents false recovery closure.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>RTO / RPO Intelligence</h3>
                <p>
                    Shows whether recovery thresholds are safe, drifting, or breached.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Recovery Dependency Validation</h3>
                <p>
                    Proves whether the entire technical, data, QA, and business recovery chain is complete.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    COBIT-Chain™ now distinguishes between technical restoration and truthful regulated recovery.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by Recovery Dependency Validation</h2>
            <p>
                RTO / RPO Governance Intelligence™ answers:
                <strong>“Are recovery thresholds safe, drifting, or breached?”</strong>
            </p>
            <p>
                Recovery Dependency Validation™ answers:
                <strong>“Even if the system is back online, is every dependency required for true recovery actually complete?”</strong>
            </p>
            <p>
                That is the point where the DR branch becomes enterprise-grade. The platform now prevents the most dangerous
                recovery mistake: declaring success when only the technical layer has recovered but the regulated governance
                chain remains broken.
            </p>
            <div class="footer-note">
                DR branch: DR Activation Intelligence™ → RTO / RPO Governance Intelligence™ →
                Recovery Dependency Validation™ → future DR Evidence Passport™ → GMP Restart Gate™ →
                Recovery Governance Command Center™ → DR Recovery Certificate™.
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#dependencyTable tbody tr");
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

        const checkRestore = document.getElementById("checkRestore");
        const checkReconcile = document.getElementById("checkReconcile");
        const checkCsqa = document.getElementById("checkCsqa");
        const checkBqa = document.getElementById("checkBqa");
        const checkDownstream = document.getElementById("checkDownstream");
        const builderTitle = document.getElementById("builderTitle");
        const builderVerdict = document.getElementById("builderVerdict");
        const builderChecks = document.getElementById("builderChecks");
        const builderClosure = document.getElementById("builderClosure");
        const builderRestart = document.getElementById("builderRestart");
        const builderNote = document.getElementById("builderNote");

        function updateBuilder() {
            const checks = [checkRestore, checkReconcile, checkCsqa, checkBqa, checkDownstream];
            const passed = checks.filter(check => check.checked).length;

            builderChecks.textContent = passed + " / 5";

            if (passed === 5) {
                builderTitle.textContent = "Recovery Truth Complete";
                builderVerdict.textContent = "All technical, data, QA, business, and downstream dependencies are satisfied. Recovery may move toward restart review.";
                builderClosure.textContent = "Complete";
                builderRestart.textContent = "Eligible";
                builderNote.textContent = "A regulated recovery is only complete when every dependency is proven, not merely when the system is online.";
            } else if (passed >= 3) {
                builderTitle.textContent = "Partial Recovery";
                builderVerdict.textContent = "Some dependencies are complete, but the recovery chain still contains open governance work.";
                builderClosure.textContent = "Partial";
                builderRestart.textContent = "Hold";
                builderNote.textContent = "The case is progressing, but open dependencies still prevent clean recovery closure.";
            } else {
                builderTitle.textContent = "False Recovery Closure";
                builderVerdict.textContent = "Technical restore is complete, but recovery truth is not. Required governance dependencies remain open.";
                builderClosure.textContent = "Blocked";
                builderRestart.textContent = "Hold";
                builderNote.textContent = "A restored server is only one dependency in a regulated recovery chain.";
            }
        }

        [checkRestore, checkReconcile, checkCsqa, checkBqa, checkDownstream].forEach(element => {
            element.addEventListener("change", updateBuilder);
        });

        updateBuilder();

        const inspectButtons = document.querySelectorAll(".inspect-btn");
        const inspectorTitle = document.getElementById("inspectorTitle");
        const inspectorTechnical = document.getElementById("inspectorTechnical");
        const inspectorDependency = document.getElementById("inspectorDependency");
        const inspectorVerdictState = document.getElementById("inspectorVerdictState");
        const inspectorRestart = document.getElementById("inspectorRestart");
        const inspectorVerdict = document.getElementById("inspectorVerdict");
        const inspectorNote = document.getElementById("inspectorNote");

        const scenarios = {
            false: {
                title: "Backup restored, QA not signed off",
                technical: "Restored",
                dependency: "CSQA / BQA",
                state: "Blocked",
                restart: "Hold",
                verdict: "Recovery cannot be declared complete while post-restore integrity and GMP impact approvals remain open.",
                note: "This is exactly the false-closure pattern the module is designed to expose."
            },
            reconcile: {
                title: "DB online, reconciliation incomplete",
                technical: "Restored",
                dependency: "Data reconciliation",
                state: "Blocked",
                restart: "Hold",
                verdict: "The database may be online, but the restored data has not yet been proven against GMP and paper records.",
                note: "Availability without reconciliation is not recovery truth."
            },
            downstream: {
                title: "System restored, downstream blocked",
                technical: "Restored",
                dependency: "Downstream dependency",
                state: "Partial",
                restart: "Hold",
                verdict: "The local system is available, but the end-to-end recovery chain remains broken downstream.",
                note: "Cross-system dependency validation prevents isolated success from being mistaken for enterprise recovery."
            },
            complete: {
                title: "End-to-end recovery complete",
                technical: "Restored",
                dependency: "None",
                state: "Complete",
                restart: "Eligible",
                verdict: "Restore, reconciliation, CSQA verification, BQA approval, and downstream checks are all complete.",
                note: "This is the only state that should be eligible to move toward restart authorization."
            }
        };

        inspectButtons.forEach(button => {
            button.addEventListener("click", () => {
                inspectButtons.forEach(btn => btn.classList.remove("active"));
                button.classList.add("active");

                const item = scenarios[button.dataset.scenario];
                inspectorTitle.textContent = item.title;
                inspectorTechnical.textContent = item.technical;
                inspectorDependency.textContent = item.dependency;
                inspectorVerdictState.textContent = item.state;
                inspectorRestart.textContent = item.restart;
                inspectorVerdict.textContent = item.verdict;
                inspectorNote.textContent = item.note;
            });
        });

        const actionButtons = document.querySelectorAll(".action-btn");
        const consoleResult = document.getElementById("consoleResult");
        const consoleTitle = document.getElementById("consoleTitle");
        const consoleNote = document.getElementById("consoleNote");

        const outcomes = {
            reconcile: {
                title: "Reconciliation Requested",
                note: "The Data Reconciliation Matrix is now required before the ERP recovery can progress."
            },
            csqa: {
                title: "CSQA Verification Routed",
                note: "Post-restore integrity verification has been opened for audit trails and Part 11 posture."
            },
            bqa: {
                title: "BQA Assessment Opened",
                note: "The GMP impact review has been routed to determine batch, material, and restart consequence."
            },
            block: {
                title: "Premature Closure Blocked",
                note: "The recovery case remains open because the technical restore alone does not satisfy governance truth."
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
        print("SKIP: RECOVERY_DEPENDENCY_VALIDATION_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/recovery-dependency-validation")',
        "Recovery Dependency Validation™",
        "Recovery Dependency Register",
        "Interactive Recovery Truth Builder",
        "Recovery Scenario Inspector",
        "Recovery Action Console",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /recovery-dependency-validation route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
