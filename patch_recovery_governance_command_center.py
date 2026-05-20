from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# RECOVERY_GOVERNANCE_COMMAND_CENTER_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# RECOVERY_GOVERNANCE_COMMAND_CENTER_ACTIVE
@app.route("/recovery-governance-command-center")
def recovery_governance_command_center_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Recovery Governance Command Center™ | COBIT-Chain™ / AssuranceLayer™</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #f4f7fb;
            color: #172033;
        }
        .shell {
            max-width: 1500px;
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
            background: linear-gradient(135deg, #111827 0%, #1d4ed8 33%, #0f766e 67%, #7f1d1d 100%);
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
            max-width: 1180px;
            margin: 0;
            line-height: 1.56;
            font-size: 16px;
            opacity: .95;
        }
        .hero-grid {
            display: grid;
            grid-template-columns: repeat(7, minmax(0, 1fr));
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
            grid-template-columns: 1.1fr .9fr;
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
        .case-card {
            background: linear-gradient(180deg, #ffffff 0%, #eff6ff 100%);
            border: 1px solid #bfdbfe;
            border-radius: 22px;
            padding: 20px;
        }
        .case-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #1d4ed8;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .case-title {
            font-size: 24px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .case-note {
            color: #4c5b73;
            line-height: 1.55;
            margin-bottom: 16px;
        }
        .case-meta {
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
        .posture-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .posture-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .posture-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .posture-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .posture-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .posture-card.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .posture-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .posture-value {
            font-size: 28px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .posture-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
        }
        .workflow {
            display: grid;
            grid-template-columns: repeat(7, minmax(0, 1fr));
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
        .module-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 12px;
        }
        .module-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .module-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .module-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .module-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .module-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .module-state {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
            margin-bottom: 10px;
        }
        .module-state.green {
            background: #dcfce7;
            color: #166534;
        }
        .module-state.amber {
            background: #fef3c7;
            color: #92400e;
        }
        .module-state.red {
            background: #fee2e2;
            color: #991b1b;
        }
        .module-note {
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
            min-width: 360px;
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
        .priority-grid {
            display: grid;
            gap: 12px;
        }
        .priority-item {
            display: grid;
            grid-template-columns: 54px 1fr auto;
            gap: 14px;
            align-items: start;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .priority-no {
            width: 44px;
            height: 44px;
            border-radius: 14px;
            background: #7f1d1d;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 900;
        }
        .priority-title {
            font-weight: 900;
            margin-bottom: 5px;
        }
        .priority-note {
            color: #53637b;
            line-height: 1.45;
            font-size: 14px;
        }
        .priority-owner {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            text-align: right;
        }
        .queue-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .queue-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .queue-role {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 7px;
        }
        .queue-title {
            font-size: 17px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .queue-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
            margin-bottom: 10px;
        }
        .queue-state {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
        }
        .queue-state.green {
            background: #dcfce7;
            color: #166534;
        }
        .queue-state.amber {
            background: #fef3c7;
            color: #92400e;
        }
        .queue-state.red {
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
        @media (max-width: 1320px) {
            .hero-grid {
                grid-template-columns: repeat(4, minmax(0, 1fr));
            }
            .grid-2,
            .grid-3,
            .builder,
            .inspector,
            .action-console {
                grid-template-columns: 1fr;
            }
            .workflow {
                grid-template-columns: repeat(4, minmax(0, 1fr));
            }
            .module-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .posture-grid,
            .queue-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .workflow,
            .module-grid,
            .posture-grid,
            .queue-grid,
            .case-meta,
            .builder-meta,
            .inspector-meta {
                grid-template-columns: 1fr;
            }
            .search {
                margin-left: 0;
                width: 100%;
                min-width: 0;
            }
            .priority-item {
                grid-template-columns: 1fr;
            }
            .priority-owner {
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
                <a href="/rto-rpo-governance-intelligence">RTO / RPO</a>
                <a href="/recovery-dependency-validation">Dependencies</a>
                <a href="/dr-evidence-passport">Evidence Passport</a>
                <a href="/gmp-restart-gate">GMP Restart</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Operational Recovery Digital Twin</div>
            <h1>Recovery Governance Command Center™</h1>
            <p>
                The integrated mission-control view for disaster recovery governance. It brings together DR activation,
                RTO / RPO posture, recovery dependencies, evidence completeness, restart readiness, authority queues,
                and executive decision priorities so leadership can see not merely what has been restored, but what is
                truly safe, incomplete, blocked, and urgent across the recovery estate.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Active Recovery Events</div>
                    <div class="hero-value">5</div>
                    <div class="hero-note">Across RC2–RC5 systems</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Full DR Cases</div>
                    <div class="hero-value">2</div>
                    <div class="hero-note">Site Head authority needed</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Threshold Breaches</div>
                    <div class="hero-value">3</div>
                    <div class="hero-note">RTO / RPO action required</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">False Closure Risks</div>
                    <div class="hero-value">2</div>
                    <div class="hero-note">Technical restore only</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Draft Passports</div>
                    <div class="hero-value">2</div>
                    <div class="hero-note">Evidence incomplete</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Restart Holds</div>
                    <div class="hero-value">3</div>
                    <div class="hero-note">GMP resumption blocked</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Executive Posture</div>
                    <div class="hero-value">Critical</div>
                    <div class="hero-note">Action required now</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Priority Recovery Case</h2>
                <div class="case-card">
                    <div class="case-kicker">Highest Governance Priority</div>
                    <div class="case-title">ERP / Finance & Supply Chain — RCV-2026-014</div>
                    <div class="case-note">
                        Full DR is active. The system has crossed both RTO and RPO thresholds, technical restore is complete,
                        but recovery remains non-closable because the Data Reconciliation Matrix is missing, CSQA integrity review
                        is pending, the DR Evidence Passport is still draft, and GMP restart remains blocked without BQA and Site Head approval.
                    </div>

                    <div class="case-meta">
                        <div class="meta-card">
                            <div class="meta-label">Activation</div>
                            <div class="meta-value">Full DR</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Threshold State</div>
                            <div class="meta-value">Combined Failure</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Recovery Truth</div>
                            <div class="meta-value">Blocked</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Next Authority</div>
                            <div class="meta-value">BQA / Site Head</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Enterprise Recovery Posture</h2>
                <div class="posture-grid">
                    <div class="posture-card red">
                        <div class="posture-label">Operational Risk</div>
                        <div class="posture-value">High</div>
                        <div class="posture-note">Three events currently affect restart or release assurance.</div>
                    </div>
                    <div class="posture-card red">
                        <div class="posture-label">Audit Readiness</div>
                        <div class="posture-value">40%</div>
                        <div class="posture-note">Two passports remain in draft state.</div>
                    </div>
                    <div class="posture-card amber">
                        <div class="posture-label">QA Queue</div>
                        <div class="posture-value">4</div>
                        <div class="posture-note">CSQA / BQA actions still open.</div>
                    </div>
                    <div class="posture-card blue">
                        <div class="posture-label">Decision Priority</div>
                        <div class="posture-value">ERP</div>
                        <div class="posture-note">Highest system / consequence combination.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Command Center Workflow</h2>
            <div class="workflow">
                <div class="step">
                    <div class="step-number">1</div>
                    <h3>Activate</h3>
                    <p>Determine whether the event requires DR governance.</p>
                </div>
                <div class="step">
                    <div class="step-number">2</div>
                    <h3>Measure</h3>
                    <p>Read RTO / RPO posture and threshold drift.</p>
                </div>
                <div class="step">
                    <div class="step-number">3</div>
                    <h3>Validate</h3>
                    <p>Check end-to-end recovery dependencies.</p>
                </div>
                <div class="step">
                    <div class="step-number">4</div>
                    <h3>Evidence</h3>
                    <p>Assemble the controlled DR passport.</p>
                </div>
                <div class="step">
                    <div class="step-number">5</div>
                    <h3>Restart</h3>
                    <p>Gate GMP resumption separately from restore.</p>
                </div>
                <div class="step">
                    <div class="step-number">6</div>
                    <h3>Prioritize</h3>
                    <p>Rank what leadership must act on first.</p>
                </div>
                <div class="step">
                    <div class="step-number">7</div>
                    <h3>Certify</h3>
                    <p>Close only when the full chain is complete.</p>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Integrated Recovery Chain Status</h2>
            <p>
                One line of sight across every recovery-governance layer for the highest-priority event.
            </p>

            <div class="module-grid">
                <div class="module-card red">
                    <div class="module-title">DR Activation</div>
                    <div class="module-state red">FULL DR</div>
                    <div class="module-note">Level 4 activation already required.</div>
                </div>
                <div class="module-card red">
                    <div class="module-title">RTO / RPO</div>
                    <div class="module-state red">BREACHED</div>
                    <div class="module-note">Both time and data thresholds failed.</div>
                </div>
                <div class="module-card red">
                    <div class="module-title">Recovery Dependencies</div>
                    <div class="module-state red">BLOCKED</div>
                    <div class="module-note">Reconciliation, CSQA, and BQA open.</div>
                </div>
                <div class="module-card red">
                    <div class="module-title">DR Evidence Passport</div>
                    <div class="module-state red">DRAFT</div>
                    <div class="module-note">Only 3 of 6 artifacts complete.</div>
                </div>
                <div class="module-card red">
                    <div class="module-title">GMP Restart Gate</div>
                    <div class="module-state red">HOLD</div>
                    <div class="module-note">Restart not eligible.</div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Active Recovery Portfolio</h2>
            <p>
                The portfolio shows which cases are safe, which are progressing, and which require immediate governance action.
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Cases</button>
                <button class="filter-btn" data-filter="critical">Critical</button>
                <button class="filter-btn" data-filter="watch">Watch</button>
                <button class="filter-btn" data-filter="stable">Stable</button>
                <input id="searchInput" class="search" type="text" placeholder="Search system, threshold state, passport state, or restart verdict...">
            </div>

            <table id="portfolioTable">
                <thead>
                    <tr>
                        <th>Recovery Case</th>
                        <th>System</th>
                        <th>Activation</th>
                        <th>Threshold State</th>
                        <th>Dependency State</th>
                        <th>Passport</th>
                        <th>Restart</th>
                        <th>Command Center Verdict</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-state="critical" data-search="rcv-2026-014 erp full dr combined failure blocked draft restart hold critical">
                        <td>RCV-2026-014</td>
                        <td>ERP / Finance & Supply Chain</td>
                        <td><span class="pill red">Full DR</span></td>
                        <td><span class="pill red">Combined Failure</span></td>
                        <td><span class="pill red">Blocked</span></td>
                        <td><span class="pill red">Draft</span></td>
                        <td><span class="pill red">Hold</span></td>
                        <td><span class="pill red">Executive Action</span></td>
                    </tr>
                    <tr data-state="critical" data-search="rcv-2026-015 lims full dr rpo breach partial reviewable restart blocked critical">
                        <td>RCV-2026-015</td>
                        <td>LIMS / QC</td>
                        <td><span class="pill red">Full DR</span></td>
                        <td><span class="pill red">RPO Breach</span></td>
                        <td><span class="pill amber">Partial</span></td>
                        <td><span class="pill amber">Reviewable</span></td>
                        <td><span class="pill red">Hold</span></td>
                        <td><span class="pill red">Lot Decision Needed</span></td>
                    </tr>
                    <tr data-state="watch" data-search="rcv-2026-016 continuous environmental monitoring partial dr at risk partial reviewable restart partial watch">
                        <td>RCV-2026-016</td>
                        <td>Continuous Environmental Monitoring</td>
                        <td><span class="pill amber">Partial DR</span></td>
                        <td><span class="pill amber">At Risk</span></td>
                        <td><span class="pill amber">Partial</span></td>
                        <td><span class="pill amber">Reviewable</span></td>
                        <td><span class="pill amber">Partial</span></td>
                        <td><span class="pill amber">Requalify</span></td>
                    </tr>
                    <tr data-state="stable" data-search="rcv-2026-017 filter integrity testing component safe complete audit ready eligible stable">
                        <td>RCV-2026-017</td>
                        <td>Filter Integrity Testing</td>
                        <td><span class="pill blue">Component</span></td>
                        <td><span class="pill green">Safe</span></td>
                        <td><span class="pill green">Complete</span></td>
                        <td><span class="pill green">Audit-Ready</span></td>
                        <td><span class="pill green">Eligible</span></td>
                        <td><span class="pill green">Ready to Close</span></td>
                    </tr>
                    <tr data-state="stable" data-search="rcv-2026-018 environmental monitoring standard safe complete audit ready eligible stable">
                        <td>RCV-2026-018</td>
                        <td>Environmental Monitoring</td>
                        <td><span class="pill indigo">Standard</span></td>
                        <td><span class="pill green">Safe</span></td>
                        <td><span class="pill green">Complete</span></td>
                        <td><span class="pill green">Audit-Ready</span></td>
                        <td><span class="pill green">Eligible</span></td>
                        <td><span class="pill green">Governed Complete</span></td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Priority Triage Lane</h2>
                <div class="priority-grid">
                    <div class="priority-item">
                        <div class="priority-no">1</div>
                        <div>
                            <div class="priority-title">Resolve ERP data truth gap</div>
                            <div class="priority-note">
                                Missing reconciliation matrix prevents recovery closure, passport readiness, and restart authorization.
                            </div>
                        </div>
                        <div class="priority-owner">System Custodian + BQA</div>
                    </div>
                    <div class="priority-item">
                        <div class="priority-no">2</div>
                        <div>
                            <div class="priority-title">Complete ERP CSQA integrity verification</div>
                            <div class="priority-note">
                                Technical restore exists, but post-restore integrity and Part 11 posture remain unverified.
                            </div>
                        </div>
                        <div class="priority-owner">CSQA</div>
                    </div>
                    <div class="priority-item">
                        <div class="priority-no">3</div>
                        <div>
                            <div class="priority-title">Disposition LIMS lot impact</div>
                            <div class="priority-note">
                                Product consequence is unresolved even though system recovery has progressed.
                            </div>
                        </div>
                        <div class="priority-owner">BQA</div>
                    </div>
                    <div class="priority-item">
                        <div class="priority-no">4</div>
                        <div>
                            <div class="priority-title">Prepare Site Head restart briefing</div>
                            <div class="priority-note">
                                Full-DR cases need final authority only after prerequisite gates are green.
                            </div>
                        </div>
                        <div class="priority-owner">System Owner</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Authority Queue</h2>
                <div class="queue-grid">
                    <div class="queue-card">
                        <div class="queue-role">System Custodian</div>
                        <div class="queue-title">Reconciliation Upload</div>
                        <div class="queue-note">
                            ERP Data Reconciliation Matrix still not attached.
                        </div>
                        <div class="queue-state red">Blocking</div>
                    </div>
                    <div class="queue-card">
                        <div class="queue-role">Computer System QA</div>
                        <div class="queue-title">Integrity Review</div>
                        <div class="queue-note">
                            ERP and CEM post-restore integrity checks open.
                        </div>
                        <div class="queue-state amber">Pending</div>
                    </div>
                    <div class="queue-card">
                        <div class="queue-role">Business QA</div>
                        <div class="queue-title">GMP Impact</div>
                        <div class="queue-note">
                            ERP and LIMS restart decisions await BQA disposition.
                        </div>
                        <div class="queue-state red">Critical</div>
                    </div>
                    <div class="queue-card">
                        <div class="queue-role">Site Head</div>
                        <div class="queue-title">Full DR Restart</div>
                        <div class="queue-note">
                            Approval should wait until prerequisite gates are green.
                        </div>
                        <div class="queue-state amber">Not Ready</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Interactive Command Center Engine</h2>
            <p>
                This simulation shows how one executive posture changes as the underlying DR layers improve or deteriorate.
            </p>

            <div class="builder">
                <div class="builder-grid">
                    <div class="builder-row">
                        <label for="activationSelect">DR Activation State</label>
                        <select id="activationSelect">
                            <option value="full">Full DR</option>
                            <option value="partial">Partial DR</option>
                            <option value="standard">Standard Recovery</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label for="thresholdSelect">RTO / RPO State</label>
                        <select id="thresholdSelect">
                            <option value="combined">Combined Failure</option>
                            <option value="single">Single Breach</option>
                            <option value="safe">Within Threshold</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label for="dependencySelect">Recovery Dependency State</label>
                        <select id="dependencySelect">
                            <option value="blocked">Blocked</option>
                            <option value="partial">Partial</option>
                            <option value="complete">Complete</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label for="passportSelect">DR Evidence Passport</label>
                        <select id="passportSelect">
                            <option value="draft">Draft</option>
                            <option value="reviewable">Reviewable</option>
                            <option value="auditready">Audit-Ready</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label for="restartSelect">GMP Restart Gate</label>
                        <select id="restartSelect">
                            <option value="hold">Hold</option>
                            <option value="partial">Partial</option>
                            <option value="eligible">Eligible</option>
                        </select>
                    </div>
                </div>

                <div class="builder-result">
                    <div class="builder-label">Executive Recovery Verdict</div>
                    <div id="builderTitle" class="builder-title">Critical Recovery Posture</div>
                    <div id="builderVerdict" class="builder-verdict">
                        Full DR is active, threshold failure is confirmed, recovery truth is blocked, evidence is incomplete, and restart remains on hold.
                    </div>
                    <div class="builder-meta">
                        <div class="builder-mini">
                            <div class="builder-mini-label">Priority</div>
                            <div id="builderPriority" class="builder-mini-value">Immediate</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Restart</div>
                            <div id="builderRestart" class="builder-mini-value">Blocked</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Leadership Action</div>
                            <div id="builderAction" class="builder-mini-value">Escalate</div>
                        </div>
                    </div>
                    <div id="builderNote" class="builder-note">
                        The command center is strongest when it converts five separate module states into one decision-ready enterprise posture.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Recovery Scenario Inspector</h2>
            <p>
                Select a recovery scenario to inspect how the command center interprets the full multi-module chain.
            </p>

            <div class="inspector">
                <div class="inspector-list">
                    <button class="inspect-btn active" data-scenario="erp">
                        <div class="inspect-kicker">Scenario 01</div>
                        <div class="inspect-title">ERP critical recovery</div>
                        <div class="inspect-note">Full DR, combined failure, passport draft, restart blocked.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="lims">
                        <div class="inspect-kicker">Scenario 02</div>
                        <div class="inspect-title">LIMS lot-impact hold</div>
                        <div class="inspect-note">Recovery progressed, but product consequence remains open.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="cem">
                        <div class="inspect-kicker">Scenario 03</div>
                        <div class="inspect-title">CEM watch state</div>
                        <div class="inspect-note">Partial DR with requalification still needed.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="stable">
                        <div class="inspect-kicker">Scenario 04</div>
                        <div class="inspect-title">Governed complete recovery</div>
                        <div class="inspect-note">All layers green and ready for certificate.</div>
                    </button>
                </div>

                <div class="inspector-card">
                    <div class="inspector-label">Selected Scenario</div>
                    <div id="inspectorTitle" class="inspector-title">ERP critical recovery</div>
                    <div class="inspector-meta">
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Activation</div>
                            <div id="inspectorActivation" class="inspector-mini-value">Full DR</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Thresholds</div>
                            <div id="inspectorThresholds" class="inspector-mini-value">Combined Failure</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Passport</div>
                            <div id="inspectorPassport" class="inspector-mini-value">Draft</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Restart</div>
                            <div id="inspectorRestart" class="inspector-mini-value">Hold</div>
                        </div>
                    </div>
                    <div id="inspectorVerdict" class="inspector-verdict">
                        This is the highest-priority enterprise recovery case because every major governance layer is still red or blocked.
                    </div>
                    <div id="inspectorNote" class="inspector-note">
                        Leadership should focus first on data reconciliation, QA verification, and restart-authority readiness.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Command Center Action Console</h2>
            <p>
                The command center turns enterprise posture into the next highest-value action.
            </p>

            <div class="action-console">
                <div class="action-list">
                    <div class="action-item">
                        <div>
                            <h3>Escalate ERP to executive mission control</h3>
                            <p>Route the highest-priority case with full-chain blockers visible.</p>
                        </div>
                        <button class="action-btn" data-action="escalate">Escalate</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Open ERP recovery strike team</h3>
                            <p>Bundle reconciliation, CSQA, BQA, and restart tasks into one workstream.</p>
                        </div>
                        <button class="action-btn" data-action="strike">Open</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Prepare restart-readiness briefing</h3>
                            <p>Build the executive summary for BQA and Site Head review.</p>
                        </div>
                        <button class="action-btn" data-action="briefing">Prepare</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Advance stable case to certificate</h3>
                            <p>Move fully green recovery cases toward final controlled closure.</p>
                        </div>
                        <button class="action-btn" data-action="certificate">Advance</button>
                    </div>
                </div>

                <div id="consoleResult" class="console-result">
                    <div class="console-label">Command Center Outcome</div>
                    <div id="consoleTitle" class="console-title">Awaiting Action</div>
                    <div id="consoleNote" class="console-note">
                        Select an action to see how recovery intelligence becomes coordinated enterprise action.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>Individual DR Modules</h3>
                <p>
                    Explain activation, thresholds, dependencies, evidence, and restart separately.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Recovery Governance Command Center</h3>
                <p>
                    Unifies them into one executive recovery posture and action queue.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    COBIT-Chain™ now behaves like an operational recovery digital twin, not a set of disconnected dashboards.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by the Recovery Governance Command Center</h2>
            <p>
                The earlier DR modules answer separate questions:
                <strong>Should DR activate? Which thresholds failed? Is recovery truth complete? Is the evidence ready? Can GMP restart?</strong>
            </p>
            <p>
                Recovery Governance Command Center™ answers:
                <strong>“Across the whole recovery estate, what is the enterprise posture right now, what is blocked, and what should leadership do first?”</strong>
            </p>
            <p>
                That turns the DR branch into a true command layer. It consolidates recovery intelligence, decision priority,
                approval queues, and executive action into one operational view.
            </p>
            <div class="footer-note">
                DR branch: DR Activation Intelligence™ → RTO / RPO Governance Intelligence™ →
                Recovery Dependency Validation™ → DR Evidence Passport™ → GMP Restart Gate™ →
                Recovery Governance Command Center™ → future DR Recovery Certificate™.
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#portfolioTable tbody tr");
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

        const activationSelect = document.getElementById("activationSelect");
        const thresholdSelect = document.getElementById("thresholdSelect");
        const dependencySelect = document.getElementById("dependencySelect");
        const passportSelect = document.getElementById("passportSelect");
        const restartSelect = document.getElementById("restartSelect");
        const builderTitle = document.getElementById("builderTitle");
        const builderVerdict = document.getElementById("builderVerdict");
        const builderPriority = document.getElementById("builderPriority");
        const builderRestart = document.getElementById("builderRestart");
        const builderAction = document.getElementById("builderAction");
        const builderNote = document.getElementById("builderNote");

        function updateBuilder() {
            const activation = activationSelect.value;
            const threshold = thresholdSelect.value;
            const dependency = dependencySelect.value;
            const passport = passportSelect.value;
            const restart = restartSelect.value;

            const redSignals = [
                activation === "full",
                threshold === "combined",
                dependency === "blocked",
                passport === "draft",
                restart === "hold"
            ].filter(Boolean).length;

            const amberSignals = [
                activation === "partial",
                threshold === "single",
                dependency === "partial",
                passport === "reviewable",
                restart === "partial"
            ].filter(Boolean).length;

            if (redSignals >= 3) {
                builderTitle.textContent = "Critical Recovery Posture";
                builderVerdict.textContent = "Multiple red conditions are active across the recovery chain. Executive intervention and cross-functional coordination are required.";
                builderPriority.textContent = "Immediate";
                builderRestart.textContent = "Blocked";
                builderAction.textContent = "Escalate";
                builderNote.textContent = "The command center is strongest when it converts five separate module states into one decision-ready enterprise posture.";
            } else if (redSignals >= 1 || amberSignals >= 3) {
                builderTitle.textContent = "Managed Recovery Posture";
                builderVerdict.textContent = "Recovery is progressing, but one or more governance conditions still require active management before clean closure.";
                builderPriority.textContent = "High";
                builderRestart.textContent = restart === "eligible" ? "Eligible" : "Pending";
                builderAction.textContent = "Coordinate";
                builderNote.textContent = "This is where leadership should focus on clearing remaining blockers before they become restart or audit issues.";
            } else {
                builderTitle.textContent = "Governed Recovery Complete";
                builderVerdict.textContent = "All major recovery layers are green. The case is ready to move toward final controlled certification.";
                builderPriority.textContent = "Normal";
                builderRestart.textContent = "Eligible";
                builderAction.textContent = "Certify";
                builderNote.textContent = "The enterprise can only reach this state when activation, thresholds, dependencies, evidence, and restart logic all agree.";
            }
        }

        [activationSelect, thresholdSelect, dependencySelect, passportSelect, restartSelect].forEach(element => {
            element.addEventListener("change", updateBuilder);
        });

        updateBuilder();

        const inspectButtons = document.querySelectorAll(".inspect-btn");
        const inspectorTitle = document.getElementById("inspectorTitle");
        const inspectorActivation = document.getElementById("inspectorActivation");
        const inspectorThresholds = document.getElementById("inspectorThresholds");
        const inspectorPassport = document.getElementById("inspectorPassport");
        const inspectorRestart = document.getElementById("inspectorRestart");
        const inspectorVerdict = document.getElementById("inspectorVerdict");
        const inspectorNote = document.getElementById("inspectorNote");

        const scenarios = {
            erp: {
                title: "ERP critical recovery",
                activation: "Full DR",
                thresholds: "Combined Failure",
                passport: "Draft",
                restart: "Hold",
                verdict: "This is the highest-priority enterprise recovery case because every major governance layer is still red or blocked.",
                note: "Leadership should focus first on data reconciliation, QA verification, and restart-authority readiness."
            },
            lims: {
                title: "LIMS lot-impact hold",
                activation: "Full DR",
                thresholds: "RPO Breach",
                passport: "Reviewable",
                restart: "Hold",
                verdict: "Recovery is progressing, but product consequence remains unresolved and still blocks restart.",
                note: "The command center keeps lot disposition visible as a leadership issue, not a hidden downstream detail."
            },
            cem: {
                title: "CEM watch state",
                activation: "Partial DR",
                thresholds: "At Risk",
                passport: "Reviewable",
                restart: "Partial",
                verdict: "The event is improving, but requalification and remaining evidence work keep it under active governance watch.",
                note: "This is not critical red, but it is not yet ready to disappear from executive view."
            },
            stable: {
                title: "Governed complete recovery",
                activation: "Standard",
                thresholds: "Safe",
                passport: "Audit-Ready",
                restart: "Eligible",
                verdict: "All major recovery layers are green and aligned.",
                note: "This case is ready to advance to final recovery certification."
            }
        };

        inspectButtons.forEach(button => {
            button.addEventListener("click", () => {
                inspectButtons.forEach(btn => btn.classList.remove("active"));
                button.classList.add("active");

                const item = scenarios[button.dataset.scenario];
                inspectorTitle.textContent = item.title;
                inspectorActivation.textContent = item.activation;
                inspectorThresholds.textContent = item.thresholds;
                inspectorPassport.textContent = item.passport;
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
            escalate: {
                title: "ERP Escalated to Mission Control",
                note: "The critical recovery case has been routed with full-chain blockers visible to executive leadership."
            },
            strike: {
                title: "Recovery Strike Team Opened",
                note: "Reconciliation, CSQA, BQA, and restart tasks have been grouped into one coordinated workstream."
            },
            briefing: {
                title: "Restart Briefing Prepared",
                note: "A concise readiness summary is ready for BQA and Site Head review once prerequisite gates are complete."
            },
            certificate: {
                title: "Stable Case Advanced",
                note: "The fully green recovery case is ready to move toward final controlled certification."
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
        print("SKIP: RECOVERY_GOVERNANCE_COMMAND_CENTER_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/recovery-governance-command-center")',
        "Recovery Governance Command Center™",
        "Integrated Recovery Chain Status",
        "Active Recovery Portfolio",
        "Interactive Command Center Engine",
        "Command Center Action Console",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /recovery-governance-command-center route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
