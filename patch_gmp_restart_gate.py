from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# GMP_RESTART_GATE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# GMP_RESTART_GATE_ACTIVE
@app.route("/gmp-restart-gate")
def gmp_restart_gate_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>GMP Restart Gate™ | COBIT-Chain™ / AssuranceLayer™</title>
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
            background: linear-gradient(135deg, #111827 0%, #7f1d1d 44%, #0f766e 100%);
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
        .case-card {
            background: linear-gradient(180deg, #ffffff 0%, #fff7ed 100%);
            border: 1px solid #fed7aa;
            border-radius: 22px;
            padding: 20px;
        }
        .case-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #9a3412;
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
        .readiness-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .readiness-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .readiness-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .readiness-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .readiness-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .readiness-card.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .readiness-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .readiness-value {
            font-size: 28px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .readiness-note {
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
            background: #7f1d1d;
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
            grid-template-columns: repeat(7, minmax(0, 1fr));
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
        .gate-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .gate-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .gate-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .gate-state {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
            margin-bottom: 10px;
        }
        .gate-state.green {
            background: #dcfce7;
            color: #166534;
        }
        .gate-state.amber {
            background: #fef3c7;
            color: #92400e;
        }
        .gate-state.red {
            background: #fee2e2;
            color: #991b1b;
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
        .approval-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 12px;
        }
        .approval-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
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
            margin-bottom: 10px;
        }
        .approval-state {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
        }
        .approval-state.green {
            background: #dcfce7;
            color: #166534;
        }
        .approval-state.amber {
            background: #fef3c7;
            color: #92400e;
        }
        .approval-state.red {
            background: #fee2e2;
            color: #991b1b;
        }
        .hold-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .hold-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .hold-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .hold-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .hold-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .hold-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .hold-value {
            font-size: 24px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .hold-note {
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
            background: #fff7ed;
        }
        .inspect-btn.active {
            border-color: #fdba74;
            background: #fff7ed;
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
            background: #fff7ed;
            border: 1px solid #fdba74;
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
            color: #9a3412;
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
            background: #7f1d1d;
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
            border-left: 5px solid #7f1d1d;
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
            .builder,
            .inspector,
            .action-console {
                grid-template-columns: 1fr;
            }
            .workflow {
                grid-template-columns: repeat(4, minmax(0, 1fr));
            }
            .gate-grid {
                grid-template-columns: repeat(4, minmax(0, 1fr));
            }
            .readiness-grid,
            .hold-grid,
            .approval-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .workflow,
            .gate-grid,
            .readiness-grid,
            .hold-grid,
            .approval-grid,
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
                <a href="/dr-evidence-passport">DR Evidence Passport</a>
                <a href="/recovery-dependency-validation">Recovery Dependencies</a>
                <a href="/rto-rpo-governance-intelligence">RTO / RPO Intelligence</a>
                <a href="/dr-activation-intelligence">DR Activation</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Controlled Business Resumption Layer</div>
            <h1>GMP Restart Gate™</h1>
            <p>
                The formal gate between recovery and regulated resumption. A system may be technically restored and still
                remain unfit for GMP restart if data reconciliation is incomplete, CSQA integrity verification is open,
                BQA has not approved process impact, material quarantine remains unresolved, downstream dependencies are not
                clear, or final restart authority has not been granted.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Restart Case</div>
                    <div class="hero-value">RST-2026-014</div>
                    <div class="hero-note">ERP / Full DR recovery</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Technical Recovery</div>
                    <div class="hero-value">Complete</div>
                    <div class="hero-note">System back online</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Gate Status</div>
                    <div class="hero-value">Blocked</div>
                    <div class="hero-note">Evidence gaps remain</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Open Restart Gates</div>
                    <div class="hero-value">4</div>
                    <div class="hero-note">Reconcile / CSQA / BQA / Site Head</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">GMP Posture</div>
                    <div class="hero-value">Hold</div>
                    <div class="hero-note">No resumption yet</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Restart Authority</div>
                    <div class="hero-value">Pending</div>
                    <div class="hero-note">Site Head not approved</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Selected Restart Case</h2>
                <div class="case-card">
                    <div class="case-kicker">Restart Decision Case</div>
                    <div class="case-title">ERP / Finance & Supply Chain</div>
                    <div class="case-note">
                        The ERP platform has been technically restored after a Level 4 event, but GMP resumption remains blocked.
                        The DR Evidence Passport is still draft, the Data Reconciliation Matrix is not yet approved, CSQA integrity
                        verification remains pending, BQA has not cleared GMP impact, and full-DR restart authority has not yet been granted.
                    </div>

                    <div class="case-meta">
                        <div class="meta-card">
                            <div class="meta-label">Recovery Level</div>
                            <div class="meta-value">Full DR</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Passport State</div>
                            <div class="meta-value">Draft</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Current Decision</div>
                            <div class="meta-value">Do Not Restart</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Final Authority</div>
                            <div class="meta-value">Site Head</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Restart Readiness Snapshot</h2>
                <div class="readiness-grid">
                    <div class="readiness-card green">
                        <div class="readiness-label">Technical Restore</div>
                        <div class="readiness-value">Pass</div>
                        <div class="readiness-note">Application and database restored.</div>
                    </div>
                    <div class="readiness-card red">
                        <div class="readiness-label">Data Reconciliation</div>
                        <div class="readiness-value">Fail</div>
                        <div class="readiness-note">Approved matrix still missing.</div>
                    </div>
                    <div class="readiness-card amber">
                        <div class="readiness-label">Quality Verification</div>
                        <div class="readiness-value">Pending</div>
                        <div class="readiness-note">CSQA and BQA not complete.</div>
                    </div>
                    <div class="readiness-card red">
                        <div class="readiness-label">Restart Authority</div>
                        <div class="readiness-value">Missing</div>
                        <div class="readiness-note">Site Head approval not granted.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>GMP Restart Workflow</h2>
            <div class="workflow">
                <div class="step">
                    <div class="step-number">1</div>
                    <h3>Restore</h3>
                    <p>Technical system recovery completes.</p>
                </div>
                <div class="step">
                    <div class="step-number">2</div>
                    <h3>Passport</h3>
                    <p>DR evidence record is assembled and reviewed.</p>
                </div>
                <div class="step">
                    <div class="step-number">3</div>
                    <h3>Reconcile</h3>
                    <p>Restored data is matched to GMP and paper records.</p>
                </div>
                <div class="step">
                    <div class="step-number">4</div>
                    <h3>Verify</h3>
                    <p>CSQA confirms integrity and Part 11 posture.</p>
                </div>
                <div class="step">
                    <div class="step-number">5</div>
                    <h3>Assess</h3>
                    <p>BQA clears GMP process and batch impact.</p>
                </div>
                <div class="step">
                    <div class="step-number">6</div>
                    <h3>Clear Dependencies</h3>
                    <p>Materials, lots, utilities, and downstream systems are cleared.</p>
                </div>
                <div class="step">
                    <div class="step-number">7</div>
                    <h3>Authorize</h3>
                    <p>Correct authority grants controlled restart.</p>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Restart Gate Matrix</h2>
            <p>
                A GMP restart may proceed only when every required gate is satisfied.
            </p>

            <div class="gate-grid">
                <div class="gate-card green">
                    <div class="gate-title">Gate 01 — Technical Restore</div>
                    <div class="gate-state green">PASS</div>
                    <div class="gate-note">Infrastructure, application, and database recovered.</div>
                </div>
                <div class="gate-card red">
                    <div class="gate-title">Gate 02 — DR Passport</div>
                    <div class="gate-state red">FAIL</div>
                    <div class="gate-note">Evidence passport not yet audit-ready.</div>
                </div>
                <div class="gate-card red">
                    <div class="gate-title">Gate 03 — Reconciliation</div>
                    <div class="gate-state red">FAIL</div>
                    <div class="gate-note">Data reconciliation matrix still missing.</div>
                </div>
                <div class="gate-card amber">
                    <div class="gate-title">Gate 04 — CSQA Integrity</div>
                    <div class="gate-state amber">PENDING</div>
                    <div class="gate-note">Post-restore integrity verification open.</div>
                </div>
                <div class="gate-card amber">
                    <div class="gate-title">Gate 05 — BQA Impact</div>
                    <div class="gate-state amber">PENDING</div>
                    <div class="gate-note">GMP process approval not yet complete.</div>
                </div>
                <div class="gate-card red">
                    <div class="gate-title">Gate 06 — Dependency Clear</div>
                    <div class="gate-state red">FAIL</div>
                    <div class="gate-note">Material / downstream effects unresolved.</div>
                </div>
                <div class="gate-card red">
                    <div class="gate-title">Gate 07 — Restart Authority</div>
                    <div class="gate-state red">FAIL</div>
                    <div class="gate-note">Site Head approval required for full DR.</div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>GMP Restart Decision Register</h2>
            <p>
                Each case is assessed separately so “system online” is never confused with “GMP restart permitted.”
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Cases</button>
                <button class="filter-btn" data-filter="eligible">Eligible</button>
                <button class="filter-btn" data-filter="partial">Partial</button>
                <button class="filter-btn" data-filter="blocked">Blocked</button>
                <input id="searchInput" class="search" type="text" placeholder="Search system, recovery level, blocker, or restart state...">
            </div>

            <table id="restartTable">
                <thead>
                    <tr>
                        <th>Restart Case</th>
                        <th>System</th>
                        <th>Recovery Level</th>
                        <th>Evidence Passport</th>
                        <th>Quality Gates</th>
                        <th>Dependencies</th>
                        <th>Authority</th>
                        <th>Restart Verdict</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-state="blocked" data-search="rst-2026-014 erp full dr passport draft reconciliation missing csqa pending bqa pending site head pending blocked">
                        <td>RST-2026-014</td>
                        <td>ERP / Finance & Supply Chain</td>
                        <td><span class="pill red">Full DR</span></td>
                        <td><span class="pill red">Draft</span></td>
                        <td><span class="pill amber">Pending</span></td>
                        <td><span class="pill red">Open</span></td>
                        <td><span class="pill red">Site Head pending</span></td>
                        <td><span class="pill red">Blocked</span></td>
                    </tr>
                    <tr data-state="partial" data-search="rst-2026-015 continuous environmental monitoring partial dr passport reviewable sensor requal pending bqa pending dependencies partial">
                        <td>RST-2026-015</td>
                        <td>Continuous Environmental Monitoring</td>
                        <td><span class="pill amber">Partial DR</span></td>
                        <td><span class="pill amber">Reviewable</span></td>
                        <td><span class="pill amber">Sensor requal pending</span></td>
                        <td><span class="pill amber">Manual logs pending</span></td>
                        <td><span class="pill amber">BQA pending</span></td>
                        <td><span class="pill amber">Partial</span></td>
                    </tr>
                    <tr data-state="eligible" data-search="rst-2026-016 filter integrity testing component recovery passport audit ready csqa verified bqa approved dependencies clear eligible">
                        <td>RST-2026-016</td>
                        <td>Filter Integrity Testing</td>
                        <td><span class="pill blue">Component</span></td>
                        <td><span class="pill green">Audit-Ready</span></td>
                        <td><span class="pill green">Verified</span></td>
                        <td><span class="pill green">Clear</span></td>
                        <td><span class="pill green">BQA approved</span></td>
                        <td><span class="pill green">Eligible</span></td>
                    </tr>
                    <tr data-state="blocked" data-search="rst-2026-017 lims full dr passport reviewable lot disposition open bqa not approved site head pending blocked">
                        <td>RST-2026-017</td>
                        <td>LIMS / QC</td>
                        <td><span class="pill red">Full DR</span></td>
                        <td><span class="pill amber">Reviewable</span></td>
                        <td><span class="pill amber">CSQA complete</span></td>
                        <td><span class="pill red">Lot disposition open</span></td>
                        <td><span class="pill red">Site Head pending</span></td>
                        <td><span class="pill red">Blocked</span></td>
                    </tr>
                    <tr data-state="eligible" data-search="rst-2026-018 environmental monitoring standard recovery passport audit ready bqa approved qa approved dependencies clear eligible">
                        <td>RST-2026-018</td>
                        <td>Environmental Monitoring</td>
                        <td><span class="pill indigo">System</span></td>
                        <td><span class="pill green">Audit-Ready</span></td>
                        <td><span class="pill green">Verified</span></td>
                        <td><span class="pill green">Clear</span></td>
                        <td><span class="pill green">BQA approved</span></td>
                        <td><span class="pill green">Eligible</span></td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Restart Approval Chain</h2>
                <div class="approval-grid">
                    <div class="approval-card">
                        <div class="approval-role">System Custodian</div>
                        <div class="approval-name">Technical Restore</div>
                        <div class="approval-note">
                            Confirms the platform, database, and restore actions are complete.
                        </div>
                        <div class="approval-state green">Complete</div>
                    </div>
                    <div class="approval-card">
                        <div class="approval-role">Computer System QA</div>
                        <div class="approval-name">Integrity Verification</div>
                        <div class="approval-note">
                            Confirms audit trails, system integrity, and post-restore validation posture.
                        </div>
                        <div class="approval-state amber">Pending</div>
                    </div>
                    <div class="approval-card">
                        <div class="approval-role">Business QA</div>
                        <div class="approval-name">GMP Impact Approval</div>
                        <div class="approval-note">
                            Assesses batch status, material quarantine, and process-resumption impact.
                        </div>
                        <div class="approval-state amber">Pending</div>
                    </div>
                    <div class="approval-card">
                        <div class="approval-role">Supply Chain / Logistics</div>
                        <div class="approval-name">Material Reconciliation</div>
                        <div class="approval-note">
                            Clears inventory / quarantine dependencies before restart.
                        </div>
                        <div class="approval-state red">Open</div>
                    </div>
                    <div class="approval-card">
                        <div class="approval-role">Site Head</div>
                        <div class="approval-name">Full DR Restart</div>
                        <div class="approval-note">
                            Grants final GMP restart approval for end-to-end disaster recovery.
                        </div>
                        <div class="approval-state red">Pending</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Why Restart Remains on Hold</h2>
                <div class="hold-grid">
                    <div class="hold-card red">
                        <div class="hold-title">Data Truth</div>
                        <div class="hold-value">Missing</div>
                        <div class="hold-note">No approved reconciliation matrix yet.</div>
                    </div>
                    <div class="hold-card amber">
                        <div class="hold-title">QA Integrity</div>
                        <div class="hold-value">Pending</div>
                        <div class="hold-note">CSQA has not completed review.</div>
                    </div>
                    <div class="hold-card red">
                        <div class="hold-title">GMP Impact</div>
                        <div class="hold-value">Open</div>
                        <div class="hold-note">BQA has not cleared batch / material effect.</div>
                    </div>
                    <div class="hold-card red">
                        <div class="hold-title">Final Authority</div>
                        <div class="hold-value">Absent</div>
                        <div class="hold-note">Site Head approval required for full DR.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Interactive Restart Gate Builder</h2>
            <p>
                This simulation shows why a recovered system should still be blocked from GMP restart until every resumption dependency is proven.
            </p>

            <div class="builder">
                <div class="builder-grid">
                    <div class="builder-row">
                        <label for="levelSelect">Recovery Level</label>
                        <select id="levelSelect">
                            <option value="full">Full DR</option>
                            <option value="system">System Recovery</option>
                            <option value="component">Component Recovery</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label>Required Restart Gates</label>
                        <div class="check-grid">
                            <label class="check-row">
                                <input id="checkRestore" type="checkbox" checked>
                                Technical restore complete
                            </label>
                            <label class="check-row">
                                <input id="checkPassport" type="checkbox">
                                DR Evidence Passport audit-ready
                            </label>
                            <label class="check-row">
                                <input id="checkReconcile" type="checkbox">
                                Data reconciliation approved
                            </label>
                            <label class="check-row">
                                <input id="checkCsqa" type="checkbox">
                                CSQA integrity verification complete
                            </label>
                            <label class="check-row">
                                <input id="checkBqa" type="checkbox">
                                BQA GMP impact assessment approved
                            </label>
                            <label class="check-row">
                                <input id="checkDependencies" type="checkbox">
                                Downstream / material dependencies clear
                            </label>
                            <label class="check-row" id="siteHeadRow">
                                <input id="checkSiteHead" type="checkbox">
                                Site Head restart approval granted
                            </label>
                        </div>
                    </div>
                </div>

                <div class="builder-result">
                    <div class="builder-label">Restart Verdict</div>
                    <div id="builderTitle" class="builder-title">GMP Restart Blocked</div>
                    <div id="builderVerdict" class="builder-verdict">
                        Technical recovery is complete, but the restart chain is not. Required evidence, QA, dependency, and authority gates remain open.
                    </div>
                    <div class="builder-meta">
                        <div class="builder-mini">
                            <div class="builder-mini-label">Gates Passed</div>
                            <div id="builderChecks" class="builder-mini-value">1 / 7</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Restart State</div>
                            <div id="builderState" class="builder-mini-value">Blocked</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">GMP Posture</div>
                            <div id="builderGmp" class="builder-mini-value">Hold</div>
                        </div>
                    </div>
                    <div id="builderNote" class="builder-note">
                        A restored system can remain unavailable for GMP use until resumption is formally proven and approved.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Restart Scenario Inspector</h2>
            <p>
                Select a scenario to inspect why a restart is blocked, partial, or eligible.
            </p>

            <div class="inspector">
                <div class="inspector-list">
                    <button class="inspect-btn active" data-scenario="erp">
                        <div class="inspect-kicker">Scenario 01</div>
                        <div class="inspect-title">ERP restored, GMP restart blocked</div>
                        <div class="inspect-note">System online but passport, QA, and authority gates remain open.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="cem">
                        <div class="inspect-kicker">Scenario 02</div>
                        <div class="inspect-title">Environmental controls restored, requalification pending</div>
                        <div class="inspect-note">Technical fix complete but cleanroom / monitoring assurance incomplete.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="lims">
                        <div class="inspect-kicker">Scenario 03</div>
                        <div class="inspect-title">LIMS restored, lot disposition still open</div>
                        <div class="inspect-note">Data recovered but product / lot consequence unresolved.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="ready">
                        <div class="inspect-kicker">Scenario 04</div>
                        <div class="inspect-title">All gates clear</div>
                        <div class="inspect-note">Controlled restart is now eligible.</div>
                    </button>
                </div>

                <div class="inspector-card">
                    <div class="inspector-label">Selected Scenario</div>
                    <div id="inspectorTitle" class="inspector-title">ERP restored, GMP restart blocked</div>
                    <div class="inspector-meta">
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Technical State</div>
                            <div id="inspectorTechnical" class="inspector-mini-value">Restored</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Primary Blocker</div>
                            <div id="inspectorBlocker" class="inspector-mini-value">QA + authority</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Restart Verdict</div>
                            <div id="inspectorVerdictState" class="inspector-mini-value">Blocked</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Next Authority</div>
                            <div id="inspectorAuthority" class="inspector-mini-value">BQA / Site Head</div>
                        </div>
                    </div>
                    <div id="inspectorVerdict" class="inspector-verdict">
                        ERP is technically available, but GMP restart cannot be approved while reconciliation, QA verification, and final restart authority remain incomplete.
                    </div>
                    <div id="inspectorNote" class="inspector-note">
                        This is the core distinction the gate enforces: operational availability does not equal regulated resumption.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Restart Action Console</h2>
            <p>
                The gate routes each restart blocker toward the next required governance action.
            </p>

            <div class="action-console">
                <div class="action-list">
                    <div class="action-item">
                        <div>
                            <h3>Keep GMP restart on hold</h3>
                            <p>Prevent resumption while data, QA, and authority gates remain incomplete.</p>
                        </div>
                        <button class="action-btn" data-action="hold">Hold</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Request BQA impact decision</h3>
                            <p>Route batch, material, and process-impact assessment for approval.</p>
                        </div>
                        <button class="action-btn" data-action="bqa">Request</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Escalate to Site Head</h3>
                            <p>Prepare full-DR restart decision once all prerequisite gates are green.</p>
                        </div>
                        <button class="action-btn" data-action="sitehead">Escalate</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Authorize controlled restart</h3>
                            <p>Release restart only when the full chain is proven complete.</p>
                        </div>
                        <button class="action-btn" data-action="authorize">Authorize</button>
                    </div>
                </div>

                <div id="consoleResult" class="console-result">
                    <div class="console-label">Restart Outcome</div>
                    <div id="consoleTitle" class="console-title">Awaiting Action</div>
                    <div id="consoleNote" class="console-note">
                        Select an action to see how the platform governs the move from recovery to regulated resumption.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>DR Evidence Passport</h3>
                <p>
                    Preserves the controlled recovery evidence required for review.
                </p>
            </div>
            <div class="maturity-card">
                <h3>GMP Restart Gate</h3>
                <p>
                    Decides whether regulated activity may actually resume after recovery.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    COBIT-Chain™ now separates “recovered technically” from “approved to operate.”
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by the GMP Restart Gate</h2>
            <p>
                DR Evidence Passport™ answers:
                <strong>“Do we have the controlled evidence proving the recovery state?”</strong>
            </p>
            <p>
                GMP Restart Gate™ answers:
                <strong>“Even with recovery evidence, is the enterprise actually allowed to resume GMP activity?”</strong>
            </p>
            <p>
                That is a major maturity jump. The platform now treats restart as a governed decision requiring evidence,
                QA verification, business impact clearance, dependency resolution, and the proper approval authority.
            </p>
            <div class="footer-note">
                DR branch: DR Activation Intelligence™ → RTO / RPO Governance Intelligence™ →
                Recovery Dependency Validation™ → DR Evidence Passport™ → GMP Restart Gate™ →
                future Recovery Governance Command Center™ → DR Recovery Certificate™.
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#restartTable tbody tr");
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

        const levelSelect = document.getElementById("levelSelect");
        const siteHeadRow = document.getElementById("siteHeadRow");
        const checkRestore = document.getElementById("checkRestore");
        const checkPassport = document.getElementById("checkPassport");
        const checkReconcile = document.getElementById("checkReconcile");
        const checkCsqa = document.getElementById("checkCsqa");
        const checkBqa = document.getElementById("checkBqa");
        const checkDependencies = document.getElementById("checkDependencies");
        const checkSiteHead = document.getElementById("checkSiteHead");
        const builderTitle = document.getElementById("builderTitle");
        const builderVerdict = document.getElementById("builderVerdict");
        const builderChecks = document.getElementById("builderChecks");
        const builderState = document.getElementById("builderState");
        const builderGmp = document.getElementById("builderGmp");
        const builderNote = document.getElementById("builderNote");

        function requiredChecks() {
            const base = [checkRestore, checkPassport, checkReconcile, checkCsqa, checkBqa, checkDependencies];
            if (levelSelect.value === "full") {
                return [...base, checkSiteHead];
            }
            return base;
        }

        function updateBuilder() {
            const checks = requiredChecks();
            const passed = checks.filter(check => check.checked).length;
            const total = checks.length;

            siteHeadRow.style.display = levelSelect.value === "full" ? "flex" : "none";
            builderChecks.textContent = passed + " / " + total;

            if (passed === total) {
                builderTitle.textContent = "Controlled Restart Eligible";
                builderVerdict.textContent = "All required recovery, evidence, QA, dependency, and authority gates are complete. Regulated restart may proceed under controlled authorization.";
                builderState.textContent = "Eligible";
                builderGmp.textContent = "Resume";
                builderNote.textContent = "Restart is allowed only after the full resumption chain is proven, not merely after the system comes back online.";
            } else if (passed >= Math.ceil(total * 0.6)) {
                builderTitle.textContent = "Restart Pending";
                builderVerdict.textContent = "Several gates are complete, but one or more restart dependencies remain open. GMP activity must stay on hold.";
                builderState.textContent = "Pending";
                builderGmp.textContent = "Hold";
                builderNote.textContent = "Near-complete recovery is still not permission to resume regulated work.";
            } else {
                builderTitle.textContent = "GMP Restart Blocked";
                builderVerdict.textContent = "Technical recovery may exist, but the restart chain is not sufficiently complete. Required evidence, QA, dependency, or authority gates remain open.";
                builderState.textContent = "Blocked";
                builderGmp.textContent = "Hold";
                builderNote.textContent = "A restored system can remain unavailable for GMP use until resumption is formally proven and approved.";
            }
        }

        [levelSelect, checkRestore, checkPassport, checkReconcile, checkCsqa, checkBqa, checkDependencies, checkSiteHead].forEach(element => {
            element.addEventListener("change", updateBuilder);
        });

        updateBuilder();

        const inspectButtons = document.querySelectorAll(".inspect-btn");
        const inspectorTitle = document.getElementById("inspectorTitle");
        const inspectorTechnical = document.getElementById("inspectorTechnical");
        const inspectorBlocker = document.getElementById("inspectorBlocker");
        const inspectorVerdictState = document.getElementById("inspectorVerdictState");
        const inspectorAuthority = document.getElementById("inspectorAuthority");
        const inspectorVerdict = document.getElementById("inspectorVerdict");
        const inspectorNote = document.getElementById("inspectorNote");

        const scenarios = {
            erp: {
                title: "ERP restored, GMP restart blocked",
                technical: "Restored",
                blocker: "QA + authority",
                state: "Blocked",
                authority: "BQA / Site Head",
                verdict: "ERP is technically available, but GMP restart cannot be approved while reconciliation, QA verification, and final restart authority remain incomplete.",
                note: "This is the core distinction the gate enforces: operational availability does not equal regulated resumption."
            },
            cem: {
                title: "Environmental controls restored, requalification pending",
                technical: "Restored",
                blocker: "Sensor requalification",
                state: "Partial",
                authority: "BQA",
                verdict: "The monitoring system is back, but cleanroom / sensor assurance is still incomplete and production resumption remains unsafe.",
                note: "Environmental recovery needs more than uptime; it needs requalification and operational confidence."
            },
            lims: {
                title: "LIMS restored, lot disposition still open",
                technical: "Restored",
                blocker: "Lot disposition",
                state: "Blocked",
                authority: "BQA / Site Head",
                verdict: "Data recovery does not clear product consequence. Restart remains blocked while lot disposition and GMP impact stay unresolved.",
                note: "The gate keeps product and patient-risk consequence tied to the restart decision."
            },
            ready: {
                title: "All gates clear",
                technical: "Restored",
                blocker: "None",
                state: "Eligible",
                authority: "Approved",
                verdict: "Technical restore, evidence passport, reconciliation, QA, dependencies, and authority are all complete.",
                note: "This is the only state that should allow controlled restart."
            }
        };

        inspectButtons.forEach(button => {
            button.addEventListener("click", () => {
                inspectButtons.forEach(btn => btn.classList.remove("active"));
                button.classList.add("active");

                const item = scenarios[button.dataset.scenario];
                inspectorTitle.textContent = item.title;
                inspectorTechnical.textContent = item.technical;
                inspectorBlocker.textContent = item.blocker;
                inspectorVerdictState.textContent = item.state;
                inspectorAuthority.textContent = item.authority;
                inspectorVerdict.textContent = item.verdict;
                inspectorNote.textContent = item.note;
            });
        });

        const actionButtons = document.querySelectorAll(".action-btn");
        const consoleResult = document.getElementById("consoleResult");
        const consoleTitle = document.getElementById("consoleTitle");
        const consoleNote = document.getElementById("consoleNote");

        const outcomes = {
            hold: {
                title: "GMP Restart Held",
                note: "Regulated activity remains blocked until reconciliation, QA verification, dependencies, and authority gates are complete."
            },
            bqa: {
                title: "BQA Decision Requested",
                note: "Batch, material, and GMP process-impact review has been routed for formal approval."
            },
            sitehead: {
                title: "Site Head Escalation Prepared",
                note: "Full-DR restart approval is ready for Site Head review once every prerequisite gate is green."
            },
            authorize: {
                title: "Controlled Restart Authorized",
                note: "Restart may proceed only when the full chain is complete and the correct authority has approved resumption."
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
        print("SKIP: GMP_RESTART_GATE_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/gmp-restart-gate")',
        "GMP Restart Gate™",
        "Restart Gate Matrix",
        "GMP Restart Decision Register",
        "Interactive Restart Gate Builder",
        "Restart Action Console",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /gmp-restart-gate route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
