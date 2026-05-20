from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# DR_RECOVERY_CERTIFICATE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# DR_RECOVERY_CERTIFICATE_ACTIVE
@app.route("/dr-recovery-certificate")
def dr_recovery_certificate_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DR Recovery Certificate™ | COBIT-Chain™ / AssuranceLayer™</title>
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
            background: linear-gradient(135deg, #111827 0%, #166534 42%, #1d4ed8 100%);
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
        .certificate-card {
            background: linear-gradient(180deg, #ffffff 0%, #ecfdf5 100%);
            border: 1px solid #a7f3d0;
            border-radius: 22px;
            padding: 20px;
        }
        .certificate-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #166534;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .certificate-title {
            font-size: 24px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .certificate-note {
            color: #4c5b73;
            line-height: 1.55;
            margin-bottom: 16px;
        }
        .certificate-meta {
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
            grid-template-columns: repeat(8, minmax(0, 1fr));
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
            background: #166534;
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
            grid-template-columns: repeat(8, minmax(0, 1fr));
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
        .lineage-grid {
            display: grid;
            grid-template-columns: repeat(7, minmax(0, 1fr));
            gap: 12px;
        }
        .lineage-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .lineage-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .lineage-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .lineage-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .lineage-state {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
            margin-bottom: 10px;
        }
        .lineage-state.green {
            background: #dcfce7;
            color: #166534;
        }
        .lineage-state.amber {
            background: #fef3c7;
            color: #92400e;
        }
        .lineage-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
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
        .approval-state.blue {
            background: #dbeafe;
            color: #1d4ed8;
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
            background: #f0fdf4;
            border: 1px solid #86efac;
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
            color: #166534;
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
            background: #ecfdf5;
        }
        .inspect-btn.active {
            border-color: #86efac;
            background: #ecfdf5;
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
            background: #ecfdf5;
            border: 1px solid #86efac;
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
            color: #166534;
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
            background: #166534;
            color: #fff;
            font-weight: 900;
            font-size: 13px;
            white-space: nowrap;
        }
        .console-result {
            border-radius: 22px;
            padding: 22px;
            background: #ecfdf5;
            border: 1px solid #a7f3d0;
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
            color: #166534;
            margin-bottom: 10px;
        }
        .console-note {
            color: #4d5b73;
            line-height: 1.55;
        }
        .maturity-card {
            border-left: 5px solid #166534;
            background: #ecfdf5;
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
        @media (max-width: 1360px) {
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
            .gate-grid {
                grid-template-columns: repeat(4, minmax(0, 1fr));
            }
            .lineage-grid {
                grid-template-columns: repeat(4, minmax(0, 1fr));
            }
            .readiness-grid,
            .approval-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .workflow,
            .gate-grid,
            .lineage-grid,
            .readiness-grid,
            .approval-grid,
            .certificate-meta,
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
                <a href="/recovery-governance-command-center">Recovery Command Center</a>
                <a href="/gmp-restart-gate">GMP Restart Gate</a>
                <a href="/dr-evidence-passport">DR Evidence Passport</a>
                <a href="/recovery-dependency-validation">Recovery Dependencies</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Final Controlled Closure Layer</div>
            <h1>DR Recovery Certificate™</h1>
            <p>
                The formal certificate proving that a disaster-recovery event has moved from activation through thresholds,
                dependency validation, evidence completion, restart approval, authority sign-off, residual-risk review,
                root-cause capture, and final governed closure. Recovery is not merely finished; it is now defensible.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Certificate ID</div>
                    <div class="hero-value">DRC-2026-017</div>
                    <div class="hero-note">Filter Integrity Testing</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Recovery Case</div>
                    <div class="hero-value">RCV-2026-017</div>
                    <div class="hero-note">Governed complete</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Recovery Chain</div>
                    <div class="hero-value">7 / 7</div>
                    <div class="hero-note">All major layers green</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Evidence Passport</div>
                    <div class="hero-value">Audit-Ready</div>
                    <div class="hero-note">Required proof complete</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Restart State</div>
                    <div class="hero-value">Approved</div>
                    <div class="hero-note">Controlled resumption granted</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Residual Risk</div>
                    <div class="hero-value">Resolved</div>
                    <div class="hero-note">No open critical gaps</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Certificate State</div>
                    <div class="hero-value">Issued</div>
                    <div class="hero-note">Audit defensible</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Selected Recovery Certificate</h2>
                <div class="certificate-card">
                    <div class="certificate-kicker">Issued Recovery Certificate</div>
                    <div class="certificate-title">DRC-2026-017 — Filter Integrity Testing</div>
                    <div class="certificate-note">
                        This certificate confirms that the recovery case completed all required governance layers:
                        activation recorded, thresholds documented, dependencies cleared, DR passport audit-ready,
                        restart authorized, residual risk resolved, root cause captured, and controlled closure approved.
                    </div>

                    <div class="certificate-meta">
                        <div class="meta-card">
                            <div class="meta-label">Recovery Type</div>
                            <div class="meta-value">Component Recovery</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Final Authority</div>
                            <div class="meta-value">BQA Approved</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Root Cause</div>
                            <div class="meta-value">Captured</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Closure State</div>
                            <div class="meta-value">Certified</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Certification Readiness Snapshot</h2>
                <div class="readiness-grid">
                    <div class="readiness-card green">
                        <div class="readiness-label">Recovery Truth</div>
                        <div class="readiness-value">Complete</div>
                        <div class="readiness-note">Dependencies cleared end to end.</div>
                    </div>
                    <div class="readiness-card green">
                        <div class="readiness-label">Evidence Proof</div>
                        <div class="readiness-value">Ready</div>
                        <div class="readiness-note">Passport audit-ready.</div>
                    </div>
                    <div class="readiness-card green">
                        <div class="readiness-label">Restart Approval</div>
                        <div class="readiness-value">Approved</div>
                        <div class="readiness-note">Resumption decision recorded.</div>
                    </div>
                    <div class="readiness-card green">
                        <div class="readiness-label">Closure Proof</div>
                        <div class="readiness-value">Issued</div>
                        <div class="readiness-note">Final certificate preserved.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Recovery Certification Workflow</h2>
            <div class="workflow">
                <div class="step">
                    <div class="step-number">1</div>
                    <h3>Activate</h3>
                    <p>Classify and record the DR event.</p>
                </div>
                <div class="step">
                    <div class="step-number">2</div>
                    <h3>Measure</h3>
                    <p>Capture RTO / RPO outcome.</p>
                </div>
                <div class="step">
                    <div class="step-number">3</div>
                    <h3>Validate</h3>
                    <p>Clear recovery dependencies.</p>
                </div>
                <div class="step">
                    <div class="step-number">4</div>
                    <h3>Passport</h3>
                    <p>Complete the evidence spine.</p>
                </div>
                <div class="step">
                    <div class="step-number">5</div>
                    <h3>Restart</h3>
                    <p>Authorize controlled GMP resumption.</p>
                </div>
                <div class="step">
                    <div class="step-number">6</div>
                    <h3>Risk</h3>
                    <p>Resolve or formally document residual risk.</p>
                </div>
                <div class="step">
                    <div class="step-number">7</div>
                    <h3>Learn</h3>
                    <p>Capture root cause and preventive action.</p>
                </div>
                <div class="step">
                    <div class="step-number">8</div>
                    <h3>Certify</h3>
                    <p>Issue final controlled closure record.</p>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Certificate Gate Matrix</h2>
            <p>
                A recovery certificate may issue only when every closure gate is green.
            </p>

            <div class="gate-grid">
                <div class="gate-card green">
                    <div class="gate-title">Gate 01 — DR Event</div>
                    <div class="gate-state green">PASS</div>
                    <div class="gate-note">Activation and recovery level recorded.</div>
                </div>
                <div class="gate-card green">
                    <div class="gate-title">Gate 02 — Threshold Outcome</div>
                    <div class="gate-state green">PASS</div>
                    <div class="gate-note">RTO / RPO result captured.</div>
                </div>
                <div class="gate-card green">
                    <div class="gate-title">Gate 03 — Dependencies</div>
                    <div class="gate-state green">PASS</div>
                    <div class="gate-note">Technical, data, QA, and downstream gates cleared.</div>
                </div>
                <div class="gate-card green">
                    <div class="gate-title">Gate 04 — Evidence Passport</div>
                    <div class="gate-state green">PASS</div>
                    <div class="gate-note">Passport is audit-ready.</div>
                </div>
                <div class="gate-card green">
                    <div class="gate-title">Gate 05 — Restart Approval</div>
                    <div class="gate-state green">PASS</div>
                    <div class="gate-note">Controlled restart approved.</div>
                </div>
                <div class="gate-card green">
                    <div class="gate-title">Gate 06 — Residual Risk</div>
                    <div class="gate-state green">PASS</div>
                    <div class="gate-note">No critical open risk remains.</div>
                </div>
                <div class="gate-card green">
                    <div class="gate-title">Gate 07 — Root Cause</div>
                    <div class="gate-state green">PASS</div>
                    <div class="gate-note">Cause and prevention captured.</div>
                </div>
                <div class="gate-card green">
                    <div class="gate-title">Gate 08 — Final Authority</div>
                    <div class="gate-state green">PASS</div>
                    <div class="gate-note">Closure approved and issued.</div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Recovery Certificate Register</h2>
            <p>
                Each case shows whether it is certified, nearly ready, or still blocked from final closure.
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Cases</button>
                <button class="filter-btn" data-filter="issued">Issued</button>
                <button class="filter-btn" data-filter="ready">Ready</button>
                <button class="filter-btn" data-filter="blocked">Blocked</button>
                <input id="searchInput" class="search" type="text" placeholder="Search certificate, system, passport, restart, or closure state...">
            </div>

            <table id="certificateTable">
                <thead>
                    <tr>
                        <th>Certificate</th>
                        <th>System</th>
                        <th>Recovery Chain</th>
                        <th>Evidence Passport</th>
                        <th>Restart</th>
                        <th>Residual Risk</th>
                        <th>Root Cause</th>
                        <th>Certificate State</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-state="issued" data-search="drc-2026-017 filter integrity testing 7 of 7 audit ready approved resolved captured issued">
                        <td>DRC-2026-017</td>
                        <td>Filter Integrity Testing</td>
                        <td><span class="pill green">7 / 7</span></td>
                        <td><span class="pill green">Audit-Ready</span></td>
                        <td><span class="pill green">Approved</span></td>
                        <td><span class="pill green">Resolved</span></td>
                        <td><span class="pill green">Captured</span></td>
                        <td><span class="pill green">Issued</span></td>
                    </tr>
                    <tr data-state="issued" data-search="drc-2026-018 environmental monitoring 7 of 7 audit ready approved resolved captured issued">
                        <td>DRC-2026-018</td>
                        <td>Environmental Monitoring</td>
                        <td><span class="pill green">7 / 7</span></td>
                        <td><span class="pill green">Audit-Ready</span></td>
                        <td><span class="pill green">Approved</span></td>
                        <td><span class="pill green">Resolved</span></td>
                        <td><span class="pill green">Captured</span></td>
                        <td><span class="pill green">Issued</span></td>
                    </tr>
                    <tr data-state="ready" data-search="drc-2026-016 continuous environmental monitoring 6 of 7 reviewable pending minor risk captured ready">
                        <td>DRC-2026-016</td>
                        <td>Continuous Environmental Monitoring</td>
                        <td><span class="pill amber">6 / 7</span></td>
                        <td><span class="pill amber">Reviewable</span></td>
                        <td><span class="pill amber">Pending</span></td>
                        <td><span class="pill green">Resolved</span></td>
                        <td><span class="pill green">Captured</span></td>
                        <td><span class="pill amber">Ready Soon</span></td>
                    </tr>
                    <tr data-state="blocked" data-search="drc-2026-015 lims 4 of 7 reviewable hold lot disposition open draft blocked">
                        <td>DRC-2026-015</td>
                        <td>LIMS / QC</td>
                        <td><span class="pill red">4 / 7</span></td>
                        <td><span class="pill amber">Reviewable</span></td>
                        <td><span class="pill red">Hold</span></td>
                        <td><span class="pill red">Lot impact open</span></td>
                        <td><span class="pill amber">Draft</span></td>
                        <td><span class="pill red">Blocked</span></td>
                    </tr>
                    <tr data-state="blocked" data-search="drc-2026-014 erp 3 of 7 draft hold unresolved missing blocked">
                        <td>DRC-2026-014</td>
                        <td>ERP / Finance & Supply Chain</td>
                        <td><span class="pill red">3 / 7</span></td>
                        <td><span class="pill red">Draft</span></td>
                        <td><span class="pill red">Hold</span></td>
                        <td><span class="pill red">Unresolved</span></td>
                        <td><span class="pill red">Missing</span></td>
                        <td><span class="pill red">Blocked</span></td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Recovery Lineage Seal</h2>
            <p>
                The certificate preserves the full closure trail from first activation to final issue.
            </p>

            <div class="lineage-grid">
                <div class="lineage-card green">
                    <div class="lineage-title">01. Activation</div>
                    <div class="lineage-state green">Recorded</div>
                    <div class="lineage-note">Recovery level and trigger preserved.</div>
                </div>
                <div class="lineage-card green">
                    <div class="lineage-title">02. Thresholds</div>
                    <div class="lineage-state green">Recorded</div>
                    <div class="lineage-note">RTO / RPO outcome retained.</div>
                </div>
                <div class="lineage-card green">
                    <div class="lineage-title">03. Dependencies</div>
                    <div class="lineage-state green">Cleared</div>
                    <div class="lineage-note">Technical and governance blockers resolved.</div>
                </div>
                <div class="lineage-card green">
                    <div class="lineage-title">04. Passport</div>
                    <div class="lineage-state green">Audit-Ready</div>
                    <div class="lineage-note">Evidence spine complete.</div>
                </div>
                <div class="lineage-card green">
                    <div class="lineage-title">05. Restart</div>
                    <div class="lineage-state green">Approved</div>
                    <div class="lineage-note">Controlled resumption granted.</div>
                </div>
                <div class="lineage-card green">
                    <div class="lineage-title">06. Root Cause</div>
                    <div class="lineage-state green">Captured</div>
                    <div class="lineage-note">Learning loop retained.</div>
                </div>
                <div class="lineage-card green">
                    <div class="lineage-title">07. Certificate</div>
                    <div class="lineage-state green">Issued</div>
                    <div class="lineage-note">Final closure state preserved.</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Certificate Approval Chain</h2>
                <div class="approval-grid">
                    <div class="approval-card">
                        <div class="approval-role">System Custodian</div>
                        <div class="approval-name">Recovery Proof</div>
                        <div class="approval-note">
                            Confirms restore actions, reconciliation, and technical completion.
                        </div>
                        <div class="approval-state green">Signed</div>
                    </div>
                    <div class="approval-card">
                        <div class="approval-role">Computer System QA</div>
                        <div class="approval-name">Integrity Proof</div>
                        <div class="approval-note">
                            Confirms post-restore validation and audit-trail posture.
                        </div>
                        <div class="approval-state green">Signed</div>
                    </div>
                    <div class="approval-card">
                        <div class="approval-role">Business QA</div>
                        <div class="approval-name">GMP Disposition</div>
                        <div class="approval-note">
                            Confirms batch / process impact and restart permissibility.
                        </div>
                        <div class="approval-state green">Signed</div>
                    </div>
                    <div class="approval-card">
                        <div class="approval-role">System Owner</div>
                        <div class="approval-name">Closure Accountability</div>
                        <div class="approval-note">
                            Confirms recovery package and root cause are complete.
                        </div>
                        <div class="approval-state green">Signed</div>
                    </div>
                    <div class="approval-card">
                        <div class="approval-role">Final Authority</div>
                        <div class="approval-name">Certificate Issue</div>
                        <div class="approval-note">
                            Issues final controlled closure based on all prior gates.
                        </div>
                        <div class="approval-state blue">Issued</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Certificate Interpretation</h2>
                <table>
                    <thead>
                        <tr>
                            <th>State</th>
                            <th>Meaning</th>
                            <th>Use</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Blocked</td>
                            <td>Recovery chain still incomplete</td>
                            <td><span class="pill red">Do not close</span></td>
                        </tr>
                        <tr>
                            <td>Ready Soon</td>
                            <td>Only minor final gate remains</td>
                            <td><span class="pill amber">Prepare issue</span></td>
                        </tr>
                        <tr>
                            <td>Issued</td>
                            <td>Recovery is complete and audit-defensible</td>
                            <td><span class="pill green">Controlled closure</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Interactive Certificate Builder</h2>
            <p>
                This simulation shows why a recovery certificate should issue only after the full governed chain is complete.
            </p>

            <div class="builder">
                <div class="builder-grid">
                    <div class="builder-row">
                        <label>Required Certificate Gates</label>
                        <div class="check-grid">
                            <label class="check-row">
                                <input id="checkActivation" type="checkbox" checked>
                                DR activation and recovery level recorded
                            </label>
                            <label class="check-row">
                                <input id="checkThresholds" type="checkbox" checked>
                                RTO / RPO outcome captured
                            </label>
                            <label class="check-row">
                                <input id="checkDependencies" type="checkbox" checked>
                                Recovery dependencies cleared
                            </label>
                            <label class="check-row">
                                <input id="checkPassport" type="checkbox" checked>
                                DR Evidence Passport audit-ready
                            </label>
                            <label class="check-row">
                                <input id="checkRestart" type="checkbox" checked>
                                GMP restart approved
                            </label>
                            <label class="check-row">
                                <input id="checkRisk" type="checkbox" checked>
                                Residual risk resolved or documented
                            </label>
                            <label class="check-row">
                                <input id="checkRootCause" type="checkbox" checked>
                                Root cause and preventive action captured
                            </label>
                            <label class="check-row">
                                <input id="checkAuthority" type="checkbox" checked>
                                Final closure authority granted
                            </label>
                        </div>
                    </div>
                </div>

                <div class="builder-result">
                    <div class="builder-label">Certificate Verdict</div>
                    <div id="builderTitle" class="builder-title">Recovery Certificate Issued</div>
                    <div id="builderVerdict" class="builder-verdict">
                        Every certification gate is complete. The recovery case is eligible for final controlled closure.
                    </div>
                    <div class="builder-meta">
                        <div class="builder-mini">
                            <div class="builder-mini-label">Gates Passed</div>
                            <div id="builderChecks" class="builder-mini-value">8 / 8</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Certificate State</div>
                            <div id="builderState" class="builder-mini-value">Issued</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Audit Posture</div>
                            <div id="builderAudit" class="builder-mini-value">Defensible</div>
                        </div>
                    </div>
                    <div id="builderNote" class="builder-note">
                        Closure becomes credible only when the entire recovery chain agrees.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Certificate Scenario Inspector</h2>
            <p>
                Select a scenario to inspect why a case is blocked, nearly ready, or certified.
            </p>

            <div class="inspector">
                <div class="inspector-list">
                    <button class="inspect-btn active" data-scenario="issued">
                        <div class="inspect-kicker">Scenario 01</div>
                        <div class="inspect-title">Certificate issued</div>
                        <div class="inspect-note">All recovery layers complete and aligned.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="ready">
                        <div class="inspect-kicker">Scenario 02</div>
                        <div class="inspect-title">Ready soon</div>
                        <div class="inspect-note">Only one final approval remains.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="blocked">
                        <div class="inspect-kicker">Scenario 03</div>
                        <div class="inspect-title">Blocked certificate</div>
                        <div class="inspect-note">Recovery still has unresolved restart and evidence gaps.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="false">
                        <div class="inspect-kicker">Scenario 04</div>
                        <div class="inspect-title">False closure attempt</div>
                        <div class="inspect-note">Technical restoration exists, but final proof does not.</div>
                    </button>
                </div>

                <div class="inspector-card">
                    <div class="inspector-label">Selected Scenario</div>
                    <div id="inspectorTitle" class="inspector-title">Certificate issued</div>
                    <div class="inspector-meta">
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Recovery Chain</div>
                            <div id="inspectorChain" class="inspector-mini-value">7 / 7</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Passport</div>
                            <div id="inspectorPassport" class="inspector-mini-value">Audit-Ready</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Restart</div>
                            <div id="inspectorRestart" class="inspector-mini-value">Approved</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Certificate</div>
                            <div id="inspectorCertificate" class="inspector-mini-value">Issued</div>
                        </div>
                    </div>
                    <div id="inspectorVerdict" class="inspector-verdict">
                        Every upstream governance layer is complete, so final controlled closure is defensible.
                    </div>
                    <div id="inspectorNote" class="inspector-note">
                        This is the proper end state for the DR branch: not merely restored, but certified.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Certificate Action Console</h2>
            <p>
                The certificate layer routes the final recovery outcome into controlled closure or continued governance.
            </p>

            <div class="action-console">
                <div class="action-list">
                    <div class="action-item">
                        <div>
                            <h3>Issue certificate</h3>
                            <p>Seal the fully complete recovery case as audit-defensible closure.</p>
                        </div>
                        <button class="action-btn" data-action="issue">Issue</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Return incomplete case</h3>
                            <p>Send blocked recovery back to the open governance queue.</p>
                        </div>
                        <button class="action-btn" data-action="return">Return</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Archive certificate package</h3>
                            <p>Preserve the final evidence spine for audit and inspection readiness.</p>
                        </div>
                        <button class="action-btn" data-action="archive">Archive</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Launch learning review</h3>
                            <p>Feed root cause and lessons learned into future resilience controls.</p>
                        </div>
                        <button class="action-btn" data-action="learn">Launch</button>
                    </div>
                </div>

                <div id="consoleResult" class="console-result">
                    <div class="console-label">Certificate Outcome</div>
                    <div id="consoleTitle" class="console-title">Awaiting Action</div>
                    <div id="consoleNote" class="console-note">
                        Select an action to see how recovery closure becomes controlled, preserved, and learnable.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>Recovery Governance Command Center</h3>
                <p>
                    Shows whether the recovery estate is ready, blocked, or critical.
                </p>
            </div>
            <div class="maturity-card">
                <h3>DR Recovery Certificate</h3>
                <p>
                    Issues the final proof that the recovery chain is complete and defensible.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    COBIT-Chain™ now closes DR with governed certification rather than informal “system restored” language.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by the DR Recovery Certificate</h2>
            <p>
                Recovery Governance Command Center™ answers:
                <strong>“What is the current enterprise recovery posture and what needs action?”</strong>
            </p>
            <p>
                DR Recovery Certificate™ answers:
                <strong>“Has the full recovery chain become complete enough to issue final, audit-defensible closure?”</strong>
            </p>
            <p>
                That completes the DR branch. The platform now demonstrates the full governed path from activation to threshold
                monitoring, dependency proof, evidence passports, restart gates, executive mission control, and final certification.
            </p>
            <div class="footer-note">
                Complete DR branch: DR Activation Intelligence™ → RTO / RPO Governance Intelligence™ →
                Recovery Dependency Validation™ → DR Evidence Passport™ → GMP Restart Gate™ →
                Recovery Governance Command Center™ → DR Recovery Certificate™.
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#certificateTable tbody tr");
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

        const checkActivation = document.getElementById("checkActivation");
        const checkThresholds = document.getElementById("checkThresholds");
        const checkDependencies = document.getElementById("checkDependencies");
        const checkPassport = document.getElementById("checkPassport");
        const checkRestart = document.getElementById("checkRestart");
        const checkRisk = document.getElementById("checkRisk");
        const checkRootCause = document.getElementById("checkRootCause");
        const checkAuthority = document.getElementById("checkAuthority");
        const builderTitle = document.getElementById("builderTitle");
        const builderVerdict = document.getElementById("builderVerdict");
        const builderChecks = document.getElementById("builderChecks");
        const builderState = document.getElementById("builderState");
        const builderAudit = document.getElementById("builderAudit");
        const builderNote = document.getElementById("builderNote");

        function updateBuilder() {
            const checks = [
                checkActivation,
                checkThresholds,
                checkDependencies,
                checkPassport,
                checkRestart,
                checkRisk,
                checkRootCause,
                checkAuthority
            ];

            const passed = checks.filter(check => check.checked).length;
            builderChecks.textContent = passed + " / 8";

            if (passed === 8) {
                builderTitle.textContent = "Recovery Certificate Issued";
                builderVerdict.textContent = "Every certification gate is complete. The recovery case is eligible for final controlled closure.";
                builderState.textContent = "Issued";
                builderAudit.textContent = "Defensible";
                builderNote.textContent = "Closure becomes credible only when the entire recovery chain agrees.";
            } else if (passed >= 6) {
                builderTitle.textContent = "Certificate Ready Soon";
                builderVerdict.textContent = "Most gates are complete, but one or two final closure conditions remain open.";
                builderState.textContent = "Ready Soon";
                builderAudit.textContent = "Near-ready";
                builderNote.textContent = "The case is close, but final certification must wait until every remaining gate is complete.";
            } else {
                builderTitle.textContent = "Certificate Blocked";
                builderVerdict.textContent = "Too many recovery conditions remain incomplete. Final closure would be premature.";
                builderState.textContent = "Blocked";
                builderAudit.textContent = "Not defensible";
                builderNote.textContent = "A certificate should never be used to hide an unfinished recovery chain.";
            }
        }

        [
            checkActivation,
            checkThresholds,
            checkDependencies,
            checkPassport,
            checkRestart,
            checkRisk,
            checkRootCause,
            checkAuthority
        ].forEach(element => {
            element.addEventListener("change", updateBuilder);
        });

        updateBuilder();

        const inspectButtons = document.querySelectorAll(".inspect-btn");
        const inspectorTitle = document.getElementById("inspectorTitle");
        const inspectorChain = document.getElementById("inspectorChain");
        const inspectorPassport = document.getElementById("inspectorPassport");
        const inspectorRestart = document.getElementById("inspectorRestart");
        const inspectorCertificate = document.getElementById("inspectorCertificate");
        const inspectorVerdict = document.getElementById("inspectorVerdict");
        const inspectorNote = document.getElementById("inspectorNote");

        const scenarios = {
            issued: {
                title: "Certificate issued",
                chain: "7 / 7",
                passport: "Audit-Ready",
                restart: "Approved",
                certificate: "Issued",
                verdict: "Every upstream governance layer is complete, so final controlled closure is defensible.",
                note: "This is the proper end state for the DR branch: not merely restored, but certified."
            },
            ready: {
                title: "Ready soon",
                chain: "6 / 7",
                passport: "Reviewable",
                restart: "Pending",
                certificate: "Ready Soon",
                verdict: "The case is close, but one remaining restart or approval gate still prevents certificate issue.",
                note: "A near-complete recovery is still not final closure."
            },
            blocked: {
                title: "Blocked certificate",
                chain: "4 / 7",
                passport: "Reviewable",
                restart: "Hold",
                certificate: "Blocked",
                verdict: "Recovery is progressing, but unresolved restart and residual-risk conditions still block final certification.",
                note: "The certificate should remain unavailable until the enterprise can prove the full chain."
            },
            false: {
                title: "False closure attempt",
                chain: "2 / 7",
                passport: "Draft",
                restart: "Hold",
                certificate: "Rejected",
                verdict: "Technical restoration exists, but most governance evidence is absent. Issuing a certificate now would create false assurance.",
                note: "This page prevents recovery closure from becoming ceremonial rather than evidence-based."
            }
        };

        inspectButtons.forEach(button => {
            button.addEventListener("click", () => {
                inspectButtons.forEach(btn => btn.classList.remove("active"));
                button.classList.add("active");

                const item = scenarios[button.dataset.scenario];
                inspectorTitle.textContent = item.title;
                inspectorChain.textContent = item.chain;
                inspectorPassport.textContent = item.passport;
                inspectorRestart.textContent = item.restart;
                inspectorCertificate.textContent = item.certificate;
                inspectorVerdict.textContent = item.verdict;
                inspectorNote.textContent = item.note;
            });
        });

        const actionButtons = document.querySelectorAll(".action-btn");
        const consoleResult = document.getElementById("consoleResult");
        const consoleTitle = document.getElementById("consoleTitle");
        const consoleNote = document.getElementById("consoleNote");

        const outcomes = {
            issue: {
                title: "Recovery Certificate Issued",
                note: "The fully complete recovery case has been sealed as final, controlled, and audit-defensible closure."
            },
            return: {
                title: "Case Returned to Governance Queue",
                note: "The incomplete recovery has been sent back for remaining dependency, approval, or evidence work."
            },
            archive: {
                title: "Certificate Package Archived",
                note: "The final evidence spine and approval trail are preserved for inspection and future review."
            },
            learn: {
                title: "Learning Review Launched",
                note: "Root cause and preventive lessons have been routed into the resilience improvement cycle."
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
        print("SKIP: DR_RECOVERY_CERTIFICATE_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/dr-recovery-certificate")',
        "DR Recovery Certificate™",
        "Certificate Gate Matrix",
        "Recovery Certificate Register",
        "Interactive Certificate Builder",
        "Certificate Action Console",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /dr-recovery-certificate route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
