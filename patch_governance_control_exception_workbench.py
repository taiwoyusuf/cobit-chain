from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# GOVERNANCE_CONTROL_EXCEPTION_WORKBENCH_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# GOVERNANCE_CONTROL_EXCEPTION_WORKBENCH_ACTIVE
@app.route("/governance-control-exception-workbench")
def governance_control_exception_workbench_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Governance Control Exception Workbench™ | COBIT-Chain™ / AssuranceLayer™</title>
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
            background: linear-gradient(135deg, #111827 0%, #991b1b 46%, #7c3aed 100%);
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
            max-width: 1120px;
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
        .exception-card {
            background: linear-gradient(180deg, #ffffff 0%, #fff7f7 100%);
            border: 1px solid #fecaca;
            border-radius: 22px;
            padding: 20px;
        }
        .exception-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #991b1b;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .exception-title {
            font-size: 24px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .exception-note {
            color: #4c5b73;
            line-height: 1.55;
            margin-bottom: 16px;
        }
        .exception-meta {
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
        .risk-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .risk-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .risk-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .risk-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .risk-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .risk-card.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .risk-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .risk-value {
            font-size: 28px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .risk-note {
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
            background: #991b1b;
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
        .compensating-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .comp-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .comp-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .comp-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .comp-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .comp-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
            margin-bottom: 11px;
        }
        .comp-state {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
        }
        .comp-state.green {
            background: #dcfce7;
            color: #166534;
        }
        .comp-state.amber {
            background: #fef3c7;
            color: #92400e;
        }
        .remediation-grid {
            display: grid;
            gap: 12px;
        }
        .remediation-item {
            display: grid;
            grid-template-columns: 62px 1fr auto;
            gap: 14px;
            align-items: start;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .remediation-no {
            width: 44px;
            height: 44px;
            border-radius: 14px;
            background: #991b1b;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 900;
        }
        .remediation-title {
            font-weight: 900;
            margin-bottom: 5px;
        }
        .remediation-note {
            color: #53637b;
            line-height: 1.45;
            font-size: 14px;
        }
        .remediation-owner {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
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
            background: #fff1f2;
        }
        .inspect-btn.active {
            border-color: #fca5a5;
            background: #fff1f2;
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
            background: #fff1f2;
            border: 1px solid #fca5a5;
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
            color: #991b1b;
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
        .inspector-exception {
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
        .return-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .return-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .return-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .return-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .return-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .return-value {
            font-size: 24px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .return-note {
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
            background: #991b1b;
            color: #fff;
            font-weight: 900;
            font-size: 13px;
            white-space: nowrap;
        }
        .console-result {
            border-radius: 22px;
            padding: 22px;
            background: #fff1f2;
            border: 1px solid #fecaca;
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
            color: #991b1b;
            margin-bottom: 10px;
        }
        .console-note {
            color: #4d5b73;
            line-height: 1.55;
        }
        .maturity-card {
            border-left: 5px solid #991b1b;
            background: #fff1f2;
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
            .builder,
            .action-console {
                grid-template-columns: 1fr;
            }
            .workflow {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .risk-grid,
            .compensating-grid,
            .return-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .workflow,
            .risk-grid,
            .compensating-grid,
            .return-grid,
            .exception-meta,
            .inspector-meta,
            .builder-meta {
                grid-template-columns: 1fr;
            }
            .search {
                margin-left: 0;
                width: 100%;
                min-width: 0;
            }
            .remediation-item {
                grid-template-columns: 1fr;
            }
            .remediation-owner {
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
                <a href="/governance-control-attestation-center">Attestation Center</a>
                <a href="/governance-control-change-ledger">Change Ledger</a>
                <a href="/governance-control-library">Control Library</a>
                <a href="/governance-intervention-workbench">Intervention Workbench</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Owned, Time-Bound, Evidence-Backed Exceptions</div>
            <h1>Governance Control Exception Workbench™</h1>
            <p>
                The formal workbench for controls that cannot currently operate exactly as designed.
                Instead of hiding exceptions inside notes or allowing qualified attestations to drift indefinitely,
                COBIT-Chain™ turns every exception into an owned, time-bound governance object with compensating controls,
                accepted risk, remediation steps, expiry, and a clear path back to clean attestation.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Open Exceptions</div>
                    <div class="hero-value">4</div>
                    <div class="hero-note">Across active controls</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">High-Risk</div>
                    <div class="hero-value">1</div>
                    <div class="hero-note">Immediate review needed</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Compensated</div>
                    <div class="hero-value">3</div>
                    <div class="hero-note">Temporary safeguards active</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Expiring Soon</div>
                    <div class="hero-value">2</div>
                    <div class="hero-note">Within 14 days</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Accepted Risk</div>
                    <div class="hero-value">1</div>
                    <div class="hero-note">Awaiting remediation</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Clean Return</div>
                    <div class="hero-value">75%</div>
                    <div class="hero-note">Expected this cycle</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Selected Control Exception</h2>
                <div class="exception-card">
                    <div class="exception-kicker">Exception EXC-2026-004</div>
                    <div class="exception-title">GCL-006 — Privileged Account Owner Review</div>
                    <div class="exception-note">
                        One application-specific privileged account remains outside the standard myAccess evidence path.
                        The control is operating, but the evidence chain is not yet fully aligned with the normal attestation model,
                        so the control carries a qualified exception until the account is remediated into the governed evidence path.
                    </div>

                    <div class="exception-meta">
                        <div class="meta-card">
                            <div class="meta-label">Exception Owner</div>
                            <div class="meta-value">IT Security</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Risk Acceptance</div>
                            <div class="meta-value">Temporary</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Expiry</div>
                            <div class="meta-value">2026-05-23</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Return Gate</div>
                            <div class="meta-value">Evidence Reconciled</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Exception Risk Snapshot</h2>
                <div class="risk-grid">
                    <div class="risk-card red">
                        <div class="risk-label">Residual Risk</div>
                        <div class="risk-value">Medium</div>
                        <div class="risk-note">Evidence gap remains until account is brought into governed review.</div>
                    </div>
                    <div class="risk-card green">
                        <div class="risk-label">Compensation</div>
                        <div class="risk-value">Active</div>
                        <div class="risk-note">Manual owner review and screenshot proof are temporarily in place.</div>
                    </div>
                    <div class="risk-card amber">
                        <div class="risk-label">Days to Expiry</div>
                        <div class="risk-value">14</div>
                        <div class="risk-note">Exception must close or be formally renewed before lapse.</div>
                    </div>
                    <div class="risk-card blue">
                        <div class="risk-label">Attestation Impact</div>
                        <div class="risk-value">Qualified</div>
                        <div class="risk-note">Control cannot return to clean attestation while exception is open.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Exception Governance Workflow</h2>
            <div class="workflow">
                <div class="step">
                    <div class="step-number">1</div>
                    <h3>Declare</h3>
                    <p>Record why the control cannot currently operate exactly as designed.</p>
                </div>
                <div class="step">
                    <div class="step-number">2</div>
                    <h3>Assess</h3>
                    <p>Evaluate residual risk, affected evidence, and business consequence.</p>
                </div>
                <div class="step">
                    <div class="step-number">3</div>
                    <h3>Compensate</h3>
                    <p>Assign temporary safeguards while the exception remains open.</p>
                </div>
                <div class="step">
                    <div class="step-number">4</div>
                    <h3>Accept</h3>
                    <p>Require named owner, rationale, and approved expiry period.</p>
                </div>
                <div class="step">
                    <div class="step-number">5</div>
                    <h3>Remediate</h3>
                    <p>Complete the work needed to restore normal control operation.</p>
                </div>
                <div class="step">
                    <div class="step-number">6</div>
                    <h3>Return</h3>
                    <p>Close the exception only when clean attestation is again possible.</p>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Control Exception Register</h2>
            <p>
                Every exception is visible, owned, time-bound, and tied back to the affected control.
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Exceptions</button>
                <button class="filter-btn" data-filter="open">Open</button>
                <button class="filter-btn" data-filter="high">High Risk</button>
                <button class="filter-btn" data-filter="expiring">Expiring</button>
                <button class="filter-btn" data-filter="closed">Closed</button>
                <input id="searchInput" class="search" type="text" placeholder="Search exception, control, owner, risk, or compensating control...">
            </div>

            <table id="exceptionTable">
                <thead>
                    <tr>
                        <th>Exception</th>
                        <th>Affected Control</th>
                        <th>Reason</th>
                        <th>Owner</th>
                        <th>Compensating Control</th>
                        <th>Risk</th>
                        <th>Expiry</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-state="open expiring" data-search="exc-2026-004 gcl-006 privileged account owner review it security application-specific account compensating manual review medium expiring">
                        <td>EXC-2026-004</td>
                        <td>GCL-006 — Privileged Account Owner Review</td>
                        <td>Application-specific account outside normal myAccess evidence path</td>
                        <td>IT Security</td>
                        <td>Manual owner review + screenshot proof</td>
                        <td><span class="pill amber">Medium</span></td>
                        <td>2026-05-23</td>
                        <td><span class="pill amber">Open</span></td>
                    </tr>
                    <tr data-state="high open" data-search="exc-2026-005 gcl-008 erp mes lims release chain operations high risk no current owner evidence">
                        <td>EXC-2026-005</td>
                        <td>GCL-008 — ERP → MES → LIMS Release Chain</td>
                        <td>Current-cycle owner evidence not yet submitted</td>
                        <td>Operations</td>
                        <td>Daily manual release confirmation</td>
                        <td><span class="pill red">High</span></td>
                        <td>2026-05-16</td>
                        <td><span class="pill red">Escalated</span></td>
                    </tr>
                    <tr data-state="open expiring" data-search="exc-2026-006 gcl-003 reconciliation qa systems pending live sample expiring low">
                        <td>EXC-2026-006</td>
                        <td>GCL-003 — Release-Sensitive Record Reconciliation</td>
                        <td>Current live sample unavailable during platform transition</td>
                        <td>QA Systems</td>
                        <td>Historical sample + owner confirmation</td>
                        <td><span class="pill green">Low</span></td>
                        <td>2026-05-20</td>
                        <td><span class="pill amber">Open</span></td>
                    </tr>
                    <tr data-state="open" data-search="exc-2026-007 gcl-007 periodic review evidence match engineering delayed source evidence medium">
                        <td>EXC-2026-007</td>
                        <td>GCL-007 — Periodic Review Evidence Match</td>
                        <td>Source evidence delayed from engineering review cycle</td>
                        <td>Engineering</td>
                        <td>Supervisor review log</td>
                        <td><span class="pill amber">Medium</span></td>
                        <td>2026-06-02</td>
                        <td><span class="pill blue">Accepted</span></td>
                    </tr>
                    <tr data-state="closed" data-search="exc-2026-003 gcl-005 downstream release confirmation qc governance closed remediated">
                        <td>EXC-2026-003</td>
                        <td>GCL-005 — Downstream Release Confirmation</td>
                        <td>Temporary middleware confirmation gap</td>
                        <td>QC Governance</td>
                        <td>Manual release check</td>
                        <td><span class="pill green">Low</span></td>
                        <td>2026-04-30</td>
                        <td><span class="pill green">Closed</span></td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Compensating Control Stack</h2>
                <div class="compensating-grid">
                    <div class="comp-card green">
                        <div class="comp-title">Manual Owner Review</div>
                        <div class="comp-note">
                            Named owner confirms the privileged account remains authorized while standard evidence is repaired.
                        </div>
                        <div class="comp-state green">Active</div>
                    </div>
                    <div class="comp-card green">
                        <div class="comp-title">Screenshot Proof</div>
                        <div class="comp-note">
                            Current privileged-account state captured and attached to the exception record.
                        </div>
                        <div class="comp-state green">Attached</div>
                    </div>
                    <div class="comp-card amber">
                        <div class="comp-title">Weekly Re-Check</div>
                        <div class="comp-note">
                            Exception remains subject to re-review until normal evidence alignment is restored.
                        </div>
                        <div class="comp-state amber">Scheduled</div>
                    </div>
                    <div class="comp-card amber">
                        <div class="comp-title">Expiry Escalation</div>
                        <div class="comp-note">
                            Automatic escalation triggers if remediation is incomplete by the approved expiry date.
                        </div>
                        <div class="comp-state amber">Pending</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Remediation Plan</h2>
                <div class="remediation-grid">
                    <div class="remediation-item">
                        <div class="remediation-no">1</div>
                        <div>
                            <div class="remediation-title">Confirm account classification</div>
                            <div class="remediation-note">
                                Verify whether the privileged account should remain application-specific or be normalized into the standard review path.
                            </div>
                        </div>
                        <div class="remediation-owner">IT Security</div>
                    </div>
                    <div class="remediation-item">
                        <div class="remediation-no">2</div>
                        <div>
                            <div class="remediation-title">Attach governed evidence</div>
                            <div class="remediation-note">
                                Add the required approval and role-state proof to the control evidence chain.
                            </div>
                        </div>
                        <div class="remediation-owner">Control Owner</div>
                    </div>
                    <div class="remediation-item">
                        <div class="remediation-no">3</div>
                        <div>
                            <div class="remediation-title">Re-run attestation</div>
                            <div class="remediation-note">
                                Return GCL-006 to the Attestation Center once the evidence chain is complete.
                            </div>
                        </div>
                        <div class="remediation-owner">Governance</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Exception Inspector</h2>
            <p>
                Select an exception to inspect its owner, accepted risk, compensating control, and required return path.
            </p>

            <div class="inspector">
                <div class="inspector-list">
                    <button class="inspect-btn active" data-exception="exc004">
                        <div class="inspect-kicker">EXC-2026-004</div>
                        <div class="inspect-title">GCL-006 privileged-account evidence gap</div>
                        <div class="inspect-note">Qualified attestation with temporary compensation.</div>
                    </button>
                    <button class="inspect-btn" data-exception="exc005">
                        <div class="inspect-kicker">EXC-2026-005</div>
                        <div class="inspect-title">GCL-008 owner-review absence</div>
                        <div class="inspect-note">High-risk exception affecting release-chain assurance.</div>
                    </button>
                    <button class="inspect-btn" data-exception="exc006">
                        <div class="inspect-kicker">EXC-2026-006</div>
                        <div class="inspect-title">GCL-003 live-sample gap</div>
                        <div class="inspect-note">Low-risk temporary exception during transition.</div>
                    </button>
                    <button class="inspect-btn" data-exception="exc003">
                        <div class="inspect-kicker">EXC-2026-003</div>
                        <div class="inspect-title">GCL-005 middleware confirmation gap</div>
                        <div class="inspect-note">Closed after strengthened control version deployed.</div>
                    </button>
                </div>

                <div class="inspector-card">
                    <div class="inspector-label">Selected Exception</div>
                    <div id="inspectorTitle" class="inspector-title">GCL-006 privileged-account evidence gap</div>
                    <div class="inspector-meta">
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Exception ID</div>
                            <div id="inspectorId" class="inspector-mini-value">EXC-2026-004</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Owner</div>
                            <div id="inspectorOwner" class="inspector-mini-value">IT Security</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Residual Risk</div>
                            <div id="inspectorRisk" class="inspector-mini-value">Medium</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Expiry</div>
                            <div id="inspectorExpiry" class="inspector-mini-value">2026-05-23</div>
                        </div>
                    </div>
                    <div id="inspectorException" class="inspector-exception">
                        One application-specific privileged account remains outside the normal myAccess evidence path.
                    </div>
                    <div id="inspectorNote" class="inspector-note">
                        Compensation is currently acceptable only because manual owner review, screenshot proof, weekly re-check, and an expiry date are all present.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Interactive Exception Decision Builder</h2>
            <p>
                This simulation shows why an exception is only acceptable when it is owned, compensated, time-bound, and remediable.
            </p>

            <div class="builder">
                <div class="builder-grid">
                    <div class="builder-row">
                        <label for="exceptionSelect">Exception Under Review</label>
                        <select id="exceptionSelect">
                            <option value="exc004">EXC-2026-004 — GCL-006 privileged-account evidence gap</option>
                            <option value="exc005">EXC-2026-005 — GCL-008 owner-review absence</option>
                            <option value="exc006">EXC-2026-006 — GCL-003 live-sample gap</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label>Exception Acceptance Checks</label>
                        <div class="check-grid">
                            <label class="check-row">
                                <input id="checkOwner" type="checkbox" checked>
                                Named owner accepts responsibility
                            </label>
                            <label class="check-row">
                                <input id="checkCompensation" type="checkbox" checked>
                                Compensating control is active
                            </label>
                            <label class="check-row">
                                <input id="checkExpiry" type="checkbox" checked>
                                Expiry date is defined
                            </label>
                            <label class="check-row">
                                <input id="checkRemediation" type="checkbox" checked>
                                Remediation path is documented
                            </label>
                        </div>
                    </div>
                </div>

                <div class="builder-result">
                    <div class="builder-label">Exception Verdict</div>
                    <div id="builderTitle" class="builder-title">Exception Acceptable</div>
                    <div id="builderVerdict" class="builder-verdict">
                        All required safeguards are present. The exception may remain open temporarily under governed acceptance.
                    </div>
                    <div class="builder-meta">
                        <div class="builder-mini">
                            <div class="builder-mini-label">Checks Passed</div>
                            <div id="builderChecks" class="builder-mini-value">4 / 4</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Disposition</div>
                            <div id="builderDisposition" class="builder-mini-value">Accept</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Attestation Impact</div>
                            <div id="builderImpact" class="builder-mini-value">Qualified</div>
                        </div>
                    </div>
                    <div id="builderNote" class="builder-note">
                        An exception is not a free pass. It remains acceptable only while ownership, compensation, expiry, and remediation stay intact.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Return-to-Clean-Attestation Gate</h2>
                <div class="return-grid">
                    <div class="return-card green">
                        <div class="return-title">Evidence Aligned</div>
                        <div class="return-value">Required</div>
                        <div class="return-note">Normal proof path restored for the affected control.</div>
                    </div>
                    <div class="return-card green">
                        <div class="return-title">Exception Closed</div>
                        <div class="return-value">Required</div>
                        <div class="return-note">No unresolved accepted risk remains open.</div>
                    </div>
                    <div class="return-card amber">
                        <div class="return-title">Re-Attestation</div>
                        <div class="return-value">Pending</div>
                        <div class="return-note">Control owner must re-certify after remediation.</div>
                    </div>
                    <div class="return-card amber">
                        <div class="return-title">Ledger Update</div>
                        <div class="return-value">Pending</div>
                        <div class="return-note">Closure must be preserved in the governance record.</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>What the Workbench Prevents</h2>
                <p>
                    Without an exception workbench, a control can remain “temporarily qualified” for months with no owner,
                    no expiry, and no route back to normal operation.
                </p>
                <p>
                    With this layer, the platform forces the enterprise to choose:
                    remediate, compensate, accept with evidence, or escalate — but never simply forget.
                </p>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Exception Action Console</h2>
            <p>
                The workbench routes each exception toward controlled governance action rather than informal tolerance.
            </p>

            <div class="action-console">
                <div class="action-list">
                    <div class="action-item">
                        <div>
                            <h3>Accept EXC-2026-004 temporarily</h3>
                            <p>Record owned risk with active compensating controls and approved expiry.</p>
                        </div>
                        <button class="action-btn" data-action="accept">Accept</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Escalate EXC-2026-005</h3>
                            <p>High-risk owner-review absence is affecting release-chain assurance.</p>
                        </div>
                        <button class="action-btn" data-action="escalate">Escalate</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Request remediation update</h3>
                            <p>Require evidence of progress before the approved exception period expires.</p>
                        </div>
                        <button class="action-btn" data-action="remediate">Request</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Close remediated exception</h3>
                            <p>Return the affected control to clean attestation after evidence alignment.</p>
                        </div>
                        <button class="action-btn" data-action="close">Close</button>
                    </div>
                </div>

                <div id="consoleResult" class="console-result">
                    <div class="console-label">Exception Outcome</div>
                    <div id="consoleTitle" class="console-title">Awaiting Action</div>
                    <div id="consoleNote" class="console-note">
                        Select an action to see how exceptions remain visible, owned, and time-bound.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>Attestation Center</h3>
                <p>
                    Reveals when a control cannot receive a clean owner attestation.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Exception Workbench</h3>
                <p>
                    Governs the exception with ownership, compensation, expiry, remediation, and return gates.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    COBIT-Chain™ does not hide imperfect reality; it makes imperfect reality governed and auditable.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by the Exception Workbench</h2>
            <p>
                The Governance Control Attestation Center™ answers: <strong>“Can this control be cleanly attested today?”</strong>
            </p>
            <p>
                The Governance Control Exception Workbench™ answers: <strong>“If not, what exactly is the exception, who owns it, how is it compensated, when does it expire, and how does the control return to normal?”</strong>
            </p>
            <p>
                That is the difference between merely noticing a qualified control and properly governing the gap.
                COBIT-Chain™ now demonstrates a mature exception-management discipline around the control environment itself.
            </p>
            <div class="footer-note">
                Simulation chain: pain point detection → dependency validation → reconciliation → decision intelligence →
                Governance Passport™ → Governance Assurance Register™ → Governance Intervention Workbench™ →
                Governance Re-Closure Gate™ → Governance Closure Certificate™ → Governance Learning Loop™ →
                Governance Rule Factory™ → Governance Control Library™ → Governance Control Effectiveness Monitor™ →
                Governance Control Optimization Workbench™ → Governance Control Release Orchestrator™ →
                Governance Control Change Ledger™ → Governance Control Attestation Center™ →
                Governance Control Exception Workbench™.
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#exceptionTable tbody tr");
        const searchInput = document.getElementById("searchInput");
        let activeFilter = "all";

        function applyFilters() {
            const query = searchInput.value.toLowerCase().trim();

            rows.forEach(row => {
                const states = row.dataset.state.split(" ");
                const searchable = row.dataset.search;
                const matchesFilter = activeFilter === "all" || states.includes(activeFilter);
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
        const inspectorId = document.getElementById("inspectorId");
        const inspectorOwner = document.getElementById("inspectorOwner");
        const inspectorRisk = document.getElementById("inspectorRisk");
        const inspectorExpiry = document.getElementById("inspectorExpiry");
        const inspectorException = document.getElementById("inspectorException");
        const inspectorNote = document.getElementById("inspectorNote");

        const exceptions = {
            exc004: {
                title: "GCL-006 privileged-account evidence gap",
                id: "EXC-2026-004",
                owner: "IT Security",
                risk: "Medium",
                expiry: "2026-05-23",
                exception: "One application-specific privileged account remains outside the normal myAccess evidence path.",
                note: "Compensation is currently acceptable only because manual owner review, screenshot proof, weekly re-check, and an expiry date are all present."
            },
            exc005: {
                title: "GCL-008 owner-review absence",
                id: "EXC-2026-005",
                owner: "Operations",
                risk: "High",
                expiry: "2026-05-16",
                exception: "No current-cycle owner evidence has been submitted for the ERP → MES → LIMS release-chain control.",
                note: "This is high-risk because the affected control protects release assurance and the exception is already close to expiry."
            },
            exc006: {
                title: "GCL-003 live-sample gap",
                id: "EXC-2026-006",
                owner: "QA Systems",
                risk: "Low",
                expiry: "2026-05-20",
                exception: "A current live operational sample is unavailable during platform transition.",
                note: "Historical sample plus owner confirmation is acceptable only temporarily because the underlying control remains lower risk."
            },
            exc003: {
                title: "GCL-005 middleware confirmation gap",
                id: "EXC-2026-003",
                owner: "QC Governance",
                risk: "Low",
                expiry: "Closed",
                exception: "A temporary middleware confirmation gap existed before the strengthened control version was deployed.",
                note: "This exception is now closed because GCL-005 v1.3 restored normal control operation and clean attestation became possible again."
            }
        };

        inspectButtons.forEach(button => {
            button.addEventListener("click", () => {
                inspectButtons.forEach(btn => btn.classList.remove("active"));
                button.classList.add("active");

                const item = exceptions[button.dataset.exception];
                inspectorTitle.textContent = item.title;
                inspectorId.textContent = item.id;
                inspectorOwner.textContent = item.owner;
                inspectorRisk.textContent = item.risk;
                inspectorExpiry.textContent = item.expiry;
                inspectorException.textContent = item.exception;
                inspectorNote.textContent = item.note;
            });
        });

        const exceptionSelect = document.getElementById("exceptionSelect");
        const checkOwner = document.getElementById("checkOwner");
        const checkCompensation = document.getElementById("checkCompensation");
        const checkExpiry = document.getElementById("checkExpiry");
        const checkRemediation = document.getElementById("checkRemediation");
        const builderTitle = document.getElementById("builderTitle");
        const builderVerdict = document.getElementById("builderVerdict");
        const builderChecks = document.getElementById("builderChecks");
        const builderDisposition = document.getElementById("builderDisposition");
        const builderImpact = document.getElementById("builderImpact");
        const builderNote = document.getElementById("builderNote");

        function updateBuilder() {
            const checks = [checkOwner, checkCompensation, checkExpiry, checkRemediation];
            const passed = checks.filter(check => check.checked).length;

            builderChecks.textContent = passed + " / 4";

            if (passed === 4) {
                builderTitle.textContent = "Exception Acceptable";
                builderVerdict.textContent = "All required safeguards are present. The exception may remain open temporarily under governed acceptance.";
                builderDisposition.textContent = "Accept";
                builderImpact.textContent = "Qualified";
                builderNote.textContent = "An exception is not a free pass. It remains acceptable only while ownership, compensation, expiry, and remediation stay intact.";
            } else if (passed === 3) {
                builderTitle.textContent = "Exception Incomplete";
                builderVerdict.textContent = "One required safeguard is missing. The exception cannot yet be accepted cleanly and requires additional action.";
                builderDisposition.textContent = "Hold";
                builderImpact.textContent = "Not defensible";
                builderNote.textContent = "Missing even one safeguard means the enterprise is carrying undocumented or poorly bounded risk.";
            } else {
                builderTitle.textContent = "Exception Rejected";
                builderVerdict.textContent = "Too many safeguards are missing. The exception should be escalated, remediated, or rejected.";
                builderDisposition.textContent = "Reject";
                builderImpact.textContent = "Escalate";
                builderNote.textContent = "Unowned or uncompensated exceptions are not governance objects; they are uncontrolled gaps.";
            }
        }

        [exceptionSelect, checkOwner, checkCompensation, checkExpiry, checkRemediation].forEach(element => {
            element.addEventListener("change", updateBuilder);
        });

        updateBuilder();

        const actionButtons = document.querySelectorAll(".action-btn");
        const consoleResult = document.getElementById("consoleResult");
        const consoleTitle = document.getElementById("consoleTitle");
        const consoleNote = document.getElementById("consoleNote");

        const outcomes = {
            accept: {
                title: "EXC-2026-004 Accepted Temporarily",
                note: "The exception remains open under owned risk, active compensation, approved expiry, and documented remediation."
            },
            escalate: {
                title: "EXC-2026-005 Escalated",
                note: "The high-risk release-chain exception has been escalated because owner evidence is missing near expiry."
            },
            remediate: {
                title: "Remediation Update Requested",
                note: "The exception owner must provide progress evidence before the approved exception period lapses."
            },
            close: {
                title: "Exception Closed",
                note: "The control may return to clean attestation only after evidence alignment, exception closure, and re-attestation are complete."
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
        print("SKIP: GOVERNANCE_CONTROL_EXCEPTION_WORKBENCH_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/governance-control-exception-workbench")',
        "Governance Control Exception Workbench™",
        "Control Exception Register",
        "Exception Inspector",
        "Interactive Exception Decision Builder",
        "Exception Action Console",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /governance-control-exception-workbench route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
