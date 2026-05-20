from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# GOVERNANCE_CONTROL_EXCEPTION_CLOSURE_GATE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# GOVERNANCE_CONTROL_EXCEPTION_CLOSURE_GATE_ACTIVE
@app.route("/governance-control-exception-closure-gate")
def governance_control_exception_closure_gate_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Governance Control Exception Closure Gate™ | COBIT-Chain™ / AssuranceLayer™</title>
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
            background: linear-gradient(135deg, #111827 0%, #166534 45%, #0f766e 100%);
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
        .closure-card {
            background: linear-gradient(180deg, #ffffff 0%, #f0fdf4 100%);
            border: 1px solid #bbf7d0;
            border-radius: 22px;
            padding: 20px;
        }
        .closure-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #166534;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .closure-title {
            font-size: 24px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .closure-note {
            color: #4c5b73;
            line-height: 1.55;
            margin-bottom: 16px;
        }
        .closure-meta {
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
        .readiness-card.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .readiness-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
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
            grid-template-columns: repeat(5, minmax(0, 1fr));
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
        .retirement-grid {
            display: grid;
            gap: 12px;
        }
        .retirement-item {
            display: grid;
            grid-template-columns: 60px 1fr auto;
            gap: 14px;
            align-items: start;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .retirement-no {
            width: 44px;
            height: 44px;
            border-radius: 14px;
            background: #166534;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 900;
        }
        .retirement-title {
            font-weight: 900;
            margin-bottom: 5px;
        }
        .retirement-note {
            color: #53637b;
            line-height: 1.45;
            font-size: 14px;
        }
        .retirement-owner {
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
            background: #f0fdf4;
        }
        .inspect-btn.active {
            border-color: #86efac;
            background: #f0fdf4;
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
            background: #f0fdf4;
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
            background: #f0fdf4;
            border: 1px solid #86efac;
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
            background: #f0fdf4;
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
            .gate-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .readiness-grid,
            .return-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .workflow,
            .gate-grid,
            .readiness-grid,
            .return-grid,
            .closure-meta,
            .inspector-meta,
            .builder-meta {
                grid-template-columns: 1fr;
            }
            .search {
                margin-left: 0;
                width: 100%;
                min-width: 0;
            }
            .retirement-item {
                grid-template-columns: 1fr;
            }
            .retirement-owner {
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
                <a href="/governance-control-exception-workbench">Exception Workbench</a>
                <a href="/governance-control-attestation-center">Attestation Center</a>
                <a href="/governance-control-change-ledger">Change Ledger</a>
                <a href="/governance-control-library">Control Library</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Return-to-Clean-Attestation Decision Layer</div>
            <h1>Governance Control Exception Closure Gate™</h1>
            <p>
                The final decision gate for control exceptions. An exception is not closed because the owner says remediation
                is finished; it closes only when the original condition is resolved, the normal evidence path is restored,
                compensating controls are no longer needed, re-attestation is complete, and the control can safely return
                from qualified status to clean audit-defensible operation.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Closure Candidates</div>
                    <div class="hero-value">3</div>
                    <div class="hero-note">Ready for gate review</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Gate-Passed</div>
                    <div class="hero-value">2</div>
                    <div class="hero-note">Eligible to close</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Still Blocked</div>
                    <div class="hero-value">1</div>
                    <div class="hero-note">Evidence path incomplete</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Compensating Controls Retired</div>
                    <div class="hero-value">2</div>
                    <div class="hero-note">After normal control restored</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Clean Re-Attestation</div>
                    <div class="hero-value">2</div>
                    <div class="hero-note">Returned this cycle</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Closure State</div>
                    <div class="hero-value">Controlled</div>
                    <div class="hero-note">No silent exception exits</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Selected Closure Candidate</h2>
                <div class="closure-card">
                    <div class="closure-kicker">Exception Closure Candidate</div>
                    <div class="closure-title">EXC-2026-004 — GCL-006 Privileged Account Review</div>
                    <div class="closure-note">
                        The application-specific privileged account has now been brought into the normal evidence path,
                        approval evidence is attached, the temporary manual review is no longer needed, and the control is
                        ready to be tested for return to clean attestation.
                    </div>

                    <div class="closure-meta">
                        <div class="meta-card">
                            <div class="meta-label">Original Exception</div>
                            <div class="meta-value">Evidence Gap</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Remediation Owner</div>
                            <div class="meta-value">IT Security</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Compensation</div>
                            <div class="meta-value">Ready to Retire</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Target Outcome</div>
                            <div class="meta-value">Clean Attestation</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Closure Readiness Snapshot</h2>
                <div class="readiness-grid">
                    <div class="readiness-card green">
                        <div class="readiness-label">Root Condition</div>
                        <div class="readiness-value">Resolved</div>
                        <div class="readiness-note">Account is now captured in the governed evidence path.</div>
                    </div>
                    <div class="readiness-card green">
                        <div class="readiness-label">Evidence Path</div>
                        <div class="readiness-value">Restored</div>
                        <div class="readiness-note">Approval and entitlement proof are attached.</div>
                    </div>
                    <div class="readiness-card green">
                        <div class="readiness-label">Re-Attestation</div>
                        <div class="readiness-value">Passed</div>
                        <div class="readiness-note">Owner confirmed normal operation again.</div>
                    </div>
                    <div class="readiness-card amber">
                        <div class="readiness-label">Ledger Update</div>
                        <div class="readiness-value">Pending</div>
                        <div class="readiness-note">Final closure record awaits posting.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Exception Closure Workflow</h2>
            <div class="workflow">
                <div class="step">
                    <div class="step-number">1</div>
                    <h3>Claim Remediation</h3>
                    <p>Owner states that the exception condition has been corrected.</p>
                </div>
                <div class="step">
                    <div class="step-number">2</div>
                    <h3>Restore Evidence</h3>
                    <p>Normal proof path must be re-established, not merely explained.</p>
                </div>
                <div class="step">
                    <div class="step-number">3</div>
                    <h3>Retest Control</h3>
                    <p>Confirm the control now operates as originally designed.</p>
                </div>
                <div class="step">
                    <div class="step-number">4</div>
                    <h3>Re-Attest</h3>
                    <p>Owner formally certifies the restored clean control state.</p>
                </div>
                <div class="step">
                    <div class="step-number">5</div>
                    <h3>Retire Compensation</h3>
                    <p>Temporary safeguards are removed only after normal control returns.</p>
                </div>
                <div class="step">
                    <div class="step-number">6</div>
                    <h3>Close and Record</h3>
                    <p>Exception closes, attestation cleans, and the ledger is updated.</p>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Closure Gate Matrix</h2>
            <p>
                An exception may close only when every required closure gate is satisfied.
            </p>

            <div class="gate-grid">
                <div class="gate-card green">
                    <div class="gate-title">Gate 01 — Condition Resolved</div>
                    <div class="gate-status green">PASS</div>
                    <div class="gate-note">The original evidence-path failure no longer exists.</div>
                </div>
                <div class="gate-card green">
                    <div class="gate-title">Gate 02 — Evidence Restored</div>
                    <div class="gate-status green">PASS</div>
                    <div class="gate-note">Normal approval and role-state proof are now attached.</div>
                </div>
                <div class="gate-card green">
                    <div class="gate-title">Gate 03 — Control Retested</div>
                    <div class="gate-status green">PASS</div>
                    <div class="gate-note">The control operates again as documented.</div>
                </div>
                <div class="gate-card green">
                    <div class="gate-title">Gate 04 — Re-Attested</div>
                    <div class="gate-status green">PASS</div>
                    <div class="gate-note">The owner has certified the restored control state.</div>
                </div>
                <div class="gate-card amber">
                    <div class="gate-title">Gate 05 — Ledger Posted</div>
                    <div class="gate-status amber">PENDING</div>
                    <div class="gate-note">Closure is ready, but final immutable record is not yet posted.</div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Exception Closure Register</h2>
            <p>
                Every candidate is tested before it is allowed to leave exception status.
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Candidates</button>
                <button class="filter-btn" data-filter="ready">Ready</button>
                <button class="filter-btn" data-filter="blocked">Blocked</button>
                <button class="filter-btn" data-filter="closed">Closed</button>
                <input id="searchInput" class="search" type="text" placeholder="Search exception, control, owner, or closure gate...">
            </div>

            <table id="closureTable">
                <thead>
                    <tr>
                        <th>Exception</th>
                        <th>Affected Control</th>
                        <th>Closure Evidence</th>
                        <th>Re-Attestation</th>
                        <th>Compensation</th>
                        <th>Ledger</th>
                        <th>Closure State</th>
                        <th>Next Action</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-state="ready" data-search="exc-2026-004 gcl-006 privileged account review evidence restored re-attested ledger pending ready">
                        <td>EXC-2026-004</td>
                        <td>GCL-006 — Privileged Account Owner Review</td>
                        <td><span class="pill green">Restored</span></td>
                        <td><span class="pill green">Passed</span></td>
                        <td><span class="pill green">Retire</span></td>
                        <td><span class="pill amber">Pending</span></td>
                        <td><span class="pill blue">Ready</span></td>
                        <td>Post ledger</td>
                    </tr>
                    <tr data-state="blocked" data-search="exc-2026-005 gcl-008 erp mes lims release chain owner review missing blocked">
                        <td>EXC-2026-005</td>
                        <td>GCL-008 — ERP → MES → LIMS Release Chain</td>
                        <td><span class="pill red">Missing</span></td>
                        <td><span class="pill red">Not possible</span></td>
                        <td><span class="pill amber">Remain</span></td>
                        <td><span class="pill red">Not eligible</span></td>
                        <td><span class="pill red">Blocked</span></td>
                        <td>Escalate owner</td>
                    </tr>
                    <tr data-state="ready" data-search="exc-2026-006 gcl-003 release-sensitive reconciliation live sample restored ready">
                        <td>EXC-2026-006</td>
                        <td>GCL-003 — Release-Sensitive Record Reconciliation</td>
                        <td><span class="pill green">Restored</span></td>
                        <td><span class="pill green">Passed</span></td>
                        <td><span class="pill green">Retire</span></td>
                        <td><span class="pill amber">Pending</span></td>
                        <td><span class="pill blue">Ready</span></td>
                        <td>Post ledger</td>
                    </tr>
                    <tr data-state="closed" data-search="exc-2026-003 gcl-005 downstream release confirmation closed ledger complete">
                        <td>EXC-2026-003</td>
                        <td>GCL-005 — Downstream Release Confirmation</td>
                        <td><span class="pill green">Restored</span></td>
                        <td><span class="pill green">Passed</span></td>
                        <td><span class="pill green">Retired</span></td>
                        <td><span class="pill green">Posted</span></td>
                        <td><span class="pill green">Closed</span></td>
                        <td>Returned clean</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Return to Clean Attestation</h2>
                <div class="return-grid">
                    <div class="return-card green">
                        <div class="return-title">Normal Evidence Path</div>
                        <div class="return-value">Restored</div>
                        <div class="return-note">No temporary evidence workaround remains necessary.</div>
                    </div>
                    <div class="return-card green">
                        <div class="return-title">Owner Re-Attestation</div>
                        <div class="return-value">Complete</div>
                        <div class="return-note">Control owner has certified clean operation.</div>
                    </div>
                    <div class="return-card green">
                        <div class="return-title">Qualified Status</div>
                        <div class="return-value">Removed</div>
                        <div class="return-note">The control is no longer carried as exception-qualified.</div>
                    </div>
                    <div class="return-card amber">
                        <div class="return-title">Final Ledger Seal</div>
                        <div class="return-value">Pending</div>
                        <div class="return-note">Required before the exception is formally closed.</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Compensating Control Retirement Plan</h2>
                <div class="retirement-grid">
                    <div class="retirement-item">
                        <div class="retirement-no">1</div>
                        <div>
                            <div class="retirement-title">Retire manual owner review</div>
                            <div class="retirement-note">
                                Remove the temporary weekly manual review once normal evidence capture is confirmed.
                            </div>
                        </div>
                        <div class="retirement-owner">IT Security</div>
                    </div>
                    <div class="retirement-item">
                        <div class="retirement-no">2</div>
                        <div>
                            <div class="retirement-title">Archive screenshot proof</div>
                            <div class="retirement-note">
                                Preserve the historical compensating evidence but stop using it as active proof.
                            </div>
                        </div>
                        <div class="retirement-owner">Control Owner</div>
                    </div>
                    <div class="retirement-item">
                        <div class="retirement-no">3</div>
                        <div>
                            <div class="retirement-title">Restore standard review cadence</div>
                            <div class="retirement-note">
                                Return GCL-006 to ordinary quarterly attestation with no exception overlay.
                            </div>
                        </div>
                        <div class="retirement-owner">Governance</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Closure Inspector</h2>
            <p>
                Select a candidate to inspect why it is ready, blocked, or already closed.
            </p>

            <div class="inspector">
                <div class="inspector-list">
                    <button class="inspect-btn active" data-candidate="exc004">
                        <div class="inspect-kicker">EXC-2026-004</div>
                        <div class="inspect-title">GCL-006 ready for closure</div>
                        <div class="inspect-note">Evidence restored; ledger still pending.</div>
                    </button>
                    <button class="inspect-btn" data-candidate="exc005">
                        <div class="inspect-kicker">EXC-2026-005</div>
                        <div class="inspect-title">GCL-008 blocked</div>
                        <div class="inspect-note">Owner evidence still missing; cannot close.</div>
                    </button>
                    <button class="inspect-btn" data-candidate="exc006">
                        <div class="inspect-kicker">EXC-2026-006</div>
                        <div class="inspect-title">GCL-003 ready for closure</div>
                        <div class="inspect-note">Live sample restored; ledger still pending.</div>
                    </button>
                    <button class="inspect-btn" data-candidate="exc003">
                        <div class="inspect-kicker">EXC-2026-003</div>
                        <div class="inspect-title">GCL-005 already closed</div>
                        <div class="inspect-note">All gates passed and ledger posted.</div>
                    </button>
                </div>

                <div class="inspector-card">
                    <div class="inspector-label">Selected Closure Candidate</div>
                    <div id="inspectorTitle" class="inspector-title">GCL-006 ready for closure</div>
                    <div class="inspector-meta">
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Exception</div>
                            <div id="inspectorId" class="inspector-mini-value">EXC-2026-004</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Gate State</div>
                            <div id="inspectorState" class="inspector-mini-value">Ready</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Re-Attestation</div>
                            <div id="inspectorReattest" class="inspector-mini-value">Passed</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Final Blocker</div>
                            <div id="inspectorBlocker" class="inspector-mini-value">Ledger pending</div>
                        </div>
                    </div>
                    <div id="inspectorVerdict" class="inspector-verdict">
                        The exception condition is resolved, evidence is restored, the temporary compensation may retire, and only the final ledger posting remains before formal closure.
                    </div>
                    <div id="inspectorNote" class="inspector-note">
                        This candidate is eligible to return to clean attestation once the closure record is immutably posted.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Interactive Closure Gate Builder</h2>
            <p>
                This simulation shows why “remediation completed” is not enough by itself to close an exception.
            </p>

            <div class="builder">
                <div class="builder-grid">
                    <div class="builder-row">
                        <label for="candidateSelect">Closure Candidate</label>
                        <select id="candidateSelect">
                            <option value="exc004">EXC-2026-004 — GCL-006 privileged-account evidence gap</option>
                            <option value="exc005">EXC-2026-005 — GCL-008 owner-review absence</option>
                            <option value="exc006">EXC-2026-006 — GCL-003 live-sample gap</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label>Required Closure Gates</label>
                        <div class="check-grid">
                            <label class="check-row">
                                <input id="checkResolved" type="checkbox" checked>
                                Original exception condition resolved
                            </label>
                            <label class="check-row">
                                <input id="checkEvidence" type="checkbox" checked>
                                Normal evidence path restored
                            </label>
                            <label class="check-row">
                                <input id="checkReattest" type="checkbox" checked>
                                Owner re-attestation completed
                            </label>
                            <label class="check-row">
                                <input id="checkLedger" type="checkbox" checked>
                                Closure posted to governance ledger
                            </label>
                        </div>
                    </div>
                </div>

                <div class="builder-result">
                    <div class="builder-label">Closure Verdict</div>
                    <div id="builderTitle" class="builder-title">Closure Authorized</div>
                    <div id="builderVerdict" class="builder-verdict">
                        All required gates are satisfied. The exception may close and the control may return to clean attestation.
                    </div>
                    <div class="builder-meta">
                        <div class="builder-mini">
                            <div class="builder-mini-label">Gates Passed</div>
                            <div id="builderChecks" class="builder-mini-value">4 / 4</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Disposition</div>
                            <div id="builderDisposition" class="builder-mini-value">Close</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Attestation State</div>
                            <div id="builderAttestation" class="builder-mini-value">Clean</div>
                        </div>
                    </div>
                    <div id="builderNote" class="builder-note">
                        Clean closure requires correction, proof, re-attestation, and immutable recording — not just completion of a task.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Closure Action Console</h2>
            <p>
                The gate routes each exception toward the appropriate final governance action.
            </p>

            <div class="action-console">
                <div class="action-list">
                    <div class="action-item">
                        <div>
                            <h3>Post EXC-2026-004 closure ledger</h3>
                            <p>Seal the final record and allow GCL-006 to return to clean attestation.</p>
                        </div>
                        <button class="action-btn" data-action="post">Post</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Reject EXC-2026-005 closure</h3>
                            <p>Keep the high-risk exception open because owner evidence is still missing.</p>
                        </div>
                        <button class="action-btn" data-action="reject">Reject</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Retire compensating controls</h3>
                            <p>Remove temporary safeguards once normal control operation is restored.</p>
                        </div>
                        <button class="action-btn" data-action="retire">Retire</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Return control to clean attestation</h3>
                            <p>Send the remediated control back to ordinary review status.</p>
                        </div>
                        <button class="action-btn" data-action="return">Return</button>
                    </div>
                </div>

                <div id="consoleResult" class="console-result">
                    <div class="console-label">Closure Outcome</div>
                    <div id="consoleTitle" class="console-title">Awaiting Action</div>
                    <div id="consoleNote" class="console-note">
                        Select an action to see how exceptions are closed only after the full return path is proven.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>Exception Workbench</h3>
                <p>
                    Governs the open exception while imperfect reality still exists.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Closure Gate</h3>
                <p>
                    Proves the exception is truly resolved before the control returns to clean status.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    COBIT-Chain™ prevents both silent exceptions and premature exception closure.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by the Exception Closure Gate</h2>
            <p>
                The Governance Control Exception Workbench™ answers: <strong>“How do we govern an exception while it remains open?”</strong>
            </p>
            <p>
                The Governance Control Exception Closure Gate™ answers: <strong>“What must be true before we are allowed to say the exception is genuinely closed?”</strong>
            </p>
            <p>
                That finishes the control-governance branch properly. A control can now be attested, qualified, exception-governed,
                remediated, closure-gated, and finally returned to clean attestation with proof.
            </p>
            <div class="footer-note">
                Simulation chain: pain point detection → dependency validation → reconciliation → decision intelligence →
                Governance Passport™ → Governance Assurance Register™ → Governance Intervention Workbench™ →
                Governance Re-Closure Gate™ → Governance Closure Certificate™ → Governance Learning Loop™ →
                Governance Rule Factory™ → Governance Control Library™ → Governance Control Effectiveness Monitor™ →
                Governance Control Optimization Workbench™ → Governance Control Release Orchestrator™ →
                Governance Control Change Ledger™ → Governance Control Attestation Center™ →
                Governance Control Exception Workbench™ → Governance Control Exception Closure Gate™.
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#closureTable tbody tr");
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
        const inspectorId = document.getElementById("inspectorId");
        const inspectorState = document.getElementById("inspectorState");
        const inspectorReattest = document.getElementById("inspectorReattest");
        const inspectorBlocker = document.getElementById("inspectorBlocker");
        const inspectorVerdict = document.getElementById("inspectorVerdict");
        const inspectorNote = document.getElementById("inspectorNote");

        const candidates = {
            exc004: {
                title: "GCL-006 ready for closure",
                id: "EXC-2026-004",
                state: "Ready",
                reattest: "Passed",
                blocker: "Ledger pending",
                verdict: "The exception condition is resolved, evidence is restored, the temporary compensation may retire, and only the final ledger posting remains before formal closure.",
                note: "This candidate is eligible to return to clean attestation once the closure record is immutably posted."
            },
            exc005: {
                title: "GCL-008 blocked",
                id: "EXC-2026-005",
                state: "Blocked",
                reattest: "Not possible",
                blocker: "Owner evidence missing",
                verdict: "The exception cannot close because the original problem remains unresolved and there is no current-cycle owner evidence.",
                note: "This candidate must stay open and escalated; closing it now would create false governance comfort."
            },
            exc006: {
                title: "GCL-003 ready for closure",
                id: "EXC-2026-006",
                state: "Ready",
                reattest: "Passed",
                blocker: "Ledger pending",
                verdict: "The live sample is now available, the normal evidence path is restored, and only the final governance record remains outstanding.",
                note: "This candidate can return to clean attestation after the closure record is posted."
            },
            exc003: {
                title: "GCL-005 already closed",
                id: "EXC-2026-003",
                state: "Closed",
                reattest: "Passed",
                blocker: "None",
                verdict: "All closure gates passed, the compensating control was retired, and the final record was posted.",
                note: "This is the model end state: remediated, re-attested, immutably recorded, and clean again."
            }
        };

        inspectButtons.forEach(button => {
            button.addEventListener("click", () => {
                inspectButtons.forEach(btn => btn.classList.remove("active"));
                button.classList.add("active");

                const item = candidates[button.dataset.candidate];
                inspectorTitle.textContent = item.title;
                inspectorId.textContent = item.id;
                inspectorState.textContent = item.state;
                inspectorReattest.textContent = item.reattest;
                inspectorBlocker.textContent = item.blocker;
                inspectorVerdict.textContent = item.verdict;
                inspectorNote.textContent = item.note;
            });
        });

        const candidateSelect = document.getElementById("candidateSelect");
        const checkResolved = document.getElementById("checkResolved");
        const checkEvidence = document.getElementById("checkEvidence");
        const checkReattest = document.getElementById("checkReattest");
        const checkLedger = document.getElementById("checkLedger");
        const builderTitle = document.getElementById("builderTitle");
        const builderVerdict = document.getElementById("builderVerdict");
        const builderChecks = document.getElementById("builderChecks");
        const builderDisposition = document.getElementById("builderDisposition");
        const builderAttestation = document.getElementById("builderAttestation");
        const builderNote = document.getElementById("builderNote");

        function updateBuilder() {
            const checks = [checkResolved, checkEvidence, checkReattest, checkLedger];
            const passed = checks.filter(check => check.checked).length;

            builderChecks.textContent = passed + " / 4";

            if (passed === 4) {
                builderTitle.textContent = "Closure Authorized";
                builderVerdict.textContent = "All required gates are satisfied. The exception may close and the control may return to clean attestation.";
                builderDisposition.textContent = "Close";
                builderAttestation.textContent = "Clean";
                builderNote.textContent = "Clean closure requires correction, proof, re-attestation, and immutable recording — not just completion of a task.";
            } else if (passed === 3) {
                builderTitle.textContent = "Closure Pending";
                builderVerdict.textContent = "One required gate is still incomplete. The exception may be close to resolution, but it cannot be formally closed yet.";
                builderDisposition.textContent = "Hold";
                builderAttestation.textContent = "Qualified";
                builderNote.textContent = "A nearly fixed exception is still an open exception until every return-to-clean gate is proven.";
            } else {
                builderTitle.textContent = "Closure Rejected";
                builderVerdict.textContent = "Too many closure gates are incomplete. The exception must remain open and governed.";
                builderDisposition.textContent = "Reject";
                builderAttestation.textContent = "Exception";
                builderNote.textContent = "Premature closure would recreate the same false-comfort problem the platform is designed to prevent.";
            }
        }

        [candidateSelect, checkResolved, checkEvidence, checkReattest, checkLedger].forEach(element => {
            element.addEventListener("change", updateBuilder);
        });

        updateBuilder();

        const actionButtons = document.querySelectorAll(".action-btn");
        const consoleResult = document.getElementById("consoleResult");
        const consoleTitle = document.getElementById("consoleTitle");
        const consoleNote = document.getElementById("consoleNote");

        const outcomes = {
            post: {
                title: "Closure Ledger Posted",
                note: "EXC-2026-004 now has its final immutable closure record and may return to clean attestation."
            },
            reject: {
                title: "Closure Rejected",
                note: "EXC-2026-005 remains open because owner evidence is still missing and the original condition is not resolved."
            },
            retire: {
                title: "Compensating Controls Retired",
                note: "Temporary review safeguards may now be archived because normal control operation has been restored."
            },
            return: {
                title: "Control Returned Clean",
                note: "The remediated control has exited qualified status and returned to ordinary attestation cadence."
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
        print("SKIP: GOVERNANCE_CONTROL_EXCEPTION_CLOSURE_GATE_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/governance-control-exception-closure-gate")',
        "Governance Control Exception Closure Gate™",
        "Closure Gate Matrix",
        "Exception Closure Register",
        "Interactive Closure Gate Builder",
        "Closure Action Console",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /governance-control-exception-closure-gate route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
