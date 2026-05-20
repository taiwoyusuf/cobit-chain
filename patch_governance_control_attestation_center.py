from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# GOVERNANCE_CONTROL_ATTESTATION_CENTER_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# GOVERNANCE_CONTROL_ATTESTATION_CENTER_ACTIVE
@app.route("/governance-control-attestation-center")
def governance_control_attestation_center_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Governance Control Attestation Center™ | COBIT-Chain™ / AssuranceLayer™</title>
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
            background: linear-gradient(135deg, #111827 0%, #7c3aed 45%, #0f766e 100%);
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
        .cycle-card {
            background: linear-gradient(180deg, #ffffff 0%, #faf5ff 100%);
            border: 1px solid #e9d5ff;
            border-radius: 22px;
            padding: 20px;
        }
        .cycle-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #7c3aed;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .cycle-title {
            font-size: 24px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .cycle-note {
            color: #4c5b73;
            line-height: 1.55;
            margin-bottom: 16px;
        }
        .cycle-meta {
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
        .cadence-grid {
            display: grid;
            gap: 12px;
        }
        .cadence-row {
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .cadence-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 14px;
            margin-bottom: 10px;
        }
        .cadence-title {
            font-weight: 900;
        }
        .cadence-value {
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
        .bar-fill.amber {
            background: linear-gradient(90deg, #d97706 0%, #f59e0b 100%);
        }
        .bar-fill.red {
            background: linear-gradient(90deg, #dc2626 0%, #ef4444 100%);
        }
        .cadence-note {
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
            background: #7c3aed;
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
        .evidence-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .evidence-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .evidence-card h3 {
            margin: 0 0 8px;
            font-size: 16px;
        }
        .evidence-card p {
            margin: 0 0 12px;
            font-size: 14px;
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
        .exception-grid {
            display: grid;
            gap: 12px;
        }
        .exception-item {
            display: grid;
            grid-template-columns: 60px 1fr auto;
            gap: 14px;
            align-items: start;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .exception-no {
            width: 44px;
            height: 44px;
            border-radius: 14px;
            background: #7c3aed;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 900;
        }
        .exception-title {
            font-weight: 900;
            margin-bottom: 5px;
        }
        .exception-note {
            color: #53637b;
            line-height: 1.45;
            font-size: 14px;
        }
        .exception-owner {
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
            background: #eef4ff;
        }
        .inspect-btn.active {
            border-color: #c4b5fd;
            background: #f5f3ff;
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
            background: #f5f3ff;
            border: 1px solid #c4b5fd;
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
            color: #5b21b6;
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
        .inspector-attestation {
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
            background: #f5f3ff;
            border: 1px solid #c4b5fd;
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
            color: #5b21b6;
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
            background: #7c3aed;
            color: #fff;
            font-weight: 900;
            font-size: 13px;
            white-space: nowrap;
        }
        .console-result {
            border-radius: 22px;
            padding: 22px;
            background: #f5f3ff;
            border: 1px solid #c4b5fd;
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
            color: #5b21b6;
            margin-bottom: 10px;
        }
        .console-note {
            color: #4d5b73;
            line-height: 1.55;
        }
        .maturity-card {
            border-left: 5px solid #7c3aed;
            background: #f5f3ff;
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
            .readiness-grid,
            .evidence-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .workflow,
            .readiness-grid,
            .evidence-grid,
            .cycle-meta,
            .inspector-meta,
            .builder-meta {
                grid-template-columns: 1fr;
            }
            .search {
                margin-left: 0;
                width: 100%;
                min-width: 0;
            }
            .exception-item {
                grid-template-columns: 1fr;
            }
            .exception-owner {
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
                <a href="/governance-control-change-ledger">Change Ledger</a>
                <a href="/governance-control-library">Control Library</a>
                <a href="/governance-control-effectiveness-monitor">Effectiveness Monitor</a>
                <a href="/governance-control-release-orchestrator">Release Orchestrator</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Human Accountability and Periodic Review Layer</div>
            <h1>Governance Control Attestation Center™</h1>
            <p>
                The periodic accountability layer for the enterprise control environment. The Attestation Center confirms
                that each active control still exists, still operates as documented, has current evidence, has known exceptions
                declared, and has been reviewed by the accountable owner before it can remain audit-defensible.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Controls Due</div>
                    <div class="hero-value">12</div>
                    <div class="hero-note">This review cycle</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Attested</div>
                    <div class="hero-value">8</div>
                    <div class="hero-note">Owner-confirmed</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Pending</div>
                    <div class="hero-value">3</div>
                    <div class="hero-note">Awaiting evidence or sign-off</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Exceptions</div>
                    <div class="hero-value">1</div>
                    <div class="hero-note">Declared and tracked</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Audit Defensible</div>
                    <div class="hero-value">67%</div>
                    <div class="hero-note">For current cycle</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Cycle</div>
                    <div class="hero-value">Q2 2026</div>
                    <div class="hero-note">Quarterly review</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Current Attestation Cycle</h2>
                <div class="cycle-card">
                    <div class="cycle-kicker">Quarterly Governance Review</div>
                    <div class="cycle-title">Q2 2026 Control Attestation Cycle</div>
                    <div class="cycle-note">
                        Control owners confirm that published governance controls still match actual operation,
                        required evidence is present, material exceptions are declared, and control status remains defensible
                        after the latest optimization and release changes.
                    </div>

                    <div class="cycle-meta">
                        <div class="meta-card">
                            <div class="meta-label">Cycle Owner</div>
                            <div class="meta-value">Governance Review Board</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Review Window</div>
                            <div class="meta-value">May 1–31, 2026</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Controls in Scope</div>
                            <div class="meta-value">12</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Final Due Date</div>
                            <div class="meta-value">2026-05-31</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Attestation Readiness</h2>
                <div class="readiness-grid">
                    <div class="readiness-card green">
                        <div class="readiness-label">Owner Sign-Off</div>
                        <div class="readiness-value">8</div>
                        <div class="readiness-note">Controls fully attested by accountable owners.</div>
                    </div>
                    <div class="readiness-card amber">
                        <div class="readiness-label">Evidence Pending</div>
                        <div class="readiness-value">2</div>
                        <div class="readiness-note">Required proof not yet complete.</div>
                    </div>
                    <div class="readiness-card red">
                        <div class="readiness-label">Overdue</div>
                        <div class="readiness-value">1</div>
                        <div class="readiness-note">Control owner has not responded.</div>
                    </div>
                    <div class="readiness-card blue">
                        <div class="readiness-label">Exception Review</div>
                        <div class="readiness-value">1</div>
                        <div class="readiness-note">Declared deviation requires disposition.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Review Cadence Health</h2>
                <div class="cadence-grid">
                    <div class="cadence-row">
                        <div class="cadence-top">
                            <div class="cadence-title">Quarterly Control Reviews</div>
                            <div class="cadence-value">92%</div>
                        </div>
                        <div class="bar"><div class="bar-fill green" style="width: 92%;"></div></div>
                        <div class="cadence-note">Most high-consequence controls remain inside review tolerance.</div>
                    </div>
                    <div class="cadence-row">
                        <div class="cadence-top">
                            <div class="cadence-title">Evidence Completeness</div>
                            <div class="cadence-value">83%</div>
                        </div>
                        <div class="bar"><div class="bar-fill amber" style="width: 83%;"></div></div>
                        <div class="cadence-note">Two controls still need current evidence artifacts before attestation.</div>
                    </div>
                    <div class="cadence-row">
                        <div class="cadence-top">
                            <div class="cadence-title">Exception Closure</div>
                            <div class="cadence-value">75%</div>
                        </div>
                        <div class="bar"><div class="bar-fill amber" style="width: 75%;"></div></div>
                        <div class="cadence-note">One declared exception remains open for governance disposition.</div>
                    </div>
                    <div class="cadence-row">
                        <div class="cadence-top">
                            <div class="cadence-title">Late Reviews</div>
                            <div class="cadence-value">8%</div>
                        </div>
                        <div class="bar"><div class="bar-fill red" style="width: 8%;"></div></div>
                        <div class="cadence-note">One overdue owner review is currently affecting cycle readiness.</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>What Is Being Attested</h2>
                <p>
                    The Attestation Center does not ask owners to click “yes” blindly. Each review tests whether the control
                    remains real, current, and supportable.
                </p>
                <div class="evidence-grid">
                    <div class="evidence-card">
                        <h3>Rule Still Active</h3>
                        <p>The documented control is still deployed where the library says it is.</p>
                        <div class="evidence-state green">Confirmed</div>
                    </div>
                    <div class="evidence-card">
                        <h3>Operation Matches Design</h3>
                        <p>The control behaves in live workflow the way its rule logic describes.</p>
                        <div class="evidence-state amber">Evidence Pending</div>
                    </div>
                    <div class="evidence-card">
                        <h3>Evidence Current</h3>
                        <p>Latest test, sample, report, or owner proof is attached and reviewable.</p>
                        <div class="evidence-state green">Attached</div>
                    </div>
                    <div class="evidence-card">
                        <h3>Exceptions Declared</h3>
                        <p>Any known weakness, temporary workaround, or nonconformance is recorded.</p>
                        <div class="evidence-state red">1 Open</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Attestation Workflow</h2>
            <div class="workflow">
                <div class="step">
                    <div class="step-number">1</div>
                    <h3>Scope</h3>
                    <p>Identify controls due for periodic owner review.</p>
                </div>
                <div class="step">
                    <div class="step-number">2</div>
                    <h3>Request</h3>
                    <p>Route attestations to control owners with evidence requirements.</p>
                </div>
                <div class="step">
                    <div class="step-number">3</div>
                    <h3>Review</h3>
                    <p>Owner checks operation, evidence, exceptions, and change history.</p>
                </div>
                <div class="step">
                    <div class="step-number">4</div>
                    <h3>Declare</h3>
                    <p>Owner attests, qualifies, or declares an exception.</p>
                </div>
                <div class="step">
                    <div class="step-number">5</div>
                    <h3>Challenge</h3>
                    <p>Governance reviews unsupported or exception-bearing attestations.</p>
                </div>
                <div class="step">
                    <div class="step-number">6</div>
                    <h3>Certify</h3>
                    <p>Cycle closes only when the control posture is defensible.</p>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Control Attestation Register</h2>
            <p>
                The register shows which controls are attested, which still need evidence, which carry exceptions, and which are overdue.
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Controls</button>
                <button class="filter-btn" data-filter="attested">Attested</button>
                <button class="filter-btn" data-filter="pending">Pending</button>
                <button class="filter-btn" data-filter="exception">Exception</button>
                <button class="filter-btn" data-filter="overdue">Overdue</button>
                <input id="searchInput" class="search" type="text" placeholder="Search control, owner, cadence, or evidence state...">
            </div>

            <table id="attestationTable">
                <thead>
                    <tr>
                        <th>Control</th>
                        <th>Owner</th>
                        <th>Cadence</th>
                        <th>Last Review</th>
                        <th>Evidence Status</th>
                        <th>Exception State</th>
                        <th>Attestation</th>
                        <th>Next Action</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-state="attested" data-search="gcl-001 closure blocker open capa qa governance quarterly attested evidence complete">
                        <td>GCL-001<br><strong>Closure Blocker with Open CAPA</strong></td>
                        <td>QA Governance</td>
                        <td>Quarterly</td>
                        <td>2026-05-04</td>
                        <td><span class="pill green">Complete</span></td>
                        <td><span class="pill green">None</span></td>
                        <td><span class="pill green">Attested</span></td>
                        <td>Maintain</td>
                    </tr>
                    <tr data-state="attested" data-search="gcl-002 approved role granted role it security quarterly attested">
                        <td>GCL-002<br><strong>Approved Role = Granted Role</strong></td>
                        <td>IT Security</td>
                        <td>Quarterly</td>
                        <td>2026-05-06</td>
                        <td><span class="pill green">Complete</span></td>
                        <td><span class="pill green">None</span></td>
                        <td><span class="pill green">Attested</span></td>
                        <td>Maintain</td>
                    </tr>
                    <tr data-state="pending" data-search="gcl-003 release-sensitive record reconciliation qa systems quarterly pending evidence">
                        <td>GCL-003<br><strong>Release-Sensitive Record Reconciliation</strong></td>
                        <td>QA Systems</td>
                        <td>Quarterly</td>
                        <td>2026-02-02</td>
                        <td><span class="pill amber">Pending</span></td>
                        <td><span class="pill green">None</span></td>
                        <td><span class="pill amber">Pending</span></td>
                        <td>Attach live sample</td>
                    </tr>
                    <tr data-state="attested" data-search="gcl-005 downstream release confirmation qc governance quarterly attested">
                        <td>GCL-005<br><strong>Downstream Release Confirmation</strong></td>
                        <td>QC Governance</td>
                        <td>Quarterly</td>
                        <td>2026-05-08</td>
                        <td><span class="pill green">Complete</span></td>
                        <td><span class="pill green">None</span></td>
                        <td><span class="pill green">Attested</span></td>
                        <td>Maintain</td>
                    </tr>
                    <tr data-state="exception" data-search="gcl-006 privileged account owner review it security quarterly exception open">
                        <td>GCL-006<br><strong>Privileged Account Owner Review</strong></td>
                        <td>IT Security</td>
                        <td>Quarterly</td>
                        <td>2026-05-03</td>
                        <td><span class="pill green">Complete</span></td>
                        <td><span class="pill red">1 Open</span></td>
                        <td><span class="pill indigo">Qualified</span></td>
                        <td>Disposition exception</td>
                    </tr>
                    <tr data-state="pending" data-search="gcl-007 periodic review evidence match engineering quarterly pending evidence">
                        <td>GCL-007<br><strong>Periodic Review Evidence Match</strong></td>
                        <td>Engineering</td>
                        <td>Quarterly</td>
                        <td>2026-02-10</td>
                        <td><span class="pill amber">Pending</span></td>
                        <td><span class="pill green">None</span></td>
                        <td><span class="pill amber">Pending</span></td>
                        <td>Upload review evidence</td>
                    </tr>
                    <tr data-state="overdue" data-search="gcl-008 erp mes lims release chain operations overdue quarterly">
                        <td>GCL-008<br><strong>ERP → MES → LIMS Release Chain</strong></td>
                        <td>Operations</td>
                        <td>Quarterly</td>
                        <td>2026-01-28</td>
                        <td><span class="pill red">Missing</span></td>
                        <td><span class="pill amber">Unknown</span></td>
                        <td><span class="pill red">Overdue</span></td>
                        <td>Escalate owner</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Open Exception Queue</h2>
                <div class="exception-grid">
                    <div class="exception-item">
                        <div class="exception-no">01</div>
                        <div>
                            <div class="exception-title">GCL-006 privileged-account review evidence qualified</div>
                            <div class="exception-note">
                                One application-specific privileged account remains outside the standard myAccess evidence path
                                and requires documented disposition before the attestation is fully defensible.
                            </div>
                        </div>
                        <div class="exception-owner">IT Security</div>
                    </div>
                    <div class="exception-item">
                        <div class="exception-no">02</div>
                        <div>
                            <div class="exception-title">GCL-008 owner review overdue</div>
                            <div class="exception-note">
                                ERP → MES → LIMS release-chain control has not been reviewed within the current quarterly window.
                            </div>
                        </div>
                        <div class="exception-owner">Operations</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Evidence Required for Attestation</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Evidence Type</th>
                            <th>Purpose</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Current Rule Version</td>
                            <td>Confirms deployed rule matches library</td>
                            <td><span class="pill green">Attached</span></td>
                        </tr>
                        <tr>
                            <td>Operational Sample</td>
                            <td>Proves the control fires as designed</td>
                            <td><span class="pill amber">2 Pending</span></td>
                        </tr>
                        <tr>
                            <td>Exception Log</td>
                            <td>Declares known nonconformance</td>
                            <td><span class="pill red">1 Open</span></td>
                        </tr>
                        <tr>
                            <td>Owner Certification</td>
                            <td>Human accountability and review record</td>
                            <td><span class="pill blue">8 Complete</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Attestation Inspector</h2>
            <p>
                Select a control to inspect the attestation logic, current owner position, and why the control is or is not yet audit-defensible.
            </p>

            <div class="inspector">
                <div class="inspector-list">
                    <button class="inspect-btn active" data-control="gcl001">
                        <div class="inspect-kicker">GCL-001</div>
                        <div class="inspect-title">Closure Blocker with Open CAPA</div>
                        <div class="inspect-note">Fully attested with complete evidence.</div>
                    </button>
                    <button class="inspect-btn" data-control="gcl003">
                        <div class="inspect-kicker">GCL-003</div>
                        <div class="inspect-title">Release-Sensitive Record Reconciliation</div>
                        <div class="inspect-note">Pending because current operational sample is missing.</div>
                    </button>
                    <button class="inspect-btn" data-control="gcl006">
                        <div class="inspect-kicker">GCL-006</div>
                        <div class="inspect-title">Privileged Account Owner Review</div>
                        <div class="inspect-note">Qualified attestation with one declared exception.</div>
                    </button>
                    <button class="inspect-btn" data-control="gcl008">
                        <div class="inspect-kicker">GCL-008</div>
                        <div class="inspect-title">ERP → MES → LIMS Release Chain</div>
                        <div class="inspect-note">Overdue owner review affects cycle readiness.</div>
                    </button>
                </div>

                <div class="inspector-card">
                    <div class="inspector-label">Selected Attestation</div>
                    <div id="inspectorTitle" class="inspector-title">Closure Blocker with Open CAPA</div>
                    <div class="inspector-meta">
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Owner</div>
                            <div id="inspectorOwner" class="inspector-mini-value">QA Governance</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Attestation State</div>
                            <div id="inspectorState" class="inspector-mini-value">Attested</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Evidence</div>
                            <div id="inspectorEvidence" class="inspector-mini-value">Complete</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Exception</div>
                            <div id="inspectorException" class="inspector-mini-value">None</div>
                        </div>
                    </div>
                    <div id="inspectorAttestation" class="inspector-attestation">
                        Owner confirms that the control remains active, operates as documented, and still blocks closure when linked CAPA remains unresolved.
                    </div>
                    <div id="inspectorNote" class="inspector-note">
                        This control is currently audit-defensible because the rule version, live sample, owner certification, and exception state are all complete.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Interactive Attestation Builder</h2>
            <p>
                This simulation shows why a control should not be considered fully attested until the required evidence and owner declarations are complete.
            </p>

            <div class="builder">
                <div class="builder-grid">
                    <div class="builder-row">
                        <label for="controlSelect">Control Under Review</label>
                        <select id="controlSelect">
                            <option value="gcl001">GCL-001 — Closure Blocker with Open CAPA</option>
                            <option value="gcl003">GCL-003 — Release-Sensitive Record Reconciliation</option>
                            <option value="gcl006">GCL-006 — Privileged Account Owner Review</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label>Required Attestation Checks</label>
                        <div class="check-grid">
                            <label class="check-row">
                                <input id="checkActive" type="checkbox" checked>
                                Rule is still active in live environment
                            </label>
                            <label class="check-row">
                                <input id="checkEvidence" type="checkbox" checked>
                                Current evidence sample is attached
                            </label>
                            <label class="check-row">
                                <input id="checkMatch" type="checkbox" checked>
                                Actual operation matches documented design
                            </label>
                            <label class="check-row">
                                <input id="checkException" type="checkbox" checked>
                                Exceptions are declared and dispositioned
                            </label>
                        </div>
                    </div>
                </div>

                <div class="builder-result">
                    <div class="builder-label">Attestation Verdict</div>
                    <div id="builderTitle" class="builder-title">Fully Attested</div>
                    <div id="builderVerdict" class="builder-verdict">
                        All required checks are complete. The control is eligible to remain active as audit-defensible.
                    </div>
                    <div class="builder-meta">
                        <div class="builder-mini">
                            <div class="builder-mini-label">Checks Passed</div>
                            <div id="builderChecks" class="builder-mini-value">4 / 4</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Owner Position</div>
                            <div id="builderOwner" class="builder-mini-value">Certify</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Cycle Outcome</div>
                            <div id="builderOutcome" class="builder-mini-value">Defensible</div>
                        </div>
                    </div>
                    <div id="builderNote" class="builder-note">
                        Full attestation requires more than owner agreement; it requires current proof, matching operation, and declared exceptions.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Attestation Action Console</h2>
            <p>
                The center routes each review toward the right governance outcome: certify, challenge, escalate, or open an exception.
            </p>

            <div class="action-console">
                <div class="action-list">
                    <div class="action-item">
                        <div>
                            <h3>Certify GCL-001</h3>
                            <p>Record the completed owner attestation and preserve the evidence pack.</p>
                        </div>
                        <button class="action-btn" data-action="certify">Certify</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Request evidence for GCL-003</h3>
                            <p>Require a current operational sample before attestation can close.</p>
                        </div>
                        <button class="action-btn" data-action="evidence">Request</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Disposition GCL-006 exception</h3>
                            <p>Send the qualified attestation for governance review and exception decision.</p>
                        </div>
                        <button class="action-btn" data-action="exception">Route</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Escalate overdue GCL-008 review</h3>
                            <p>Notify the owner that the control is now affecting cycle audit readiness.</p>
                        </div>
                        <button class="action-btn" data-action="escalate">Escalate</button>
                    </div>
                </div>

                <div id="consoleResult" class="console-result">
                    <div class="console-label">Attestation Outcome</div>
                    <div id="consoleTitle" class="console-title">Awaiting Action</div>
                    <div id="consoleNote" class="console-note">
                        Select an action to see how owner review becomes controlled governance evidence.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>Change Ledger</h3>
                <p>
                    Proves how the control changed over time.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Attestation Center</h3>
                <p>
                    Proves that current control owners have periodically reviewed and accepted the live control posture.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    COBIT-Chain™ now combines automation, immutable traceability, and human accountability in one control environment.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by the Attestation Center</h2>
            <p>
                The Governance Control Change Ledger™ answers: <strong>“How and why did this control change?”</strong>
            </p>
            <p>
                The Governance Control Attestation Center™ answers: <strong>“Has the current owner reviewed the live control and confirmed that it remains real, current, and defensible?”</strong>
            </p>
            <p>
                That gives the platform the regulated-enterprise balance it needed: system intelligence, versioned control history,
                and periodic human accountability. A control is not merely published once and forgotten; it is periodically owned,
                evidenced, challenged, and re-accepted.
            </p>
            <div class="footer-note">
                Simulation chain: pain point detection → dependency validation → reconciliation → decision intelligence →
                Governance Passport™ → Governance Assurance Register™ → Governance Intervention Workbench™ →
                Governance Re-Closure Gate™ → Governance Closure Certificate™ → Governance Learning Loop™ →
                Governance Rule Factory™ → Governance Control Library™ → Governance Control Effectiveness Monitor™ →
                Governance Control Optimization Workbench™ → Governance Control Release Orchestrator™ →
                Governance Control Change Ledger™ → Governance Control Attestation Center™.
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#attestationTable tbody tr");
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
        const inspectorOwner = document.getElementById("inspectorOwner");
        const inspectorState = document.getElementById("inspectorState");
        const inspectorEvidence = document.getElementById("inspectorEvidence");
        const inspectorException = document.getElementById("inspectorException");
        const inspectorAttestation = document.getElementById("inspectorAttestation");
        const inspectorNote = document.getElementById("inspectorNote");

        const inspections = {
            gcl001: {
                title: "Closure Blocker with Open CAPA",
                owner: "QA Governance",
                state: "Attested",
                evidence: "Complete",
                exception: "None",
                attestation: "Owner confirms that the control remains active, operates as documented, and still blocks closure when linked CAPA remains unresolved.",
                note: "This control is currently audit-defensible because the rule version, live sample, owner certification, and exception state are all complete."
            },
            gcl003: {
                title: "Release-Sensitive Record Reconciliation",
                owner: "QA Systems",
                state: "Pending",
                evidence: "Missing sample",
                exception: "None",
                attestation: "Owner cannot yet certify the control because the current operational sample has not been attached for this review cycle.",
                note: "The control may still be active, but attestation is not yet defensible without current evidence showing live operation matches documented design."
            },
            gcl006: {
                title: "Privileged Account Owner Review",
                owner: "IT Security",
                state: "Qualified",
                evidence: "Complete",
                exception: "1 open",
                attestation: "Owner confirms the control is operating, but declares one application-specific privileged-account exception requiring formal disposition.",
                note: "This is a valid qualified attestation, but the cycle cannot be considered clean until the declared exception is accepted, mitigated, or closed."
            },
            gcl008: {
                title: "ERP → MES → LIMS Release Chain",
                owner: "Operations",
                state: "Overdue",
                evidence: "Missing",
                exception: "Unknown",
                attestation: "No current-cycle owner attestation has been received for this release-chain control.",
                note: "The control now affects overall cycle readiness because lack of owner review leaves the current operating posture unconfirmed."
            }
        };

        inspectButtons.forEach(button => {
            button.addEventListener("click", () => {
                inspectButtons.forEach(btn => btn.classList.remove("active"));
                button.classList.add("active");

                const item = inspections[button.dataset.control];
                inspectorTitle.textContent = item.title;
                inspectorOwner.textContent = item.owner;
                inspectorState.textContent = item.state;
                inspectorEvidence.textContent = item.evidence;
                inspectorException.textContent = item.exception;
                inspectorAttestation.textContent = item.attestation;
                inspectorNote.textContent = item.note;
            });
        });

        const controlSelect = document.getElementById("controlSelect");
        const checkActive = document.getElementById("checkActive");
        const checkEvidence = document.getElementById("checkEvidence");
        const checkMatch = document.getElementById("checkMatch");
        const checkException = document.getElementById("checkException");
        const builderTitle = document.getElementById("builderTitle");
        const builderVerdict = document.getElementById("builderVerdict");
        const builderChecks = document.getElementById("builderChecks");
        const builderOwner = document.getElementById("builderOwner");
        const builderOutcome = document.getElementById("builderOutcome");
        const builderNote = document.getElementById("builderNote");

        function updateBuilder() {
            const checks = [checkActive, checkEvidence, checkMatch, checkException];
            const passed = checks.filter(check => check.checked).length;

            builderChecks.textContent = passed + " / 4";

            if (passed === 4) {
                builderTitle.textContent = "Fully Attested";
                builderVerdict.textContent = "All required checks are complete. The control is eligible to remain active as audit-defensible.";
                builderOwner.textContent = "Certify";
                builderOutcome.textContent = "Defensible";
                builderNote.textContent = "Full attestation requires more than owner agreement; it requires current proof, matching operation, and declared exceptions.";
            } else if (passed === 3) {
                builderTitle.textContent = "Qualified Review";
                builderVerdict.textContent = "One required condition is still incomplete. The owner may qualify the review, but the control is not fully defensible yet.";
                builderOwner.textContent = "Qualify";
                builderOutcome.textContent = "Needs action";
                builderNote.textContent = "A single missing evidence or exception condition is enough to keep the review from closing cleanly.";
            } else {
                builderTitle.textContent = "Attestation Blocked";
                builderVerdict.textContent = "Too many required checks are incomplete. The control cannot be attested this cycle.";
                builderOwner.textContent = "Cannot certify";
                builderOutcome.textContent = "Blocked";
                builderNote.textContent = "Controls without current evidence, matching operation, and owner declaration remain audit-exposed.";
            }
        }

        [controlSelect, checkActive, checkEvidence, checkMatch, checkException].forEach(element => {
            element.addEventListener("change", updateBuilder);
        });

        updateBuilder();

        const actionButtons = document.querySelectorAll(".action-btn");
        const consoleResult = document.getElementById("consoleResult");
        const consoleTitle = document.getElementById("consoleTitle");
        const consoleNote = document.getElementById("consoleNote");

        const outcomes = {
            certify: {
                title: "GCL-001 Certified",
                note: "The completed owner attestation and supporting evidence pack have been preserved for the Q2 2026 cycle."
            },
            evidence: {
                title: "Evidence Request Issued",
                note: "GCL-003 remains pending until QA Systems attaches a current operational sample for this cycle."
            },
            exception: {
                title: "Exception Routed",
                note: "The qualified GCL-006 attestation has been sent for governance disposition of the declared privileged-account exception."
            },
            escalate: {
                title: "Overdue Review Escalated",
                note: "GCL-008 owner review has been escalated because it is now affecting current-cycle audit readiness."
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
        print("SKIP: GOVERNANCE_CONTROL_ATTESTATION_CENTER_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/governance-control-attestation-center")',
        "Governance Control Attestation Center™",
        "Control Attestation Register",
        "Attestation Inspector",
        "Interactive Attestation Builder",
        "Attestation Action Console",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /governance-control-attestation-center route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
