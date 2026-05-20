from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# DR_EVIDENCE_PASSPORT_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# DR_EVIDENCE_PASSPORT_ACTIVE
@app.route("/dr-evidence-passport")
def dr_evidence_passport_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DR Evidence Passport™ | COBIT-Chain™ / AssuranceLayer™</title>
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
            background: linear-gradient(135deg, #111827 0%, #1d4ed8 42%, #0f766e 100%);
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
        .passport-card {
            background: linear-gradient(180deg, #ffffff 0%, #eff6ff 100%);
            border: 1px solid #bfdbfe;
            border-radius: 22px;
            padding: 20px;
        }
        .passport-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #1d4ed8;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .passport-title {
            font-size: 24px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .passport-note {
            color: #4c5b73;
            line-height: 1.55;
            margin-bottom: 16px;
        }
        .passport-meta {
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
        .lineage-grid {
            display: grid;
            grid-template-columns: repeat(6, minmax(0, 1fr));
            gap: 12px;
        }
        .lineage-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .lineage-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .lineage-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .lineage-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
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
        .lineage-state.red {
            background: #fee2e2;
            color: #991b1b;
        }
        .lineage-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
        }
        .owner-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .owner-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .owner-role {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 7px;
        }
        .owner-name {
            font-size: 17px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .owner-note {
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
            .readiness-grid,
            .owner-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
            .lineage-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .workflow,
            .readiness-grid,
            .lineage-grid,
            .owner-grid,
            .passport-meta,
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
                <a href="/recovery-dependency-validation">Recovery Dependencies</a>
                <a href="/rto-rpo-governance-intelligence">RTO / RPO Intelligence</a>
                <a href="/dr-activation-intelligence">DR Activation</a>
                <a href="/governance-passport">Governance Passport</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Audit-Ready Recovery Evidence Layer</div>
            <h1>DR Evidence Passport™</h1>
            <p>
                The governed evidence object for disaster recovery execution. Instead of leaving restore proof, data reconciliation,
                QA verification, business impact review, and root-cause evidence scattered across separate files, the passport brings
                them into one traceable recovery record with ownership, completeness, lineage, approval state, and audit readiness.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Passport ID</div>
                    <div class="hero-value">DRP-2026-014</div>
                    <div class="hero-note">ERP recovery case</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Artifacts Required</div>
                    <div class="hero-value">6</div>
                    <div class="hero-note">Controlled evidence set</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Artifacts Present</div>
                    <div class="hero-value">3</div>
                    <div class="hero-note">Half complete</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Open Blockers</div>
                    <div class="hero-value">3</div>
                    <div class="hero-note">Reconciliation / CSQA / BQA</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Audit Readiness</div>
                    <div class="hero-value">50%</div>
                    <div class="hero-note">Not yet defensible</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Passport State</div>
                    <div class="hero-value">Draft</div>
                    <div class="hero-note">Cannot certify yet</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Selected DR Evidence Passport</h2>
                <div class="passport-card">
                    <div class="passport-kicker">Recovery Evidence Passport</div>
                    <div class="passport-title">DRP-2026-014 — ERP Recovery</div>
                    <div class="passport-note">
                        This passport captures the controlled evidence required to support the ERP disaster-recovery case:
                        what happened, what was restored, what data was reconciled, what QA verified, what business impact
                        was assessed, and what root cause will prevent recurrence.
                    </div>

                    <div class="passport-meta">
                        <div class="meta-card">
                            <div class="meta-label">Affected System</div>
                            <div class="meta-value">ERP / RC5</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Recovery Case</div>
                            <div class="meta-value">RCV-2026-014</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Current Owner</div>
                            <div class="meta-value">System Custodian</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Target Outcome</div>
                            <div class="meta-value">Audit-Ready</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Passport Readiness</h2>
                <div class="readiness-grid">
                    <div class="readiness-card green">
                        <div class="readiness-label">Damage Assessment</div>
                        <div class="readiness-value">Ready</div>
                        <div class="readiness-note">Event trigger and impact documented.</div>
                    </div>
                    <div class="readiness-card green">
                        <div class="readiness-label">Restore Proof</div>
                        <div class="readiness-value">Ready</div>
                        <div class="readiness-note">Backup restore log attached.</div>
                    </div>
                    <div class="readiness-card red">
                        <div class="readiness-label">Data Proof</div>
                        <div class="readiness-value">Missing</div>
                        <div class="readiness-note">Reconciliation matrix absent.</div>
                    </div>
                    <div class="readiness-card amber">
                        <div class="readiness-label">Approval Proof</div>
                        <div class="readiness-value">Partial</div>
                        <div class="readiness-note">CSQA and BQA still pending.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>DR Evidence Passport Workflow</h2>
            <div class="workflow">
                <div class="step">
                    <div class="step-number">1</div>
                    <h3>Trigger</h3>
                    <p>Capture the disaster event and damage assessment context.</p>
                </div>
                <div class="step">
                    <div class="step-number">2</div>
                    <h3>Restore</h3>
                    <p>Attach backup, restore, and technical recovery evidence.</p>
                </div>
                <div class="step">
                    <div class="step-number">3</div>
                    <h3>Reconcile</h3>
                    <p>Prove restored data against GMP and paper records.</p>
                </div>
                <div class="step">
                    <div class="step-number">4</div>
                    <h3>Verify</h3>
                    <p>Obtain CSQA system-integrity confirmation.</p>
                </div>
                <div class="step">
                    <div class="step-number">5</div>
                    <h3>Assess</h3>
                    <p>Document BQA GMP impact and restart consequence.</p>
                </div>
                <div class="step">
                    <div class="step-number">6</div>
                    <h3>Seal</h3>
                    <p>Complete root cause, approvals, and audit-ready passport status.</p>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Required Evidence Register</h2>
            <p>
                Every required DR artifact is visible with owner, purpose, and completeness status.
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Evidence</button>
                <button class="filter-btn" data-filter="ready">Ready</button>
                <button class="filter-btn" data-filter="pending">Pending</button>
                <button class="filter-btn" data-filter="missing">Missing</button>
                <input id="searchInput" class="search" type="text" placeholder="Search artifact, owner, purpose, or status...">
            </div>

            <table id="evidenceTable">
                <thead>
                    <tr>
                        <th>Artifact</th>
                        <th>Purpose</th>
                        <th>Owner</th>
                        <th>Required For</th>
                        <th>Status</th>
                        <th>Evidence Effect</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-state="ready" data-search="damage assessment report system custodian trigger impact assessment ready">
                        <td>Damage Assessment Report</td>
                        <td>Documents event trigger, impacted systems, and recovery consequence</td>
                        <td>System Custodian</td>
                        <td>Recovery opening</td>
                        <td><span class="pill green">Ready</span></td>
                        <td>Explains why DR began</td>
                    </tr>
                    <tr data-state="ready" data-search="backup restore log system custodian timestamps source success fail ready">
                        <td>Backup Restore Log</td>
                        <td>Proves restore timestamps, source, and success / fail result</td>
                        <td>System Custodian</td>
                        <td>Technical recovery</td>
                        <td><span class="pill green">Ready</span></td>
                        <td>Proves what was restored</td>
                    </tr>
                    <tr data-state="missing" data-search="data reconciliation matrix gmp gaps paper records missing">
                        <td>Data Reconciliation Matrix</td>
                        <td>Compares restored data against GMP gaps and paper records</td>
                        <td>System Custodian + BQA</td>
                        <td>Data truth</td>
                        <td><span class="pill red">Missing</span></td>
                        <td>Blocks recovery closure</td>
                    </tr>
                    <tr data-state="pending" data-search="csqa integrity verification part 11 audit trails pending">
                        <td>CSQA Integrity Verification</td>
                        <td>Confirms audit trails, integrity, and Part 11 posture</td>
                        <td>Computer System QA</td>
                        <td>System integrity</td>
                        <td><span class="pill amber">Pending</span></td>
                        <td>Blocks QA verification</td>
                    </tr>
                    <tr data-state="pending" data-search="bqa gmp impact assessment batch hold release restart pending">
                        <td>BQA GMP Impact Assessment</td>
                        <td>Determines batch hold / release and restart consequence</td>
                        <td>Business QA</td>
                        <td>GMP restart</td>
                        <td><span class="pill amber">Pending</span></td>
                        <td>Blocks restart decision</td>
                    </tr>
                    <tr data-state="ready" data-search="root cause analysis prevention plan ready">
                        <td>Root Cause Analysis</td>
                        <td>Documents why the event happened and what prevents recurrence</td>
                        <td>System Owner</td>
                        <td>Post-recovery learning</td>
                        <td><span class="pill blue">Draft</span></td>
                        <td>Supports continuous improvement</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Evidence Lineage Chain</h2>
            <p>
                The passport preserves the exact path from incident trigger to recovery proof and final approval.
            </p>

            <div class="lineage-grid">
                <div class="lineage-card green">
                    <div class="lineage-title">01. Trigger</div>
                    <div class="lineage-state green">Captured</div>
                    <div class="lineage-note">Damage assessment explains what happened.</div>
                </div>
                <div class="lineage-card green">
                    <div class="lineage-title">02. Restore</div>
                    <div class="lineage-state green">Captured</div>
                    <div class="lineage-note">Backup restore log proves technical recovery.</div>
                </div>
                <div class="lineage-card red">
                    <div class="lineage-title">03. Reconcile</div>
                    <div class="lineage-state red">Missing</div>
                    <div class="lineage-note">Data truth is not yet demonstrated.</div>
                </div>
                <div class="lineage-card amber">
                    <div class="lineage-title">04. Verify</div>
                    <div class="lineage-state amber">Pending</div>
                    <div class="lineage-note">CSQA integrity confirmation remains open.</div>
                </div>
                <div class="lineage-card amber">
                    <div class="lineage-title">05. Assess</div>
                    <div class="lineage-state amber">Pending</div>
                    <div class="lineage-note">BQA has not yet cleared GMP impact.</div>
                </div>
                <div class="lineage-card red">
                    <div class="lineage-title">06. Seal</div>
                    <div class="lineage-state red">Blocked</div>
                    <div class="lineage-note">Passport cannot become audit-ready yet.</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Evidence Ownership Map</h2>
                <div class="owner-grid">
                    <div class="owner-card">
                        <div class="owner-role">System Custodian</div>
                        <div class="owner-name">Restore + Reconciliation</div>
                        <div class="owner-note">
                            Owns technical recovery proof, restore log, and reconciliation initiation.
                        </div>
                    </div>
                    <div class="owner-card">
                        <div class="owner-role">Computer System QA</div>
                        <div class="owner-name">Integrity Verification</div>
                        <div class="owner-note">
                            Confirms audit trails, Part 11 posture, and post-restore system integrity.
                        </div>
                    </div>
                    <div class="owner-card">
                        <div class="owner-role">Business QA</div>
                        <div class="owner-name">GMP Impact Review</div>
                        <div class="owner-note">
                            Determines batch, material, and restart impact before resumption.
                        </div>
                    </div>
                    <div class="owner-card">
                        <div class="owner-role">System Owner</div>
                        <div class="owner-name">Final Passport Accountability</div>
                        <div class="owner-note">
                            Ensures the evidence set is complete and the learning loop is closed.
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Audit Readiness Interpretation</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Passport State</th>
                            <th>Meaning</th>
                            <th>Audit Posture</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Draft</td>
                            <td>Core artifacts missing or approvals open</td>
                            <td><span class="pill red">Not defensible</span></td>
                        </tr>
                        <tr>
                            <td>Reviewable</td>
                            <td>Artifacts exist but one or more approvals remain open</td>
                            <td><span class="pill amber">Partial</span></td>
                        </tr>
                        <tr>
                            <td>Audit-Ready</td>
                            <td>All required evidence and approvals complete</td>
                            <td><span class="pill green">Defensible</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Interactive Passport Builder</h2>
            <p>
                This simulation shows how the passport moves from draft to reviewable to audit-ready as evidence is completed.
            </p>

            <div class="builder">
                <div class="builder-grid">
                    <div class="builder-row">
                        <label>Required Passport Artifacts</label>
                        <div class="check-grid">
                            <label class="check-row">
                                <input id="checkDamage" type="checkbox" checked>
                                Damage Assessment Report attached
                            </label>
                            <label class="check-row">
                                <input id="checkRestore" type="checkbox" checked>
                                Backup Restore Log attached
                            </label>
                            <label class="check-row">
                                <input id="checkReconcile" type="checkbox">
                                Data Reconciliation Matrix approved
                            </label>
                            <label class="check-row">
                                <input id="checkCsqa" type="checkbox">
                                CSQA Integrity Verification completed
                            </label>
                            <label class="check-row">
                                <input id="checkBqa" type="checkbox">
                                BQA GMP Impact Assessment approved
                            </label>
                            <label class="check-row">
                                <input id="checkRca" type="checkbox" checked>
                                Root Cause Analysis drafted
                            </label>
                        </div>
                    </div>
                </div>

                <div class="builder-result">
                    <div class="builder-label">Passport Verdict</div>
                    <div id="builderTitle" class="builder-title">Draft Passport</div>
                    <div id="builderVerdict" class="builder-verdict">
                        Core evidence remains missing. The recovery case is documented, but it is not yet audit-ready.
                    </div>
                    <div class="builder-meta">
                        <div class="builder-mini">
                            <div class="builder-mini-label">Artifacts Complete</div>
                            <div id="builderChecks" class="builder-mini-value">3 / 6</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Passport State</div>
                            <div id="builderState" class="builder-mini-value">Draft</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Audit Posture</div>
                            <div id="builderAudit" class="builder-mini-value">Blocked</div>
                        </div>
                    </div>
                    <div id="builderNote" class="builder-note">
                        A recovery record is only as strong as the evidence that supports it.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Passport Scenario Inspector</h2>
            <p>
                Select a scenario to inspect why a passport is draft, reviewable, or audit-ready.
            </p>

            <div class="inspector">
                <div class="inspector-list">
                    <button class="inspect-btn active" data-scenario="draft">
                        <div class="inspect-kicker">Scenario 01</div>
                        <div class="inspect-title">Draft passport</div>
                        <div class="inspect-note">Restore proof exists, but reconciliation and QA approvals are missing.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="reviewable">
                        <div class="inspect-kicker">Scenario 02</div>
                        <div class="inspect-title">Reviewable passport</div>
                        <div class="inspect-note">Artifacts exist, but one approval remains open.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="auditready">
                        <div class="inspect-kicker">Scenario 03</div>
                        <div class="inspect-title">Audit-ready passport</div>
                        <div class="inspect-note">All evidence and approvals are complete.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="false">
                        <div class="inspect-kicker">Scenario 04</div>
                        <div class="inspect-title">False comfort record</div>
                        <div class="inspect-note">A restore log exists, but no governance proof supports closure.</div>
                    </button>
                </div>

                <div class="inspector-card">
                    <div class="inspector-label">Selected Scenario</div>
                    <div id="inspectorTitle" class="inspector-title">Draft passport</div>
                    <div class="inspector-meta">
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Artifacts</div>
                            <div id="inspectorArtifacts" class="inspector-mini-value">3 / 6</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">State</div>
                            <div id="inspectorState" class="inspector-mini-value">Draft</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Open Blocker</div>
                            <div id="inspectorBlocker" class="inspector-mini-value">Reconciliation + QA</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Audit Posture</div>
                            <div id="inspectorAudit" class="inspector-mini-value">Blocked</div>
                        </div>
                    </div>
                    <div id="inspectorVerdict" class="inspector-verdict">
                        The recovery record is useful, but it cannot support closure because required data and approval evidence remain absent.
                    </div>
                    <div id="inspectorNote" class="inspector-note">
                        This is the right place to see exactly why a recovery case is not yet defensible.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Passport Action Console</h2>
            <p>
                The passport turns missing artifacts into concrete governance work.
            </p>

            <div class="action-console">
                <div class="action-list">
                    <div class="action-item">
                        <div>
                            <h3>Request reconciliation matrix</h3>
                            <p>Open the missing data-truth artifact required for closure.</p>
                        </div>
                        <button class="action-btn" data-action="reconcile">Request</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Route to CSQA</h3>
                            <p>Send the passport for post-restore integrity verification.</p>
                        </div>
                        <button class="action-btn" data-action="csqa">Route</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Open BQA assessment</h3>
                            <p>Require GMP impact review before restart is considered.</p>
                        </div>
                        <button class="action-btn" data-action="bqa">Open</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Generate audit summary</h3>
                            <p>Prepare a one-page proof of current artifact status and blockers.</p>
                        </div>
                        <button class="action-btn" data-action="summary">Generate</button>
                    </div>
                </div>

                <div id="consoleResult" class="console-result">
                    <div class="console-label">Passport Outcome</div>
                    <div id="consoleTitle" class="console-title">Awaiting Action</div>
                    <div id="consoleNote" class="console-note">
                        Select an action to see how the passport converts missing evidence into accountable recovery work.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>Recovery Dependency Validation</h3>
                <p>
                    Proves whether the recovery chain is complete.
                </p>
            </div>
            <div class="maturity-card">
                <h3>DR Evidence Passport</h3>
                <p>
                    Preserves the formal evidence object proving why the recovery chain is or is not complete.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    COBIT-Chain™ now turns recovery evidence into a traceable, audit-ready object rather than scattered files.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by the DR Evidence Passport</h2>
            <p>
                Recovery Dependency Validation™ answers:
                <strong>“Is the recovery chain actually complete?”</strong>
            </p>
            <p>
                DR Evidence Passport™ answers:
                <strong>“What exact controlled evidence proves the recovery status, who owns each artifact, and what remains missing?”</strong>
            </p>
            <p>
                That gives the DR branch its formal evidence spine. The platform no longer only knows that a recovery is incomplete;
                it now shows the controlled evidence packet that must exist before the event can become audit-ready.
            </p>
            <div class="footer-note">
                DR branch: DR Activation Intelligence™ → RTO / RPO Governance Intelligence™ →
                Recovery Dependency Validation™ → DR Evidence Passport™ → future GMP Restart Gate™ →
                Recovery Governance Command Center™ → DR Recovery Certificate™.
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#evidenceTable tbody tr");
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

        const checkDamage = document.getElementById("checkDamage");
        const checkRestore = document.getElementById("checkRestore");
        const checkReconcile = document.getElementById("checkReconcile");
        const checkCsqa = document.getElementById("checkCsqa");
        const checkBqa = document.getElementById("checkBqa");
        const checkRca = document.getElementById("checkRca");
        const builderTitle = document.getElementById("builderTitle");
        const builderVerdict = document.getElementById("builderVerdict");
        const builderChecks = document.getElementById("builderChecks");
        const builderState = document.getElementById("builderState");
        const builderAudit = document.getElementById("builderAudit");
        const builderNote = document.getElementById("builderNote");

        function updateBuilder() {
            const checks = [checkDamage, checkRestore, checkReconcile, checkCsqa, checkBqa, checkRca];
            const passed = checks.filter(check => check.checked).length;

            builderChecks.textContent = passed + " / 6";

            if (passed === 6) {
                builderTitle.textContent = "Audit-Ready Passport";
                builderVerdict.textContent = "All required artifacts and approvals are present. The recovery case is fully supported by controlled evidence.";
                builderState.textContent = "Audit-Ready";
                builderAudit.textContent = "Defensible";
                builderNote.textContent = "A complete passport makes recovery decisions explainable, reviewable, and audit-ready.";
            } else if (passed >= 5) {
                builderTitle.textContent = "Reviewable Passport";
                builderVerdict.textContent = "Most evidence is present, but one remaining artifact or approval still prevents full audit readiness.";
                builderState.textContent = "Reviewable";
                builderAudit.textContent = "Partial";
                builderNote.textContent = "The case may be reviewed, but it should not yet be certified as fully complete.";
            } else {
                builderTitle.textContent = "Draft Passport";
                builderVerdict.textContent = "Core evidence remains missing. The recovery case is documented, but it is not yet audit-ready.";
                builderState.textContent = "Draft";
                builderAudit.textContent = "Blocked";
                builderNote.textContent = "A recovery record is only as strong as the evidence that supports it.";
            }
        }

        [checkDamage, checkRestore, checkReconcile, checkCsqa, checkBqa, checkRca].forEach(element => {
            element.addEventListener("change", updateBuilder);
        });

        updateBuilder();

        const inspectButtons = document.querySelectorAll(".inspect-btn");
        const inspectorTitle = document.getElementById("inspectorTitle");
        const inspectorArtifacts = document.getElementById("inspectorArtifacts");
        const inspectorState = document.getElementById("inspectorState");
        const inspectorBlocker = document.getElementById("inspectorBlocker");
        const inspectorAudit = document.getElementById("inspectorAudit");
        const inspectorVerdict = document.getElementById("inspectorVerdict");
        const inspectorNote = document.getElementById("inspectorNote");

        const scenarios = {
            draft: {
                title: "Draft passport",
                artifacts: "3 / 6",
                state: "Draft",
                blocker: "Reconciliation + QA",
                audit: "Blocked",
                verdict: "The recovery record is useful, but it cannot support closure because required data and approval evidence remain absent.",
                note: "This is the right place to see exactly why a recovery case is not yet defensible."
            },
            reviewable: {
                title: "Reviewable passport",
                artifacts: "5 / 6",
                state: "Reviewable",
                blocker: "BQA approval",
                audit: "Partial",
                verdict: "The evidence set is nearly complete, but one final approval remains open before the case can be called audit-ready.",
                note: "A passport can be useful before it is final, but the open blocker must remain visible."
            },
            auditready: {
                title: "Audit-ready passport",
                artifacts: "6 / 6",
                state: "Audit-Ready",
                blocker: "None",
                audit: "Defensible",
                verdict: "All required artifacts and approvals are present, linked, and reviewable.",
                note: "This is the state that can support final recovery certification."
            },
            false: {
                title: "False comfort record",
                artifacts: "1 / 6",
                state: "Insufficient",
                blocker: "Most evidence absent",
                audit: "Not defensible",
                verdict: "A restore log alone creates a record of technical action, not a governed proof of recovery.",
                note: "The passport prevents isolated technical documents from masquerading as full recovery evidence."
            }
        };

        inspectButtons.forEach(button => {
            button.addEventListener("click", () => {
                inspectButtons.forEach(btn => btn.classList.remove("active"));
                button.classList.add("active");

                const item = scenarios[button.dataset.scenario];
                inspectorTitle.textContent = item.title;
                inspectorArtifacts.textContent = item.artifacts;
                inspectorState.textContent = item.state;
                inspectorBlocker.textContent = item.blocker;
                inspectorAudit.textContent = item.audit;
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
                note: "The missing Data Reconciliation Matrix has been assigned as the next required passport artifact."
            },
            csqa: {
                title: "CSQA Review Routed",
                note: "The passport has been sent for post-restore integrity verification and Part 11 review."
            },
            bqa: {
                title: "BQA Assessment Opened",
                note: "The GMP impact assessment is now required before the passport can become audit-ready."
            },
            summary: {
                title: "Audit Summary Prepared",
                note: "The passport now has a concise evidence-status summary showing current blockers and owners."
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
        print("SKIP: DR_EVIDENCE_PASSPORT_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/dr-evidence-passport")',
        "DR Evidence Passport™",
        "Required Evidence Register",
        "Interactive Passport Builder",
        "Passport Scenario Inspector",
        "Passport Action Console",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /dr-evidence-passport route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
