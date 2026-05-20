from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# DR_ACTIVATION_INTELLIGENCE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# DR_ACTIVATION_INTELLIGENCE_ACTIVE
@app.route("/dr-activation-intelligence")
def dr_activation_intelligence_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DR Activation Intelligence™ | COBIT-Chain™ / AssuranceLayer™</title>
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
            background: linear-gradient(135deg, #111827 0%, #0f4c5c 45%, #7c2d12 100%);
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
            max-width: 1130px;
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
        .incident-card {
            background: linear-gradient(180deg, #ffffff 0%, #f0fdfa 100%);
            border: 1px solid #99f6e4;
            border-radius: 22px;
            padding: 20px;
        }
        .incident-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #0f766e;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .incident-title {
            font-size: 24px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .incident-note {
            color: #4c5b73;
            line-height: 1.55;
            margin-bottom: 16px;
        }
        .incident-meta {
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
        .threshold-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .threshold-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .threshold-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .threshold-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .threshold-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .threshold-card.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .threshold-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .threshold-value {
            font-size: 28px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .threshold-note {
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
            background: #0f4c5c;
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
        .criteria-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 12px;
        }
        .criteria-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .criteria-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .criteria-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .criteria-card.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .criteria-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .criteria-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
            margin-bottom: 10px;
        }
        .criteria-chip {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
            background: rgba(255,255,255,.72);
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
        .system-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .system-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .system-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .system-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
            margin-bottom: 11px;
        }
        .system-state {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
            background: #dbeafe;
            color: #1d4ed8;
        }
        .role-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .role-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .role-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .role-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
            margin-bottom: 11px;
        }
        .role-state {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
            background: #ccfbf1;
            color: #115e59;
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
            background: #0f4c5c;
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
            border-left: 5px solid #0f4c5c;
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
            .criteria-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
            .threshold-grid,
            .system-grid,
            .role-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .workflow,
            .criteria-grid,
            .threshold-grid,
            .system-grid,
            .role-grid,
            .incident-meta,
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
                <a href="/governance-recovery-simulator">Recovery Simulator</a>
                <a href="/governance-decision-engine">Decision Engine</a>
                <a href="/cross-system-dependency-validation">Dependency Validation</a>
                <a href="/executive-mission-control">Mission Control</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Operational Recovery Governance Branch</div>
            <h1>DR Activation Intelligence™</h1>
            <p>
                The decision doorway into disaster recovery governance. This module determines whether an event remains
                normal incident response or has crossed into formal DR activation by weighing RTO breach, RPO loss,
                system criticality, compliance impact, cybersecurity severity, infrastructure failure, utility failure,
                and the governance approvals required for escalation.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Current Event</div>
                    <div class="hero-value">INC-DR-014</div>
                    <div class="hero-note">ERP outage + data-loss concern</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">System Class</div>
                    <div class="hero-value">RC5</div>
                    <div class="hero-note">High-risk GMP system</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Downtime</div>
                    <div class="hero-value">51h</div>
                    <div class="hero-note">RTO threshold exceeded</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Estimated Data Recovery</div>
                    <div class="hero-value">99.7%</div>
                    <div class="hero-note">Below 99.9% target</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Activation State</div>
                    <div class="hero-value">DR Required</div>
                    <div class="hero-note">Level 4 logic triggered</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Next Authority</div>
                    <div class="hero-value">System Owner</div>
                    <div class="hero-note">Escalate for approval</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Current Recovery Event</h2>
                <div class="incident-card">
                    <div class="incident-kicker">Activation Assessment</div>
                    <div class="incident-title">ERP / Supply Chain Recovery Disruption</div>
                    <div class="incident-note">
                        An RC5 enterprise system has exceeded the acceptable downtime window and estimated data recovery
                        has fallen below the target threshold. Because the system supports procurement, supply-chain continuity,
                        and regulatory data, the event can no longer be treated as routine restoration only.
                    </div>

                    <div class="incident-meta">
                        <div class="meta-card">
                            <div class="meta-label">Affected System</div>
                            <div class="meta-value">ERP / Finance & Supply Chain</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Criticality</div>
                            <div class="meta-value">High / RC5</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Observed Trigger</div>
                            <div class="meta-value">RTO + RPO Breach</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Governance Decision</div>
                            <div class="meta-value">Activate DRP</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Threshold Snapshot</h2>
                <div class="threshold-grid">
                    <div class="threshold-card red">
                        <div class="threshold-label">Actual Downtime</div>
                        <div class="threshold-value">51h</div>
                        <div class="threshold-note">Exceeds 24–48h RTO window for critical system.</div>
                    </div>
                    <div class="threshold-card red">
                        <div class="threshold-label">Estimated Recovery</div>
                        <div class="threshold-value">99.7%</div>
                        <div class="threshold-note">Below 99.9% RPO expectation for ERP.</div>
                    </div>
                    <div class="threshold-card amber">
                        <div class="threshold-label">Compliance Impact</div>
                        <div class="threshold-value">High</div>
                        <div class="threshold-note">Product release and GMP records may be affected.</div>
                    </div>
                    <div class="threshold-card blue">
                        <div class="threshold-label">Escalation Level</div>
                        <div class="threshold-value">L4</div>
                        <div class="threshold-note">Cannot be handled by standard restore only.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>DR Activation Workflow</h2>
            <div class="workflow">
                <div class="step">
                    <div class="step-number">1</div>
                    <h3>Detect Event</h3>
                    <p>Incident affects a system or service important to GMP or continuity.</p>
                </div>
                <div class="step">
                    <div class="step-number">2</div>
                    <h3>Classify System</h3>
                    <p>Determine RC level, business criticality, and production dependency.</p>
                </div>
                <div class="step">
                    <div class="step-number">3</div>
                    <h3>Compare Thresholds</h3>
                    <p>Check actual downtime, data loss, utility impact, and compliance triggers.</p>
                </div>
                <div class="step">
                    <div class="step-number">4</div>
                    <h3>Assess Escalation</h3>
                    <p>Decide whether the event remains incident response or enters DR governance.</p>
                </div>
                <div class="step">
                    <div class="step-number">5</div>
                    <h3>Notify Authorities</h3>
                    <p>Route to System Owner, Custodians, QA, and business leadership.</p>
                </div>
                <div class="step">
                    <div class="step-number">6</div>
                    <h3>Activate DRP</h3>
                    <p>Launch controlled recovery only when activation criteria are satisfied.</p>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Activation Criteria Library</h2>
            <p>
                Formal DR activation is driven by specific governance triggers, not by outage anxiety alone.
            </p>

            <div class="criteria-grid">
                <div class="criteria-card red">
                    <div class="criteria-title">Critical Downtime</div>
                    <div class="criteria-note">
                        Manufacturing, quality, or IT systems remain unavailable beyond the defined RTO.
                    </div>
                    <div class="criteria-chip">RTO breach</div>
                </div>
                <div class="criteria-card red">
                    <div class="criteria-title">Data Integrity Loss</div>
                    <div class="criteria-note">
                        Missing, corrupted, or unrecoverable GMP data exceeds the tolerated RPO threshold.
                    </div>
                    <div class="criteria-chip">RPO breach</div>
                </div>
                <div class="criteria-card amber">
                    <div class="criteria-title">Infrastructure Disaster</div>
                    <div class="criteria-note">
                        Servers, networks, labs, or environmental infrastructure cannot support safe operation.
                    </div>
                    <div class="criteria-chip">Physical / utility failure</div>
                </div>
                <div class="criteria-card amber">
                    <div class="criteria-title">Cybersecurity Severity</div>
                    <div class="criteria-note">
                        A critical breach affects manufacturing control, quality data, or regulated records.
                    </div>
                    <div class="criteria-chip">Critical security</div>
                </div>
                <div class="criteria-card blue">
                    <div class="criteria-title">Compliance Risk</div>
                    <div class="criteria-note">
                        The event jeopardizes GMP compliance, reporting obligations, or product release capability.
                    </div>
                    <div class="criteria-chip">GMP trigger</div>
                </div>
                <div class="criteria-card blue">
                    <div class="criteria-title">Extended Utility Failure</div>
                    <div class="criteria-note">
                        Power, network, HVAC, or environmental controls fail beyond acceptable operating thresholds.
                    </div>
                    <div class="criteria-chip">Utility trigger</div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>System Criticality Register</h2>
            <p>
                The same outage means something very different depending on the system’s risk category and function in production.
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Systems</button>
                <button class="filter-btn" data-filter="rc5">RC5</button>
                <button class="filter-btn" data-filter="rc4">RC4</button>
                <button class="filter-btn" data-filter="rc3">RC3</button>
                <button class="filter-btn" data-filter="rc2">RC2</button>
                <input id="searchInput" class="search" type="text" placeholder="Search system, function, criticality, or RPO target...">
            </div>

            <table id="criticalityTable">
                <thead>
                    <tr>
                        <th>Risk Category</th>
                        <th>System Type</th>
                        <th>Production Function</th>
                        <th>Criticality</th>
                        <th>RTO</th>
                        <th>RPO Target</th>
                        <th>Activation Sensitivity</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-category="rc5" data-search="rc5 erp finance supply chain procurement isotopes high 24-48 hours 99.9">
                        <td><span class="pill red">RC5</span></td>
                        <td>ERP / Finance & Supply Chain</td>
                        <td>Procurement, finance, supply continuity</td>
                        <td>High</td>
                        <td>24–48h</td>
                        <td>≥ 99.9%</td>
                        <td>Very High</td>
                    </tr>
                    <tr data-category="rc5" data-search="rc5 chromatography data system purity radio-ligand compounds high 24-48 99.8">
                        <td><span class="pill red">RC5</span></td>
                        <td>Chromatography Data System</td>
                        <td>Purity analysis before release</td>
                        <td>High</td>
                        <td>24–48h</td>
                        <td>≥ 99.8%</td>
                        <td>Very High</td>
                    </tr>
                    <tr data-category="rc5" data-search="rc5 continuous environmental monitoring temperature humidity production areas high 24-48 99.9">
                        <td><span class="pill red">RC5</span></td>
                        <td>Continuous Environmental Monitoring</td>
                        <td>Temperature / humidity protection</td>
                        <td>High</td>
                        <td>24–48h</td>
                        <td>≥ 99.9%</td>
                        <td>Very High</td>
                    </tr>
                    <tr data-category="rc4" data-search="rc4 environmental monitoring airborne particles cleanrooms medium 24-48 95">
                        <td><span class="pill amber">RC4</span></td>
                        <td>Environmental Monitoring</td>
                        <td>Cleanroom particle monitoring</td>
                        <td>Medium</td>
                        <td>24–48h</td>
                        <td>≥ 95%</td>
                        <td>High</td>
                    </tr>
                    <tr data-category="rc3" data-search="rc3 asset calibration management calibration lab equipment medium 24-48 95">
                        <td><span class="pill blue">RC3</span></td>
                        <td>Asset & Calibration Management</td>
                        <td>Calibration tracking</td>
                        <td>Medium</td>
                        <td>24–48h</td>
                        <td>≥ 95%</td>
                        <td>Moderate</td>
                    </tr>
                    <tr data-category="rc2" data-search="rc2 weighing instruments pH measurement instruments medium 24-48 95">
                        <td><span class="pill indigo">RC2</span></td>
                        <td>Weighing / pH Instruments</td>
                        <td>Measurement support</td>
                        <td>Medium</td>
                        <td>24–48h</td>
                        <td>≥ 95%</td>
                        <td>Moderate</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Recovery Ownership Map</h2>
                <div class="role-grid">
                    <div class="role-card">
                        <div class="role-title">System Owner</div>
                        <div class="role-note">
                            Owns DR strategy, approves Level 3–4 activation, and aligns production-impact decisions.
                        </div>
                        <div class="role-state">Activation authority</div>
                    </div>
                    <div class="role-card">
                        <div class="role-title">System Custodian</div>
                        <div class="role-note">
                            Executes technical recovery, leads Level 1–2 response, documents recovery actions.
                        </div>
                        <div class="role-state">Technical lead</div>
                    </div>
                    <div class="role-card">
                        <div class="role-title">Computer System QA</div>
                        <div class="role-note">
                            Verifies integrity after restore, reviews data reconciliation, confirms validation posture.
                        </div>
                        <div class="role-state">Integrity gate</div>
                    </div>
                    <div class="role-card">
                        <div class="role-title">Business QA</div>
                        <div class="role-note">
                            Assesses GMP impact, approves resumption of activities, and reconciles business records.
                        </div>
                        <div class="role-state">GMP restart gate</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Activation Decision Ladder</h2>
                <div class="system-grid">
                    <div class="system-card">
                        <div class="system-title">Level 1</div>
                        <div class="system-note">
                            Local issue; handled by System Custodian through standard restart or rollback.
                        </div>
                        <div class="system-state">Incident response</div>
                    </div>
                    <div class="system-card">
                        <div class="system-title">Level 2</div>
                        <div class="system-note">
                            Broader technical recovery; escalate only if thresholds or GMP risk worsen.
                        </div>
                        <div class="system-state">Escalated incident</div>
                    </div>
                    <div class="system-card">
                        <div class="system-title">Level 3</div>
                        <div class="system-note">
                            Major recovery event requiring System Owner approval and cross-functional governance.
                        </div>
                        <div class="system-state">Partial DR</div>
                    </div>
                    <div class="system-card">
                        <div class="system-title">Level 4</div>
                        <div class="system-note">
                            RPO exceeded, major compliance risk, or full disaster condition; standard restore is insufficient.
                        </div>
                        <div class="system-state">Full DR activation</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Interactive Activation Engine</h2>
            <p>
                This simulation shows how the same event can remain an ordinary incident or cross into DR activation depending on criticality, RTO, RPO, and compliance impact.
            </p>

            <div class="builder">
                <div class="builder-grid">
                    <div class="builder-row">
                        <label for="systemSelect">System Type</label>
                        <select id="systemSelect">
                            <option value="erp">ERP / Finance & Supply Chain — RC5</option>
                            <option value="cds">Chromatography Data System — RC5</option>
                            <option value="em">Environmental Monitoring — RC4</option>
                            <option value="weighing">Weighing Instruments — RC2</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label for="downtimeSelect">Actual Downtime</label>
                        <select id="downtimeSelect">
                            <option value="12">12 hours</option>
                            <option value="36">36 hours</option>
                            <option value="51">51 hours</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label for="recoverySelect">Estimated Data Recovery</label>
                        <select id="recoverySelect">
                            <option value="99.95">99.95%</option>
                            <option value="99.90">99.90%</option>
                            <option value="99.70">99.70%</option>
                            <option value="94.00">94.00%</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label for="triggerSelect">Additional Trigger</label>
                        <select id="triggerSelect">
                            <option value="none">No additional trigger</option>
                            <option value="compliance">Compliance / GMP risk</option>
                            <option value="cyber">Critical cybersecurity breach</option>
                            <option value="utility">Extended utility failure</option>
                        </select>
                    </div>
                </div>

                <div class="builder-result">
                    <div class="builder-label">Recommended Governance Decision</div>
                    <div id="builderTitle" class="builder-title">Full DR Activation</div>
                    <div id="builderVerdict" class="builder-verdict">
                        RC5 ERP has exceeded RTO and fallen below its RPO target. The event should move to Level 4 DR governance.
                    </div>
                    <div class="builder-meta">
                        <div class="builder-mini">
                            <div class="builder-mini-label">Severity</div>
                            <div id="builderSeverity" class="builder-mini-value">Level 4</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">Next Authority</div>
                            <div id="builderAuthority" class="builder-mini-value">System Owner</div>
                        </div>
                        <div class="builder-mini">
                            <div class="builder-mini-label">GMP Posture</div>
                            <div id="builderGmp" class="builder-mini-value">Hold / assess</div>
                        </div>
                    </div>
                    <div id="builderNote" class="builder-note">
                        Technical restore alone is not enough once threshold and compliance logic indicate governed DR activation.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Activation Scenario Inspector</h2>
            <p>
                Select a scenario to inspect why the platform recommends routine handling, partial DR, or full activation.
            </p>

            <div class="inspector">
                <div class="inspector-list">
                    <button class="inspect-btn active" data-scenario="erp">
                        <div class="inspect-kicker">Scenario 01</div>
                        <div class="inspect-title">ERP outage beyond RTO</div>
                        <div class="inspect-note">RTO breached and RPO below target.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="cyber">
                        <div class="inspect-kicker">Scenario 02</div>
                        <div class="inspect-title">Critical ransomware event</div>
                        <div class="inspect-note">Cybersecurity severity alone can activate DR governance.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="em">
                        <div class="inspect-kicker">Scenario 03</div>
                        <div class="inspect-title">Environmental monitoring gap</div>
                        <div class="inspect-note">Medium-risk system with GMP implications.</div>
                    </button>
                    <button class="inspect-btn" data-scenario="local">
                        <div class="inspect-kicker">Scenario 04</div>
                        <div class="inspect-title">Local instrument restart</div>
                        <div class="inspect-note">Below threshold; remains standard response.</div>
                    </button>
                </div>

                <div class="inspector-card">
                    <div class="inspector-label">Selected Scenario</div>
                    <div id="inspectorTitle" class="inspector-title">ERP outage beyond RTO</div>
                    <div class="inspector-meta">
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">System</div>
                            <div id="inspectorSystem" class="inspector-mini-value">ERP / RC5</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Trigger</div>
                            <div id="inspectorTrigger" class="inspector-mini-value">RTO + RPO breach</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Decision</div>
                            <div id="inspectorDecision" class="inspector-mini-value">Full DR</div>
                        </div>
                        <div class="inspector-mini">
                            <div class="inspector-mini-label">Authority</div>
                            <div id="inspectorAuthority" class="inspector-mini-value">System Owner</div>
                        </div>
                    </div>
                    <div id="inspectorVerdict" class="inspector-verdict">
                        Standard restoration is no longer sufficient because the event exceeds both the allowed recovery time and the tolerated data-loss boundary.
                    </div>
                    <div id="inspectorNote" class="inspector-note">
                        Once thresholds are crossed on a high-risk system, the platform should recommend DR activation, QA involvement, and controlled recovery governance.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Activation Action Console</h2>
            <p>
                The module routes each event toward the correct governance action instead of treating all outages the same.
            </p>

            <div class="action-console">
                <div class="action-list">
                    <div class="action-item">
                        <div>
                            <h3>Escalate to System Owner</h3>
                            <p>Route the Level 4 activation decision for formal DR approval.</p>
                        </div>
                        <button class="action-btn" data-action="owner">Escalate</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Notify CSQA and BQA</h3>
                            <p>Trigger integrity verification and GMP-impact assessment workstreams.</p>
                        </div>
                        <button class="action-btn" data-action="qa">Notify</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Open DR evidence packet</h3>
                            <p>Prepare damage assessment, restore log, reconciliation, and approval artifacts.</p>
                        </div>
                        <button class="action-btn" data-action="evidence">Open</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Hold GMP restart</h3>
                            <p>Prevent premature resumption until recovery proof and QA approvals are complete.</p>
                        </div>
                        <button class="action-btn" data-action="hold">Hold</button>
                    </div>
                </div>

                <div id="consoleResult" class="console-result">
                    <div class="console-label">Activation Outcome</div>
                    <div id="consoleTitle" class="console-title">Awaiting Action</div>
                    <div id="consoleNote" class="console-note">
                        Select an action to see how DR activation becomes governed recovery, not just technical troubleshooting.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>Incident Response</h3>
                <p>
                    Handles local or routine disruption while thresholds remain within tolerance.
                </p>
            </div>
            <div class="maturity-card">
                <h3>DR Activation Intelligence</h3>
                <p>
                    Detects when time, data, compliance, or severity thresholds require governed DR activation.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    COBIT-Chain™ now distinguishes between “system down” and “enterprise recovery governance required.”
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by DR Activation Intelligence</h2>
            <p>
                The existing recovery modules answer: <strong>“How do we recover?”</strong>
            </p>
            <p>
                DR Activation Intelligence™ answers the prior and more strategic question:
                <strong>“When does an event become serious enough that ordinary incident handling is no longer sufficient?”</strong>
            </p>
            <p>
                That is the correct starting point for the new Operational Recovery Governance branch. From here,
                the platform can move into RTO/RPO intelligence, recovery dependency validation, DR evidence passports,
                GMP restart gates, recovery command centers, and final recovery certification.
            </p>
            <div class="footer-note">
                DR branch entry point: DR Activation Intelligence™ → future RTO / RPO Governance Intelligence™ →
                Recovery Dependency Validation™ → DR Evidence Passport™ → GMP Restart Gate™ →
                Recovery Governance Command Center™ → DR Recovery Certificate™.
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#criticalityTable tbody tr");
        const searchInput = document.getElementById("searchInput");
        let activeFilter = "all";

        function applyFilters() {
            const query = searchInput.value.toLowerCase().trim();

            rows.forEach(row => {
                const category = row.dataset.category;
                const searchable = row.dataset.search;
                const matchesFilter = activeFilter === "all" || category === activeFilter;
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

        const systemSelect = document.getElementById("systemSelect");
        const downtimeSelect = document.getElementById("downtimeSelect");
        const recoverySelect = document.getElementById("recoverySelect");
        const triggerSelect = document.getElementById("triggerSelect");
        const builderTitle = document.getElementById("builderTitle");
        const builderVerdict = document.getElementById("builderVerdict");
        const builderSeverity = document.getElementById("builderSeverity");
        const builderAuthority = document.getElementById("builderAuthority");
        const builderGmp = document.getElementById("builderGmp");
        const builderNote = document.getElementById("builderNote");

        const systemProfiles = {
            erp: {
                label: "RC5 ERP",
                rpo: 99.9,
                highRisk: true
            },
            cds: {
                label: "RC5 Chromatography Data System",
                rpo: 99.8,
                highRisk: true
            },
            em: {
                label: "RC4 Environmental Monitoring",
                rpo: 95.0,
                highRisk: false
            },
            weighing: {
                label: "RC2 Weighing Instruments",
                rpo: 95.0,
                highRisk: false
            }
        };

        function updateBuilder() {
            const profile = systemProfiles[systemSelect.value];
            const downtime = Number(downtimeSelect.value);
            const recovery = Number(recoverySelect.value);
            const trigger = triggerSelect.value;

            const rtoBreached = downtime > 48;
            const rpoBreached = recovery < profile.rpo;
            const criticalTrigger = trigger === "compliance" || trigger === "cyber";
            const utilityTrigger = trigger === "utility";

            if ((profile.highRisk && rpoBreached) || (profile.highRisk && rtoBreached) || criticalTrigger) {
                builderTitle.textContent = "Full DR Activation";
                builderVerdict.textContent = profile.label + " has crossed a disaster-recovery threshold. The event should move into formal DR governance.";
                builderSeverity.textContent = "Level 4";
                builderAuthority.textContent = "System Owner";
                builderGmp.textContent = "Hold / assess";
                builderNote.textContent = "Technical restore alone is not enough once high-risk thresholds or compliance triggers are breached.";
            } else if (rtoBreached || utilityTrigger) {
                builderTitle.textContent = "Partial DR Escalation";
                builderVerdict.textContent = profile.label + " has crossed a significant recovery threshold and should move beyond routine incident response.";
                builderSeverity.textContent = "Level 3";
                builderAuthority.textContent = "System Owner";
                builderGmp.textContent = "Assess impact";
                builderNote.textContent = "The event requires cross-functional review even if it has not yet reached full DR activation.";
            } else {
                builderTitle.textContent = "Standard Incident Response";
                builderVerdict.textContent = profile.label + " remains within defined recovery tolerance and may continue under standard incident handling.";
                builderSeverity.textContent = "Level 1–2";
                builderAuthority.textContent = "System Custodian";
                builderGmp.textContent = "Monitor";
                builderNote.textContent = "The system is still within threshold, so standard recovery remains appropriate unless conditions worsen.";
            }
        }

        [systemSelect, downtimeSelect, recoverySelect, triggerSelect].forEach(element => {
            element.addEventListener("change", updateBuilder);
        });

        updateBuilder();

        const inspectButtons = document.querySelectorAll(".inspect-btn");
        const inspectorTitle = document.getElementById("inspectorTitle");
        const inspectorSystem = document.getElementById("inspectorSystem");
        const inspectorTrigger = document.getElementById("inspectorTrigger");
        const inspectorDecision = document.getElementById("inspectorDecision");
        const inspectorAuthority = document.getElementById("inspectorAuthority");
        const inspectorVerdict = document.getElementById("inspectorVerdict");
        const inspectorNote = document.getElementById("inspectorNote");

        const scenarios = {
            erp: {
                title: "ERP outage beyond RTO",
                system: "ERP / RC5",
                trigger: "RTO + RPO breach",
                decision: "Full DR",
                authority: "System Owner",
                verdict: "Standard restoration is no longer sufficient because the event exceeds both the allowed recovery time and the tolerated data-loss boundary.",
                note: "Once thresholds are crossed on a high-risk system, the platform should recommend DR activation, QA involvement, and controlled recovery governance."
            },
            cyber: {
                title: "Critical ransomware event",
                system: "QC / RC5",
                trigger: "Critical cybersecurity breach",
                decision: "Full DR",
                authority: "System Owner",
                verdict: "A critical breach affecting regulated systems should activate DR governance even before ordinary recovery metrics are fully known.",
                note: "Cyber severity can itself become the activation trigger because integrity, availability, and regulatory records may all be compromised."
            },
            em: {
                title: "Environmental monitoring gap",
                system: "Environmental Monitoring / RC4",
                trigger: "Extended utility failure",
                decision: "Partial DR",
                authority: "System Owner",
                verdict: "The system is medium-risk, but prolonged environmental-control loss creates GMP consequence and therefore needs structured escalation.",
                note: "The right answer is not always full DR, but it is also not silent continuation of routine handling."
            },
            local: {
                title: "Local instrument restart",
                system: "Weighing Instruments / RC2",
                trigger: "Below threshold",
                decision: "Incident Response",
                authority: "System Custodian",
                verdict: "The issue remains local, within tolerance, and suitable for standard restart or rollback procedure.",
                note: "Not every failure is a disaster. The platform must be able to prevent over-escalation as well as under-escalation."
            }
        };

        inspectButtons.forEach(button => {
            button.addEventListener("click", () => {
                inspectButtons.forEach(btn => btn.classList.remove("active"));
                button.classList.add("active");

                const item = scenarios[button.dataset.scenario];
                inspectorTitle.textContent = item.title;
                inspectorSystem.textContent = item.system;
                inspectorTrigger.textContent = item.trigger;
                inspectorDecision.textContent = item.decision;
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
            owner: {
                title: "Escalated to System Owner",
                note: "INC-DR-014 has been routed for formal Level 4 DR activation approval."
            },
            qa: {
                title: "QA Workstreams Notified",
                note: "CSQA and BQA have been engaged for integrity verification and GMP-impact assessment."
            },
            evidence: {
                title: "DR Evidence Packet Opened",
                note: "Damage assessment, restore log, reconciliation, integrity verification, and impact-assessment artifacts are now required."
            },
            hold: {
                title: "GMP Restart Held",
                note: "Production restart remains blocked until recovery evidence and QA approvals are complete."
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
        print("SKIP: DR_ACTIVATION_INTELLIGENCE_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/dr-activation-intelligence")',
        "DR Activation Intelligence™",
        "Activation Criteria Library",
        "System Criticality Register",
        "Interactive Activation Engine",
        "Activation Action Console",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /dr-activation-intelligence route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
