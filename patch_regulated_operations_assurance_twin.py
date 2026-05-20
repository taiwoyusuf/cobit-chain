from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# REGULATED_OPERATIONS_ASSURANCE_TWIN_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# ============================================================
# REGULATED_OPERATIONS_ASSURANCE_TWIN_ACTIVE
# Umbrella flagship page for COBIT-Chain™ / AssuranceLayer™.
# Additive route only; does not modify protected modules.
# ============================================================

@app.route("/regulated-operations-assurance-twin")
def regulated_operations_assurance_twin_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Regulated Operations Assurance Twin™ | COBIT-Chain™ / AssuranceLayer™</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #f4f7fb;
            color: #172033;
        }
        .shell {
            max-width: 1560px;
            margin: 0 auto;
            padding: 28px 22px 46px;
        }
        .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
            flex-wrap: wrap;
            margin-bottom: 22px;
        }
        .brand {
            font-size: 14px;
            font-weight: 900;
            color: #1d4ed8;
            letter-spacing: .06em;
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
            font-weight: 800;
        }
        .hero {
            background:
                radial-gradient(circle at top left, rgba(34,197,94,.20), transparent 30%),
                radial-gradient(circle at bottom right, rgba(14,165,233,.24), transparent 34%),
                linear-gradient(135deg, #071527 0%, #0f2745 42%, #1d4ed8 100%);
            color: #fff;
            border-radius: 30px;
            padding: 34px;
            box-shadow: 0 18px 46px rgba(15, 23, 42, .25);
            margin-bottom: 20px;
        }
        .eyebrow {
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: .08em;
            opacity: .84;
            font-weight: 900;
            margin-bottom: 10px;
        }
        h1 {
            margin: 0 0 10px;
            font-size: 42px;
            line-height: 1.10;
            letter-spacing: -.8px;
        }
        .hero p {
            max-width: 1240px;
            margin: 0;
            line-height: 1.58;
            font-size: 16px;
            opacity: .96;
        }
        .hero-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 12px;
            margin-top: 24px;
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
            font-size: 22px;
            font-weight: 900;
        }
        .hero-note {
            font-size: 12px;
            opacity: .84;
            margin-top: 5px;
            line-height: 1.35;
        }
        .panel {
            background: #fff;
            border-radius: 22px;
            padding: 22px;
            box-shadow: 0 10px 28px rgba(22, 42, 74, .08);
            margin-bottom: 18px;
        }
        .panel h2 {
            margin: 0 0 15px;
            font-size: 22px;
        }
        .panel p {
            line-height: 1.58;
            color: #44536b;
            margin: 0 0 14px;
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
        .grid-4 {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 14px;
            margin-bottom: 18px;
        }
        .statement {
            border-left: 7px solid #1d4ed8;
            border-radius: 18px;
            padding: 18px;
            background: linear-gradient(135deg,#eff6ff,#ffffff);
            line-height: 1.64;
            font-size: 17px;
            font-weight: 800;
        }
        .definition-card {
            border-radius: 18px;
            padding: 18px;
            border: 1px solid #dbeafe;
            background: #f8fbff;
        }
        .definition-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #64748b;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .definition-title {
            font-size: 19px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .definition-note {
            color: #516078;
            line-height: 1.48;
            font-size: 14px;
        }
        .operating-model {
            display: grid;
            grid-template-columns: repeat(7, minmax(0, 1fr));
            gap: 12px;
        }
        .model-step {
            border-radius: 18px;
            padding: 16px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .model-step strong {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 34px;
            height: 34px;
            border-radius: 12px;
            background: #1d4ed8;
            color: #fff;
            font-size: 14px;
            margin-bottom: 10px;
        }
        .model-step h3 {
            margin: 0 0 8px;
            font-size: 16px;
        }
        .model-step p {
            margin: 0;
            font-size: 13px;
            line-height: 1.46;
            color: #53637b;
        }
        .map-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .map-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .map-card.highlight {
            background: #ecfeff;
            border-color: #67e8f9;
        }
        .map-kicker {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 900;
            margin-bottom: 7px;
        }
        .map-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .map-note {
            font-size: 14px;
            color: #516078;
            line-height: 1.45;
        }
        .map-card a {
            display: inline-block;
            margin-top: 10px;
            text-decoration: none;
            background: #0f172a;
            color: #fff;
            padding: 8px 11px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 900;
        }
        .domain-grid {
            display: grid;
            grid-template-columns: repeat(7, minmax(0, 1fr));
            gap: 12px;
        }
        .domain-card {
            border-radius: 18px;
            padding: 16px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
            cursor: pointer;
            transition: transform .15s ease, background .15s ease, border-color .15s ease;
        }
        .domain-card:hover {
            transform: translateY(-2px);
            background: #eff6ff;
            border-color: #93c5fd;
        }
        .domain-card.active {
            background: #eff6ff;
            border-color: #60a5fa;
            box-shadow: 0 10px 24px rgba(37,99,235,.12);
        }
        .domain-kicker {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 900;
            margin-bottom: 7px;
        }
        .domain-title {
            font-size: 15px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .domain-note {
            font-size: 13px;
            color: #516078;
            line-height: 1.43;
        }
        .sim-layout {
            display: grid;
            grid-template-columns: 1.05fr .95fr;
            gap: 18px;
        }
        .signal-grid {
            display: grid;
            gap: 12px;
        }
        .signal-row {
            border: 1px solid #e2eaf7;
            background: #f8fbff;
            border-radius: 18px;
            padding: 16px;
        }
        .signal-top {
            display: flex;
            justify-content: space-between;
            gap: 10px;
            align-items: center;
            margin-bottom: 10px;
        }
        .signal-title {
            font-size: 16px;
            font-weight: 900;
        }
        .signal-value {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
            background: #dbeafe;
            color: #1d4ed8;
        }
        .signal-row input[type="range"] {
            width: 100%;
            accent-color: #1d4ed8;
        }
        .signal-foot {
            display: flex;
            justify-content: space-between;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 8px;
            color: #64748b;
            font-size: 12px;
            font-weight: 800;
        }
        .twin-output {
            border-radius: 24px;
            padding: 22px;
            background:
                radial-gradient(circle at top right, rgba(59,130,246,.12), transparent 28%),
                linear-gradient(180deg,#ffffff 0%, #f8fbff 100%);
            border: 1px solid #bfdbfe;
        }
        .output-top {
            display: flex;
            justify-content: space-between;
            gap: 12px;
            align-items: flex-start;
            flex-wrap: wrap;
            margin-bottom: 16px;
        }
        .output-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #1d4ed8;
            font-weight: 900;
            margin-bottom: 7px;
        }
        .output-title {
            font-size: 27px;
            font-weight: 900;
        }
        .output-badge {
            display: inline-block;
            border-radius: 999px;
            padding: 8px 12px;
            font-size: 12px;
            font-weight: 900;
            background: #dbeafe;
            color: #1d4ed8;
        }
        .score-ring {
            width: 132px;
            height: 132px;
            border-radius: 50%;
            background: conic-gradient(#16a34a 0deg, #16a34a 306deg, #e5e7eb 306deg, #e5e7eb 360deg);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 18px;
            position: relative;
        }
        .score-ring::before {
            content: "";
            position: absolute;
            inset: 15px;
            border-radius: 50%;
            background: #fff;
        }
        .score-value {
            position: relative;
            z-index: 1;
            font-size: 32px;
            font-weight: 900;
        }
        .verdict {
            border-radius: 18px;
            padding: 17px;
            background: #ecfdf5;
            border: 1px solid #a7f3d0;
            margin-bottom: 14px;
        }
        .verdict-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 900;
            margin-bottom: 6px;
        }
        .verdict-title {
            font-size: 24px;
            font-weight: 900;
            color: #166534;
            margin-bottom: 7px;
        }
        .verdict-note {
            color: #475569;
            line-height: 1.5;
        }
        .mini-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 10px;
            margin-bottom: 14px;
        }
        .mini-card {
            background: #fff;
            border: 1px solid #e2eaf7;
            border-radius: 14px;
            padding: 12px;
        }
        .mini-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 900;
            margin-bottom: 5px;
        }
        .mini-value {
            font-weight: 900;
        }
        .profile-grid {
            display: grid;
            gap: 10px;
        }
        .profile-row {
            display: grid;
            grid-template-columns: 190px 1fr 68px;
            gap: 10px;
            align-items: center;
        }
        .profile-label {
            font-size: 13px;
            font-weight: 800;
        }
        .bar {
            height: 12px;
            border-radius: 999px;
            background: #e5e7eb;
            overflow: hidden;
        }
        .bar span {
            display: block;
            height: 100%;
            border-radius: 999px;
            width: 0%;
            background: linear-gradient(90deg,#2563eb,#16a34a);
        }
        .profile-score {
            text-align: right;
            font-size: 13px;
            font-weight: 900;
        }
        .table-wrap {
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            border-radius: 16px;
            overflow: hidden;
            font-size: 13px;
        }
        th {
            background: #0f172a;
            color: #fff;
            text-align: left;
            padding: 11px;
        }
        td {
            border-bottom: 1px solid #e5e7eb;
            padding: 11px;
            vertical-align: top;
        }
        .pill {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
        }
        .pill.green { background:#dcfce7; color:#166534; }
        .pill.amber { background:#fef3c7; color:#92400e; }
        .pill.red { background:#fee2e2; color:#991b1b; }
        .pill.blue { background:#dbeafe; color:#1d4ed8; }
        .commercial-card {
            border-left: 6px solid #1d4ed8;
            background: #eff6ff;
            border-radius: 18px;
            padding: 17px;
        }
        .commercial-card h3 {
            margin: 0 0 8px;
            font-size: 18px;
        }
        .commercial-card p {
            margin: 0;
            font-size: 14px;
        }
        .callout {
            border-left: 7px solid #0891b2;
            border-radius: 18px;
            padding: 18px;
            background: linear-gradient(135deg,#ecfeff,#ffffff);
            color: #334155;
            line-height: 1.65;
            margin-bottom: 18px;
        }
        .action-row {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 16px;
        }
        .action-row a {
            display: inline-block;
            text-decoration: none;
            padding: 10px 14px;
            border-radius: 999px;
            font-size: 13px;
            font-weight: 900;
            background: #0f172a;
            color: #fff;
        }
        .action-row a.primary {
            background: #0891b2;
        }
        .footer-note {
            color: #5c6a80;
            font-size: 13px;
            line-height: 1.55;
            margin-top: 14px;
        }
        @media (max-width: 1360px) {
            .hero-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .grid-2,
            .sim-layout {
                grid-template-columns: 1fr;
            }
            .grid-4,
            .map-grid,
            .domain-grid,
            .operating-model {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
        }
        @media (max-width: 820px) {
            .hero-grid,
            .grid-3,
            .grid-4,
            .map-grid,
            .domain-grid,
            .operating-model,
            .mini-grid {
                grid-template-columns: 1fr;
            }
            .profile-row {
                grid-template-columns: 1fr;
            }
            h1 {
                font-size: 31px;
            }
        }
    </style>
</head>
<body>
    <div class="shell">
        <div class="topbar">
            <div class="brand">COBIT-Chain™ / AssuranceLayer™</div>
            <div class="nav-links">
                <a href="/command-center">Command Center</a>
                <a href="/enterprise-assurance-passport-factory">Passport Factory</a>
                <a href="/cobit-chain-maturity-scorecard">Maturity Scorecard</a>
                <a href="/governance-assurance-passport/BATCH-2026-041">Sample Passport</a>
                <a href="/recovery-governance-command-center">DR Governance</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Umbrella Flagship Concept</div>
            <h1>Regulated Operations Assurance Twin™</h1>
            <p>
                The Regulated Operations Assurance Twin™ is the live governance mirror of regulated work.
                It does not replace systems of record. It sits above them as an assurance intelligence layer:
                sensing operational evidence, verifying integrity, reconciling cross-system truth, exposing blockers,
                gating decisions, and issuing portable Governance Assurance Passports™ only when the chain is defensible.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Platform Role</div>
                    <div class="hero-value">Assurance Twin</div>
                    <div class="hero-note">Live governance mirror</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Governed Objects</div>
                    <div class="hero-value">7+</div>
                    <div class="hero-note">Batch, SOP, CI, CSP, DR, access, CAPA</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Decision Model</div>
                    <div class="hero-value">Truth</div>
                    <div class="hero-note">Reconciled, not assumed</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Output</div>
                    <div class="hero-value">Passport</div>
                    <div class="hero-note">Portable audit-ready proof</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Commercial Story</div>
                    <div class="hero-value">Scale</div>
                    <div class="hero-note">One engine, many domains</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>The One-Sentence Definition</h2>
                <div class="statement">
                    COBIT-Chain™ is a <b>Regulated Operations Assurance Twin™</b> that converts fragmented regulated records
                    into live governance truth and issues portable assurance passports only when the full control, evidence,
                    dependency, exception, recovery, and closure chain is defensible.
                </div>
            </div>

            <div class="panel">
                <h2>What This Is Not</h2>
                <div class="grid-2">
                    <div class="definition-card">
                        <div class="definition-kicker">Not only</div>
                        <div class="definition-title">A Dashboard</div>
                        <div class="definition-note">Dashboards show status. The twin evaluates whether the status can be trusted.</div>
                    </div>
                    <div class="definition-card">
                        <div class="definition-kicker">Not only</div>
                        <div class="definition-title">A Blockchain App</div>
                        <div class="definition-note">Hashing proves integrity. The twin also proves readiness, dependencies, and closure logic.</div>
                    </div>
                    <div class="definition-card">
                        <div class="definition-kicker">Not only</div>
                        <div class="definition-title">A Workflow Tool</div>
                        <div class="definition-note">Workflow moves work. The twin verifies whether work is defensible across evidence chains.</div>
                    </div>
                    <div class="definition-card">
                        <div class="definition-kicker">Not only</div>
                        <div class="definition-title">A Document Pack</div>
                        <div class="definition-note">Documents store proof. The twin determines whether the proof is complete and aligned.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel">
            <h2>Assurance Twin Operating Model</h2>
            <div class="operating-model">
                <div class="model-step"><strong>1</strong><h3>Sense</h3><p>Read signals from records, tickets, assets, evidence, reviews, and recovery events.</p></div>
                <div class="model-step"><strong>2</strong><h3>Verify</h3><p>Check integrity anchors, hash state, version state, and lineage trust.</p></div>
                <div class="model-step"><strong>3</strong><h3>Reconcile</h3><p>Compare system truth across operational, QA, IT, and governance records.</p></div>
                <div class="model-step"><strong>4</strong><h3>Validate</h3><p>Expose dependencies, missing approvals, hidden blockers, and readiness gaps.</p></div>
                <div class="model-step"><strong>5</strong><h3>Decide</h3><p>Classify the object as certified, conditional, blocked, or escalation-required.</p></div>
                <div class="model-step"><strong>6</strong><h3>Certify</h3><p>Generate a portable Governance Assurance Passport™ when the chain is defensible.</p></div>
                <div class="model-step"><strong>7</strong><h3>Learn</h3><p>Feed patterns into maturity scoring, risk intelligence, and future improvement.</p></div>
            </div>
        </section>

        <section class="panel">
            <h2>How Existing Modules Become One Twin</h2>
            <div class="map-grid">
                <div class="map-card highlight">
                    <div class="map-kicker">Umbrella</div>
                    <div class="map-title">Regulated Operations Assurance Twin™</div>
                    <div class="map-note">The executive concept that connects every governance engine into one assurance story.</div>
                    <a href="/regulated-operations-assurance-twin">Current Page</a>
                </div>
                <div class="map-card">
                    <div class="map-kicker">Diagnostic</div>
                    <div class="map-title">COBIT-Chain Maturity Scorecard™</div>
                    <div class="map-note">Measures whether an organization can reliably produce assurance at scale.</div>
                    <a href="/cobit-chain-maturity-scorecard">Open Scorecard</a>
                </div>
                <div class="map-card">
                    <div class="map-kicker">Engine</div>
                    <div class="map-title">Enterprise Assurance Passport Factory™</div>
                    <div class="map-note">Applies one assurance model across batches, SOPs, CIs, CSPs, DR events, access reviews, and CAPA.</div>
                    <a href="/enterprise-assurance-passport-factory">Open Factory</a>
                </div>
                <div class="map-card">
                    <div class="map-kicker">Output</div>
                    <div class="map-title">Governance Assurance Passport™</div>
                    <div class="map-note">Portable proof of control coverage, evidence, integrity, reconciliation, dependency, recovery, and closure.</div>
                    <a href="/governance-assurance-passport/BATCH-2026-041">Open Passport</a>
                </div>
                <div class="map-card">
                    <div class="map-kicker">Truth Layer</div>
                    <div class="map-title">Governance Reconciliation Layer</div>
                    <div class="map-note">Detects where systems disagree and blocks false assurance.</div>
                    <a href="/governance-reconciliation-layer">Open Reconciliation</a>
                </div>
                <div class="map-card">
                    <div class="map-kicker">Decision Layer</div>
                    <div class="map-title">Governance Decision Engine</div>
                    <div class="map-note">Converts evidence conditions into explainable governance decisions.</div>
                    <a href="/governance-decision-engine">Open Decision Engine</a>
                </div>
                <div class="map-card">
                    <div class="map-kicker">Resilience Layer</div>
                    <div class="map-title">Recovery Governance Command Center™</div>
                    <div class="map-note">Shows whether recovery is truly ready, not merely technically restored.</div>
                    <a href="/recovery-governance-command-center">Open Recovery Governance</a>
                </div>
                <div class="map-card">
                    <div class="map-kicker">Health Layer</div>
                    <div class="map-title">Platform Health</div>
                    <div class="map-note">Shows which platform capabilities are active, registered, and traceable.</div>
                    <a href="/platform-health">Open Platform Health</a>
                </div>
            </div>
        </section>

        <section class="panel">
            <h2>Regulated Object Coverage</h2>
            <p>Select a governed object to see how the same Assurance Twin logic changes by domain.</p>
            <div class="domain-grid">
                <div class="domain-card active" data-domain="batch"><div class="domain-kicker">Manufacturing</div><div class="domain-title">Batch</div><div class="domain-note">Release evidence, QA approval, deviations, closure.</div></div>
                <div class="domain-card" data-domain="sop"><div class="domain-kicker">Procedure</div><div class="domain-title">SOP</div><div class="domain-note">Version, training, practice drift, harmonization.</div></div>
                <div class="domain-card" data-domain="ci"><div class="domain-kicker">IT / Asset</div><div class="domain-title">CI / Asset</div><div class="domain-note">Owner, access, CMDB, duplicate risk, readiness.</div></div>
                <div class="domain-card" data-domain="sterile"><div class="domain-kicker">Pharmacy</div><div class="domain-title">CSP Record</div><div class="domain-note">Environmental, personnel, release, seal health.</div></div>
                <div class="domain-card" data-domain="dr"><div class="domain-kicker">Recovery</div><div class="domain-title">DR Event</div><div class="domain-note">RTO/RPO, restore proof, restart gate, certificate.</div></div>
                <div class="domain-card" data-domain="access"><div class="domain-kicker">IAM</div><div class="domain-title">Access Review</div><div class="domain-note">Entitlement, owner, training, periodic review.</div></div>
                <div class="domain-card" data-domain="capa"><div class="domain-kicker">Quality</div><div class="domain-title">CAPA / Finding</div><div class="domain-note">Root cause, action proof, effectiveness, closure.</div></div>
            </div>
        </section>

        <section class="panel">
            <h2>Interactive Assurance Twin Simulator</h2>
            <p>
                The twin does not ask only “is there a record?” It asks whether the full assurance chain is strong enough
                to certify, conditional enough to review, or weak enough to block.
            </p>

            <div class="sim-layout">
                <div class="signal-grid">
                    <div class="signal-row">
                        <div class="signal-top">
                            <div class="signal-title">Evidence Completeness</div>
                            <div id="valueEvidence" class="signal-value">90</div>
                        </div>
                        <input id="evidenceSlider" type="range" min="0" max="100" step="5" value="90">
                        <div class="signal-foot"><span>Missing</span><span>Complete</span></div>
                    </div>
                    <div class="signal-row">
                        <div class="signal-top">
                            <div class="signal-title">Integrity / Lineage Trust</div>
                            <div id="valueIntegrity" class="signal-value">90</div>
                        </div>
                        <input id="integritySlider" type="range" min="0" max="100" step="5" value="90">
                        <div class="signal-foot"><span>Unproven</span><span>Anchored</span></div>
                    </div>
                    <div class="signal-row">
                        <div class="signal-top">
                            <div class="signal-title">Cross-System Reconciliation</div>
                            <div id="valueReconciliation" class="signal-value">85</div>
                        </div>
                        <input id="reconciliationSlider" type="range" min="0" max="100" step="5" value="85">
                        <div class="signal-foot"><span>Contradicted</span><span>Aligned</span></div>
                    </div>
                    <div class="signal-row">
                        <div class="signal-top">
                            <div class="signal-title">Dependency / Blocker Clearance</div>
                            <div id="valueDependency" class="signal-value">80</div>
                        </div>
                        <input id="dependencySlider" type="range" min="0" max="100" step="5" value="80">
                        <div class="signal-foot"><span>Blocked</span><span>Cleared</span></div>
                    </div>
                    <div class="signal-row">
                        <div class="signal-top">
                            <div class="signal-title">Exception / CAPA Control</div>
                            <div id="valueException" class="signal-value">85</div>
                        </div>
                        <input id="exceptionSlider" type="range" min="0" max="100" step="5" value="85">
                        <div class="signal-foot"><span>Open risk</span><span>Controlled</span></div>
                    </div>
                    <div class="signal-row">
                        <div class="signal-top">
                            <div class="signal-title">Recovery / Continuity Readiness</div>
                            <div id="valueRecovery" class="signal-value">75</div>
                        </div>
                        <input id="recoverySlider" type="range" min="0" max="100" step="5" value="75">
                        <div class="signal-foot"><span>Unknown</span><span>Proven</span></div>
                    </div>
                    <div class="signal-row">
                        <div class="signal-top">
                            <div class="signal-title">Closure / Certification Gate</div>
                            <div id="valueClosure" class="signal-value">90</div>
                        </div>
                        <input id="closureSlider" type="range" min="0" max="100" step="5" value="90">
                        <div class="signal-foot"><span>Failed</span><span>Approved</span></div>
                    </div>
                </div>

                <div class="twin-output">
                    <div class="output-top">
                        <div>
                            <div class="output-kicker">Live Twin Verdict</div>
                            <div id="outputTitle" class="output-title">Batch Assurance Twin</div>
                        </div>
                        <div id="outputBadge" class="output-badge">CERTIFIABLE</div>
                    </div>

                    <div id="scoreRing" class="score-ring">
                        <div id="scoreValue" class="score-value">85</div>
                    </div>

                    <div id="verdictBox" class="verdict">
                        <div class="verdict-label">Twin Decision</div>
                        <div id="verdictTitle" class="verdict-title">Certified Assurance</div>
                        <div id="verdictNote" class="verdict-note">
                            The twin can support a Governance Assurance Passport™ because the assurance chain is defensible.
                        </div>
                    </div>

                    <div class="mini-grid">
                        <div class="mini-card"><div class="mini-label">Object</div><div id="objectLabel" class="mini-value">Manufacturing Batch</div></div>
                        <div class="mini-card"><div class="mini-label">Twin State</div><div id="twinState" class="mini-value">Aligned</div></div>
                        <div class="mini-card"><div class="mini-label">Passport</div><div id="passportState" class="mini-value">Issue</div></div>
                        <div class="mini-card"><div class="mini-label">Primary Blocker</div><div id="blockerState" class="mini-value">None</div></div>
                    </div>

                    <div class="profile-grid">
                        <div class="profile-row"><div class="profile-label">Evidence</div><div class="bar"><span id="barEvidence"></span></div><div id="scoreEvidence" class="profile-score">90</div></div>
                        <div class="profile-row"><div class="profile-label">Integrity</div><div class="bar"><span id="barIntegrity"></span></div><div id="scoreIntegrity" class="profile-score">90</div></div>
                        <div class="profile-row"><div class="profile-label">Reconciliation</div><div class="bar"><span id="barReconciliation"></span></div><div id="scoreReconciliation" class="profile-score">85</div></div>
                        <div class="profile-row"><div class="profile-label">Dependencies</div><div class="bar"><span id="barDependency"></span></div><div id="scoreDependency" class="profile-score">80</div></div>
                        <div class="profile-row"><div class="profile-label">Exceptions</div><div class="bar"><span id="barException"></span></div><div id="scoreException" class="profile-score">85</div></div>
                        <div class="profile-row"><div class="profile-label">Recovery</div><div class="bar"><span id="barRecovery"></span></div><div id="scoreRecovery" class="profile-score">75</div></div>
                        <div class="profile-row"><div class="profile-label">Closure</div><div class="bar"><span id="barClosure"></span></div><div id="scoreClosure" class="profile-score">90</div></div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel">
            <h2>Executive Differentiation</h2>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Traditional Approach</th>
                            <th>What It Misses</th>
                            <th>Assurance Twin Advantage</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Status dashboard</td>
                            <td>Shows what users entered but may not prove whether the status is defensible.</td>
                            <td><span class="pill green">Verifies</span> evidence, integrity, dependencies, and closure logic.</td>
                        </tr>
                        <tr>
                            <td>Document repository</td>
                            <td>Stores controlled documents but may not detect practice drift or cross-system contradiction.</td>
                            <td><span class="pill green">Reconciles</span> document truth against operational evidence.</td>
                        </tr>
                        <tr>
                            <td>Ticket / workflow system</td>
                            <td>Moves tasks but may not prove regulated readiness or downstream dependency clearance.</td>
                            <td><span class="pill green">Gates</span> decisions before release, restart, or closure.</td>
                        </tr>
                        <tr>
                            <td>Backup / DR record</td>
                            <td>May prove technical restore but not GMP restart readiness or final recovery certification.</td>
                            <td><span class="pill green">Separates</span> restore from regulated restart and certified closure.</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <section class="grid-3">
            <div class="commercial-card">
                <h3>Academic Strength</h3>
                <p>The concept is research-friendly because it operationalizes governance into observable dimensions, decision logic, and assurance outputs.</p>
            </div>
            <div class="commercial-card">
                <h3>Commercial Strength</h3>
                <p>The product can be sold as a maturity diagnostic, verification layer, or enterprise governance intelligence platform.</p>
            </div>
            <div class="commercial-card">
                <h3>Executive Strength</h3>
                <p>Leadership gets one clear message: the platform proves whether regulated work is truly ready, not merely recorded.</p>
            </div>
        </section>

        <section class="panel">
            <h2>Strategic Meaning</h2>
            <div class="callout">
                <b>Final positioning:</b>
                COBIT-Chain™ / AssuranceLayer™ is a governance intelligence platform for regulated operations.
                Its flagship product category is the <b>Regulated Operations Assurance Twin™</b>.
                Its commercial product stack is the <b>Maturity Scorecard → Passport Factory → Governance Assurance Passport</b>.
            </div>
            <div class="action-row">
                <a class="primary" href="/cobit-chain-maturity-scorecard">Open Maturity Scorecard</a>
                <a href="/enterprise-assurance-passport-factory">Open Passport Factory</a>
                <a href="/governance-assurance-passport/BATCH-2026-041">Open Sample Passport</a>
                <a href="/command-center">Return to Command Center</a>
            </div>
            <div class="footer-note">
                Boundary: this is an umbrella product-concept page. It does not replace validated systems, overwrite existing modules, or create production automation.
            </div>
        </section>
    </div>

    <script>
        const domainProfiles = {
            batch: { title: "Batch Assurance Twin", object: "Manufacturing Batch", state: "Aligned" },
            sop: { title: "SOP Assurance Twin", object: "SOP / Controlled Procedure", state: "Drift-sensitive" },
            ci: { title: "CI Assurance Twin", object: "CI / Regulated Asset", state: "Cross-system" },
            sterile: { title: "Sterile Compounding Assurance Twin", object: "Sterile Compounding Record", state: "Release-gated" },
            dr: { title: "Recovery Assurance Twin", object: "DR Event", state: "Recovery-gated" },
            access: { title: "Access Assurance Twin", object: "Access Review", state: "IAM-linked" },
            capa: { title: "CAPA Assurance Twin", object: "CAPA / Audit Finding", state: "Closure-gated" }
        };

        const sliders = {
            evidence: document.getElementById("evidenceSlider"),
            integrity: document.getElementById("integritySlider"),
            reconciliation: document.getElementById("reconciliationSlider"),
            dependency: document.getElementById("dependencySlider"),
            exception: document.getElementById("exceptionSlider"),
            recovery: document.getElementById("recoverySlider"),
            closure: document.getElementById("closureSlider")
        };

        const valueLabels = {
            evidence: document.getElementById("valueEvidence"),
            integrity: document.getElementById("valueIntegrity"),
            reconciliation: document.getElementById("valueReconciliation"),
            dependency: document.getElementById("valueDependency"),
            exception: document.getElementById("valueException"),
            recovery: document.getElementById("valueRecovery"),
            closure: document.getElementById("valueClosure")
        };

        const bars = {
            evidence: [document.getElementById("barEvidence"), document.getElementById("scoreEvidence")],
            integrity: [document.getElementById("barIntegrity"), document.getElementById("scoreIntegrity")],
            reconciliation: [document.getElementById("barReconciliation"), document.getElementById("scoreReconciliation")],
            dependency: [document.getElementById("barDependency"), document.getElementById("scoreDependency")],
            exception: [document.getElementById("barException"), document.getElementById("scoreException")],
            recovery: [document.getElementById("barRecovery"), document.getElementById("scoreRecovery")],
            closure: [document.getElementById("barClosure"), document.getElementById("scoreClosure")]
        };

        const weights = {
            evidence: 0.16,
            integrity: 0.14,
            reconciliation: 0.15,
            dependency: 0.14,
            exception: 0.12,
            recovery: 0.13,
            closure: 0.16
        };

        let activeDomain = "batch";

        const outputTitle = document.getElementById("outputTitle");
        const outputBadge = document.getElementById("outputBadge");
        const objectLabel = document.getElementById("objectLabel");
        const twinState = document.getElementById("twinState");
        const passportState = document.getElementById("passportState");
        const blockerState = document.getElementById("blockerState");
        const scoreRing = document.getElementById("scoreRing");
        const scoreValue = document.getElementById("scoreValue");
        const verdictBox = document.getElementById("verdictBox");
        const verdictTitle = document.getElementById("verdictTitle");
        const verdictNote = document.getElementById("verdictNote");

        function blockerFor(key) {
            const names = {
                evidence: "Evidence gap",
                integrity: "Integrity not proven",
                reconciliation: "System contradiction",
                dependency: "Dependency blocker",
                exception: "Open exception",
                recovery: "Recovery unknown",
                closure: "Closure gate failed"
            };
            return names[key] || "None";
        }

        function updateTwin() {
            const profile = domainProfiles[activeDomain];
            outputTitle.textContent = profile.title;
            objectLabel.textContent = profile.object;
            twinState.textContent = profile.state;

            let total = 0;
            let lowestKey = null;
            let lowestValue = 101;

            Object.keys(sliders).forEach(key => {
                const value = Number(sliders[key].value);
                total += value * weights[key];

                valueLabels[key].textContent = value;
                bars[key][0].style.width = value + "%";
                bars[key][1].textContent = value;

                if (value < lowestValue) {
                    lowestValue = value;
                    lowestKey = key;
                }
            });

            const score = Math.round(total);
            scoreValue.textContent = score;

            let color = "#16a34a";
            let bg = "#ecfdf5";
            let border = "#a7f3d0";
            let titleColor = "#166534";
            let badge = "CERTIFIABLE";
            let title = "Certified Assurance";
            let note = "The twin can support a Governance Assurance Passport™ because the assurance chain is defensible.";
            let passport = "Issue";
            let blocker = "None";

            if (score < 60 || lowestValue <= 35) {
                color = "#dc2626";
                bg = "#fef2f2";
                border = "#fecaca";
                titleColor = "#991b1b";
                badge = "BLOCKED";
                title = "Assurance Blocked";
                note = "The twin cannot support a defensible passport because a critical governance condition has failed.";
                passport = "Withhold";
                blocker = blockerFor(lowestKey);
            } else if (score < 85 || lowestValue < 70) {
                color = "#f59e0b";
                bg = "#fffbeb";
                border = "#fde68a";
                titleColor = "#92400e";
                badge = "CONDITIONAL";
                title = "Conditional Assurance";
                note = "The twin can support review, but full certification requires remediation of one or more assurance dimensions.";
                passport = "Conditional";
                blocker = blockerFor(lowestKey);
            }

            outputBadge.textContent = badge;
            passportState.textContent = passport;
            blockerState.textContent = blocker;
            verdictTitle.textContent = title;
            verdictNote.textContent = note;

            verdictBox.style.background = bg;
            verdictBox.style.borderColor = border;
            verdictTitle.style.color = titleColor;

            const degrees = Math.round(score * 3.6);
            scoreRing.style.background = `conic-gradient(${color} 0deg, ${color} ${degrees}deg, #e5e7eb ${degrees}deg, #e5e7eb 360deg)`;
        }

        Object.values(sliders).forEach(slider => {
            slider.addEventListener("input", updateTwin);
        });

        document.querySelectorAll(".domain-card").forEach(card => {
            card.addEventListener("click", () => {
                document.querySelectorAll(".domain-card").forEach(item => item.classList.remove("active"));
                card.classList.add("active");
                activeDomain = card.dataset.domain;
                updateTwin();
            });
        });

        updateTwin();
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
        print("SKIP: Regulated Operations Assurance Twin route already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/regulated-operations-assurance-twin")',
        "Regulated Operations Assurance Twin™",
        "Assurance Twin Operating Model",
        "How Existing Modules Become One Twin",
        "Interactive Assurance Twin Simulator",
        "Executive Differentiation",
        "Final positioning:",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /regulated-operations-assurance-twin route inserted safely.")
    print("VERIFIED: required umbrella concept markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
