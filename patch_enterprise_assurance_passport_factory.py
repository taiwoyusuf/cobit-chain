from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# ENTERPRISE_ASSURANCE_PASSPORT_FACTORY_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# ============================================================
# ENTERPRISE_ASSURANCE_PASSPORT_FACTORY_ACTIVE
# Regulated Operations Assurance Twin™
# Cross-domain product layer that generates portable assurance
# logic across regulated objects without modifying protected modules.
# ============================================================

@app.route("/enterprise-assurance-passport-factory")
def enterprise_assurance_passport_factory_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Enterprise Assurance Passport Factory™ | COBIT-Chain™ / AssuranceLayer™</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #f4f7fb;
            color: #172033;
        }
        .shell {
            max-width: 1540px;
            margin: 0 auto;
            padding: 28px 22px 44px;
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
                radial-gradient(circle at top left, rgba(34,197,94,.18), transparent 30%),
                radial-gradient(circle at bottom right, rgba(59,130,246,.22), transparent 32%),
                linear-gradient(135deg, #071527 0%, #0f2745 40%, #1d4ed8 100%);
            color: #fff;
            border-radius: 28px;
            padding: 30px;
            box-shadow: 0 18px 46px rgba(15, 23, 42, .24);
            margin-bottom: 20px;
        }
        .eyebrow {
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: .08em;
            opacity: .82;
            font-weight: 800;
            margin-bottom: 10px;
        }
        h1 {
            margin: 0 0 10px;
            font-size: 38px;
            line-height: 1.12;
        }
        .hero p {
            max-width: 1200px;
            margin: 0;
            line-height: 1.58;
            font-size: 16px;
            opacity: .96;
        }
        .hero-metrics {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
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
            font-size: 22px;
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
            grid-template-columns: 1.06fr .94fr;
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
            margin-bottom: 18px;
        }
        .panel h2 {
            margin: 0 0 15px;
            font-size: 21px;
        }
        .panel p {
            line-height: 1.56;
            color: #44536b;
            margin: 0 0 14px;
        }
        .concept-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .concept-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .concept-card.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .concept-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .concept-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .concept-card.indigo {
            background: #eef2ff;
            border-color: #c7d2fe;
        }
        .concept-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .concept-title {
            font-size: 18px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .concept-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
        }
        .statement {
            border-left: 7px solid #1d4ed8;
            border-radius: 18px;
            padding: 18px;
            background: linear-gradient(135deg,#eff6ff,#ffffff);
            line-height: 1.6;
            font-size: 16px;
            font-weight: 800;
        }
        .workflow {
            display: grid;
            grid-template-columns: repeat(8, minmax(0, 1fr));
            gap: 12px;
        }
        .step {
            border: 1px solid #e2eaf7;
            background: #f8fbff;
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
        .object-grid {
            display: grid;
            grid-template-columns: repeat(7, minmax(0, 1fr));
            gap: 12px;
        }
        .object-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
            cursor: pointer;
            transition: transform .15s ease, border-color .15s ease, background .15s ease;
        }
        .object-card:hover {
            transform: translateY(-2px);
            border-color: #93c5fd;
            background: #eff6ff;
        }
        .object-card.active {
            background: #eff6ff;
            border-color: #60a5fa;
            box-shadow: 0 10px 24px rgba(37,99,235,.12);
        }
        .object-kicker {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 900;
            margin-bottom: 7px;
        }
        .object-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .object-note {
            font-size: 13px;
            line-height: 1.45;
            color: #516078;
        }
        .factory-layout {
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
            font-weight: 900;
            margin-bottom: 8px;
        }
        select {
            width: 100%;
            border: 1px solid #d7e1f0;
            border-radius: 14px;
            padding: 12px 13px;
            font-size: 14px;
            background: #fff;
            color: #172033;
            outline: none;
        }
        .passport-preview {
            border-radius: 24px;
            padding: 22px;
            background:
                radial-gradient(circle at top right, rgba(59,130,246,.12), transparent 28%),
                linear-gradient(180deg,#ffffff 0%, #f8fbff 100%);
            border: 1px solid #bfdbfe;
            display: flex;
            flex-direction: column;
        }
        .preview-top {
            display: flex;
            justify-content: space-between;
            gap: 12px;
            align-items: flex-start;
            flex-wrap: wrap;
            margin-bottom: 16px;
        }
        .preview-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #1d4ed8;
            font-weight: 900;
            margin-bottom: 7px;
        }
        .preview-title {
            font-size: 25px;
            font-weight: 900;
        }
        .preview-badge {
            display: inline-block;
            border-radius: 999px;
            padding: 8px 12px;
            font-size: 12px;
            font-weight: 900;
            background: #dbeafe;
            color: #1d4ed8;
        }
        .score-ring {
            width: 122px;
            height: 122px;
            border-radius: 50%;
            background: conic-gradient(#16a34a 0deg, #16a34a 295deg, #e5e7eb 295deg, #e5e7eb 360deg);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 18px;
            position: relative;
        }
        .score-ring::before {
            content: "";
            position: absolute;
            inset: 14px;
            border-radius: 50%;
            background: #fff;
        }
        .score-value {
            position: relative;
            z-index: 1;
            font-size: 31px;
            font-weight: 900;
        }
        .verdict {
            border-radius: 18px;
            padding: 16px;
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
        .dimension-grid {
            display: grid;
            gap: 10px;
        }
        .dimension-row {
            display: grid;
            grid-template-columns: 190px 1fr 70px;
            gap: 10px;
            align-items: center;
        }
        .dimension-label {
            font-size: 13px;
            font-weight: 800;
        }
        .bar {
            height: 12px;
            border-radius: 999px;
            background: #e5e7eb;
            overflow: hidden;
        }
        .bar > span {
            display: block;
            height: 100%;
            border-radius: 999px;
            background: linear-gradient(90deg,#2563eb,#16a34a);
            width: 0%;
        }
        .dimension-score {
            text-align: right;
            font-size: 13px;
            font-weight: 900;
        }
        .schema-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 12px;
        }
        .schema-card {
            border-radius: 18px;
            padding: 16px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .schema-title {
            font-size: 15px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .schema-note {
            font-size: 14px;
            color: #516078;
            line-height: 1.45;
        }
        .compare-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .compare-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .compare-card.highlight {
            background: #ecfdf5;
            border-color: #86efac;
        }
        .compare-title {
            font-size: 17px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .compare-note {
            font-size: 14px;
            color: #516078;
            line-height: 1.45;
        }
        .scenario-layout {
            display: grid;
            grid-template-columns: 1fr .92fr;
            gap: 18px;
        }
        .scenario-list {
            display: grid;
            gap: 12px;
        }
        .scenario-btn {
            width: 100%;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
            border-radius: 18px;
            padding: 16px;
            text-align: left;
            cursor: pointer;
        }
        .scenario-btn:hover {
            background: #eff6ff;
        }
        .scenario-btn.active {
            background: #eff6ff;
            border-color: #93c5fd;
        }
        .scenario-kicker {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 900;
            margin-bottom: 6px;
        }
        .scenario-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 5px;
        }
        .scenario-note {
            font-size: 14px;
            color: #53637b;
            line-height: 1.45;
        }
        .scenario-card {
            border-radius: 22px;
            padding: 22px;
            background: #eff6ff;
            border: 1px solid #bfdbfe;
        }
        .scenario-card-title {
            font-size: 26px;
            font-weight: 900;
            color: #1d4ed8;
            margin-bottom: 10px;
        }
        .scenario-meta {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 10px;
            margin-bottom: 14px;
        }
        .scenario-mini {
            background: rgba(255,255,255,.78);
            border-radius: 14px;
            padding: 12px;
        }
        .scenario-mini-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 900;
            margin-bottom: 5px;
        }
        .scenario-mini-value {
            font-weight: 900;
        }
        .scenario-verdict {
            background: rgba(255,255,255,.8);
            border-radius: 18px;
            padding: 16px;
            font-weight: 800;
            line-height: 1.5;
            margin-bottom: 12px;
        }
        .scenario-body {
            color: #4d5b73;
            line-height: 1.56;
        }
        .market-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 12px;
        }
        .market-card {
            border-left: 6px solid #1d4ed8;
            background: #eff6ff;
            border-radius: 18px;
            padding: 17px;
        }
        .market-card h3 {
            margin: 0 0 8px;
            font-size: 17px;
        }
        .market-card p {
            margin: 0;
            font-size: 14px;
        }
        .footer-note {
            color: #5c6a80;
            font-size: 13px;
            line-height: 1.55;
            margin-top: 14px;
        }
        @media (max-width: 1360px) {
            .hero-metrics {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .grid-2,
            .factory-layout,
            .scenario-layout {
                grid-template-columns: 1fr;
            }
            .workflow {
                grid-template-columns: repeat(4, minmax(0, 1fr));
            }
            .object-grid {
                grid-template-columns: repeat(4, minmax(0, 1fr));
            }
            .schema-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .concept-grid,
            .compare-grid,
            .market-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 820px) {
            .hero-metrics,
            .workflow,
            .object-grid,
            .schema-grid,
            .concept-grid,
            .compare-grid,
            .mini-grid,
            .scenario-meta,
            .market-grid {
                grid-template-columns: 1fr;
            }
            .dimension-row {
                grid-template-columns: 1fr;
            }
            h1 {
                font-size: 29px;
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
                <a href="/modules">Modules Directory</a>
                <a href="/governance-passport">Governance Passport</a>
                <a href="/governance-digital-twin">Governance Digital Twin</a>
                <a href="/recovery-governance-command-center">Recovery Governance</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Regulated Operations Assurance Twin™</div>
            <h1>Enterprise Assurance Passport Factory™</h1>
            <p>
                The cross-domain product layer that converts fragmented regulated records into one portable,
                evidence-backed assurance output. A batch, SOP, CI, sterile compounding record, DR event, access review,
                or CAPA item may look different operationally — but each can be tested through the same governance truth
                engine before it earns a defensible passport.
            </p>

            <div class="hero-metrics">
                <div class="hero-card">
                    <div class="hero-label">Governed Object Classes</div>
                    <div class="hero-value">7</div>
                    <div class="hero-note">Batch to DR event</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Assurance Dimensions</div>
                    <div class="hero-value">8</div>
                    <div class="hero-note">Control to closure</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Factory Output</div>
                    <div class="hero-value">Passport</div>
                    <div class="hero-note">Portable audit artifact</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Product Distinction</div>
                    <div class="hero-value">Truth</div>
                    <div class="hero-note">Not just dashboard status</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Platform Role</div>
                    <div class="hero-value">Unifier</div>
                    <div class="hero-note">One logic, many domains</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>The Stronger Product Idea</h2>
                <div class="statement">
                    COBIT-Chain™ is evolving into a <b>Regulated Operations Assurance Twin™</b>:
                    a governance intelligence layer that converts fragmented records into live, cross-system truth
                    and issues portable assurance passports only when the full control, evidence, dependency,
                    exception, and recovery chain is defensible.
                </div>
            </div>

            <div class="panel">
                <h2>Product Hierarchy</h2>
                <div class="concept-grid">
                    <div class="concept-card blue">
                        <div class="concept-kicker">Framework</div>
                        <div class="concept-title">COBIT-Chain™</div>
                        <div class="concept-note">Governance logic and assurance method.</div>
                    </div>
                    <div class="concept-card green">
                        <div class="concept-kicker">Platform</div>
                        <div class="concept-title">AssuranceLayer™</div>
                        <div class="concept-note">Software that operationalizes the logic.</div>
                    </div>
                    <div class="concept-card indigo">
                        <div class="concept-kicker">Category</div>
                        <div class="concept-title">Assurance Twin™</div>
                        <div class="concept-note">Live model of governed readiness.</div>
                    </div>
                    <div class="concept-card amber">
                        <div class="concept-kicker">Portable Output</div>
                        <div class="concept-title">Passport™</div>
                        <div class="concept-note">Audit-ready proof generated by the twin.</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel">
            <h2>Factory Logic: One Engine, Many Regulated Objects</h2>
            <div class="workflow">
                <div class="step">
                    <div class="step-number">1</div>
                    <h3>Identify</h3>
                    <p>Recognize the governed object.</p>
                </div>
                <div class="step">
                    <div class="step-number">2</div>
                    <h3>Map Controls</h3>
                    <p>Determine what must apply.</p>
                </div>
                <div class="step">
                    <div class="step-number">3</div>
                    <h3>Collect Evidence</h3>
                    <p>Check what proof exists.</p>
                </div>
                <div class="step">
                    <div class="step-number">4</div>
                    <h3>Anchor Integrity</h3>
                    <p>Verify hash / ledger trust.</p>
                </div>
                <div class="step">
                    <div class="step-number">5</div>
                    <h3>Reconcile</h3>
                    <p>Compare truth across systems.</p>
                </div>
                <div class="step">
                    <div class="step-number">6</div>
                    <h3>Validate</h3>
                    <p>Expose blockers and dependencies.</p>
                </div>
                <div class="step">
                    <div class="step-number">7</div>
                    <h3>Gate</h3>
                    <p>Resolve exception / recovery state.</p>
                </div>
                <div class="step">
                    <div class="step-number">8</div>
                    <h3>Issue</h3>
                    <p>Generate passport or block closure.</p>
                </div>
            </div>
        </section>

        <section class="panel">
            <h2>Governed Object Library</h2>
            <p>
                Select any object below. The Factory changes the business story, but the assurance engine remains the same.
            </p>
            <div class="object-grid">
                <div class="object-card active" data-object="batch">
                    <div class="object-kicker">Manufacturing</div>
                    <div class="object-title">Batch</div>
                    <div class="object-note">Release evidence, deviation links, approvals, lineage.</div>
                </div>
                <div class="object-card" data-object="sop">
                    <div class="object-kicker">Procedure</div>
                    <div class="object-title">SOP</div>
                    <div class="object-note">Version control, comparison gaps, training, drift.</div>
                </div>
                <div class="object-card" data-object="ci">
                    <div class="object-kicker">Asset / CMDB</div>
                    <div class="object-title">CI / Asset</div>
                    <div class="object-note">Owner, access, evidence, readiness, duplicate risk.</div>
                </div>
                <div class="object-card" data-object="sterile">
                    <div class="object-kicker">Sterile Pharmacy</div>
                    <div class="object-title">CSP Record</div>
                    <div class="object-note">Release readiness, environment, personnel, seal.</div>
                </div>
                <div class="object-card" data-object="dr">
                    <div class="object-kicker">Resilience</div>
                    <div class="object-title">DR Event</div>
                    <div class="object-note">RTO/RPO, restore proof, restart, certificate.</div>
                </div>
                <div class="object-card" data-object="access">
                    <div class="object-kicker">IAM</div>
                    <div class="object-title">Access Review</div>
                    <div class="object-note">Entitlement, approval, training, periodic review.</div>
                </div>
                <div class="object-card" data-object="capa">
                    <div class="object-kicker">Quality</div>
                    <div class="object-title">CAPA / Finding</div>
                    <div class="object-note">Root cause, action proof, effectiveness, closure.</div>
                </div>
            </div>
        </section>

        <section class="panel">
            <h2>Interactive Enterprise Assurance Passport Factory</h2>
            <p>
                Adjust the assurance conditions. The Factory will decide whether the selected object deserves a certified passport,
                only a conditional passport, or no passport at all.
            </p>

            <div class="factory-layout">
                <div class="builder-grid">
                    <div class="builder-row">
                        <label>Governed Object</label>
                        <select id="objectSelect">
                            <option value="batch">Manufacturing Batch</option>
                            <option value="sop">SOP / Controlled Procedure</option>
                            <option value="ci">CI / Regulated Asset</option>
                            <option value="sterile">Sterile Compounding Record</option>
                            <option value="dr">DR Event</option>
                            <option value="access">Access Review</option>
                            <option value="capa">CAPA / Audit Finding</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label>Control Coverage</label>
                        <select id="controlSelect">
                            <option value="100">Complete control mapping</option>
                            <option value="75">Mostly mapped; minor gaps</option>
                            <option value="40">Partial mapping; major gaps</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label>Evidence Completeness</label>
                        <select id="evidenceSelect">
                            <option value="100">All required evidence present</option>
                            <option value="70">Reviewable; one or two gaps</option>
                            <option value="35">Material evidence missing</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label>Integrity Anchoring</label>
                        <select id="integritySelect">
                            <option value="100">Hash / ledger verified</option>
                            <option value="75">Hash present; ledger pending</option>
                            <option value="30">Integrity not proven</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label>Cross-System Reconciliation</label>
                        <select id="reconciliationSelect">
                            <option value="100">Truth aligned across systems</option>
                            <option value="70">Minor mismatch under review</option>
                            <option value="25">Material contradiction exists</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label>Dependency Validation</label>
                        <select id="dependencySelect">
                            <option value="100">All dependencies cleared</option>
                            <option value="70">One non-critical dependency open</option>
                            <option value="20">Critical dependency blocking readiness</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label>Exception / CAPA Linkage</label>
                        <select id="exceptionSelect">
                            <option value="100">No open exceptions or fully linked</option>
                            <option value="75">Open item documented and owned</option>
                            <option value="25">Open exception with no governed path</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label>DR / Continuity Readiness</label>
                        <select id="drSelect">
                            <option value="100">Recovery readiness proven</option>
                            <option value="70">Recovery plan exists; proof incomplete</option>
                            <option value="30">Recovery readiness unknown</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label>Closure / Certification State</label>
                        <select id="closureSelect">
                            <option value="100">Closure approved</option>
                            <option value="70">Ready for final review</option>
                            <option value="20">Closure gate failed</option>
                        </select>
                    </div>
                </div>

                <div class="passport-preview">
                    <div class="preview-top">
                        <div>
                            <div class="preview-kicker">Generated Output</div>
                            <div id="previewTitle" class="preview-title">Governance Assurance Passport™ — Manufacturing Batch</div>
                        </div>
                        <div id="previewBadge" class="preview-badge">Portable Output</div>
                    </div>

                    <div id="scoreRing" class="score-ring">
                        <div id="scoreValue" class="score-value">100</div>
                    </div>

                    <div id="verdictBox" class="verdict">
                        <div class="verdict-label">Factory Verdict</div>
                        <div id="verdictTitle" class="verdict-title">Certified Passport</div>
                        <div id="verdictNote" class="verdict-note">
                            The full assurance chain is defensible. This governed object is eligible for a portable, audit-ready passport.
                        </div>
                    </div>

                    <div class="mini-grid">
                        <div class="mini-card">
                            <div class="mini-label">Object ID</div>
                            <div id="objectId" class="mini-value">BATCH-2026-041</div>
                        </div>
                        <div class="mini-card">
                            <div class="mini-label">Twin State</div>
                            <div id="twinState" class="mini-value">Aligned</div>
                        </div>
                        <div class="mini-card">
                            <div class="mini-label">Passport State</div>
                            <div id="passportState" class="mini-value">Issued</div>
                        </div>
                        <div class="mini-card">
                            <div class="mini-label">Primary Blocker</div>
                            <div id="primaryBlocker" class="mini-value">None</div>
                        </div>
                    </div>

                    <div class="dimension-grid">
                        <div class="dimension-row">
                            <div class="dimension-label">Control Coverage</div>
                            <div class="bar"><span id="barControl"></span></div>
                            <div id="scoreControl" class="dimension-score">100</div>
                        </div>
                        <div class="dimension-row">
                            <div class="dimension-label">Evidence Completeness</div>
                            <div class="bar"><span id="barEvidence"></span></div>
                            <div id="scoreEvidence" class="dimension-score">100</div>
                        </div>
                        <div class="dimension-row">
                            <div class="dimension-label">Integrity Anchoring</div>
                            <div class="bar"><span id="barIntegrity"></span></div>
                            <div id="scoreIntegrity" class="dimension-score">100</div>
                        </div>
                        <div class="dimension-row">
                            <div class="dimension-label">Reconciliation</div>
                            <div class="bar"><span id="barReconciliation"></span></div>
                            <div id="scoreReconciliation" class="dimension-score">100</div>
                        </div>
                        <div class="dimension-row">
                            <div class="dimension-label">Dependencies</div>
                            <div class="bar"><span id="barDependency"></span></div>
                            <div id="scoreDependency" class="dimension-score">100</div>
                        </div>
                        <div class="dimension-row">
                            <div class="dimension-label">Exceptions / CAPA</div>
                            <div class="bar"><span id="barException"></span></div>
                            <div id="scoreException" class="dimension-score">100</div>
                        </div>
                        <div class="dimension-row">
                            <div class="dimension-label">DR Readiness</div>
                            <div class="bar"><span id="barDr"></span></div>
                            <div id="scoreDr" class="dimension-score">100</div>
                        </div>
                        <div class="dimension-row">
                            <div class="dimension-label">Closure State</div>
                            <div class="bar"><span id="barClosure"></span></div>
                            <div id="scoreClosure" class="dimension-score">100</div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel">
            <h2>Portable Governance Assurance Passport™ Schema</h2>
            <p>
                The Passport is not just a PDF summary. It is a portable assurance record generated from the live twin.
            </p>
            <div class="schema-grid">
                <div class="schema-card">
                    <div class="schema-title">Object Identity</div>
                    <div class="schema-note">What is being governed, who owns it, where it belongs.</div>
                </div>
                <div class="schema-card">
                    <div class="schema-title">Control Coverage</div>
                    <div class="schema-note">Which governance controls apply and whether they are satisfied.</div>
                </div>
                <div class="schema-card">
                    <div class="schema-title">Evidence Pack</div>
                    <div class="schema-note">Required artifacts, completeness, source references, approval trail.</div>
                </div>
                <div class="schema-card">
                    <div class="schema-title">Integrity Anchors</div>
                    <div class="schema-note">Hash, ledger, version, and lineage proof.</div>
                </div>
                <div class="schema-card">
                    <div class="schema-title">Reconciliation Verdict</div>
                    <div class="schema-note">Whether connected systems agree on the truth.</div>
                </div>
                <div class="schema-card">
                    <div class="schema-title">Dependency State</div>
                    <div class="schema-note">What is blocking readiness and what must clear first.</div>
                </div>
                <div class="schema-card">
                    <div class="schema-title">Exception / CAPA Links</div>
                    <div class="schema-note">Open issues, owners, linked actions, and risk disposition.</div>
                </div>
                <div class="schema-card">
                    <div class="schema-title">DR Snapshot</div>
                    <div class="schema-note">RTO/RPO tier, recovery proof, restart readiness, continuity posture.</div>
                </div>
                <div class="schema-card">
                    <div class="schema-title">Closure Verdict</div>
                    <div class="schema-note">Certified, conditional, or blocked — with reason.</div>
                </div>
                <div class="schema-card">
                    <div class="schema-title">Assurance Score</div>
                    <div class="schema-note">One explainable score backed by the eight dimensions.</div>
                </div>
            </div>
        </section>

        <section class="panel">
            <h2>Why This Is Stronger Than a Dashboard</h2>
            <div class="compare-grid">
                <div class="compare-card">
                    <div class="compare-title">Dashboard</div>
                    <div class="compare-note">Shows status, often after data has already been accepted.</div>
                </div>
                <div class="compare-card">
                    <div class="compare-title">Checklist</div>
                    <div class="compare-note">Confirms fields were filled, but may not reconcile truth.</div>
                </div>
                <div class="compare-card">
                    <div class="compare-title">Static Passport</div>
                    <div class="compare-note">Summarizes evidence, but may not prove that the system still agrees.</div>
                </div>
                <div class="compare-card highlight">
                    <div class="compare-title">Assurance Twin + Passport</div>
                    <div class="compare-note">Computes readiness, exposes blockers, and issues proof only when the chain is defensible.</div>
                </div>
            </div>
        </section>

        <section class="panel">
            <h2>Cross-Domain Scenario Inspector</h2>
            <p>
                These examples show why the Factory is commercially stronger than a one-off workflow module.
            </p>

            <div class="scenario-layout">
                <div class="scenario-list">
                    <button class="scenario-btn active" data-scenario="batch">
                        <div class="scenario-kicker">Scenario 01</div>
                        <div class="scenario-title">Batch ready for release</div>
                        <div class="scenario-note">All controls, evidence, and approvals align.</div>
                    </button>
                    <button class="scenario-btn" data-scenario="sop">
                        <div class="scenario-kicker">Scenario 02</div>
                        <div class="scenario-title">SOP looks approved, but practice drift exists</div>
                        <div class="scenario-note">Document control is green; operational truth is not.</div>
                    </button>
                    <button class="scenario-btn" data-scenario="ci">
                        <div class="scenario-kicker">Scenario 03</div>
                        <div class="scenario-title">CI exists, but access governance is incomplete</div>
                        <div class="scenario-note">Asset readiness is blocked by access linkage.</div>
                    </button>
                    <button class="scenario-btn" data-scenario="dr">
                        <div class="scenario-kicker">Scenario 04</div>
                        <div class="scenario-title">System restored, but GMP restart is blocked</div>
                        <div class="scenario-note">Technical recovery is not enterprise readiness.</div>
                    </button>
                </div>

                <div class="scenario-card">
                    <div id="scenarioTitle" class="scenario-card-title">Batch ready for release</div>
                    <div class="scenario-meta">
                        <div class="scenario-mini">
                            <div class="scenario-mini-label">Object</div>
                            <div id="scenarioObject" class="scenario-mini-value">Manufacturing Batch</div>
                        </div>
                        <div class="scenario-mini">
                            <div class="scenario-mini-label">Twin Verdict</div>
                            <div id="scenarioTwin" class="scenario-mini-value">Aligned</div>
                        </div>
                        <div class="scenario-mini">
                            <div class="scenario-mini-label">Passport</div>
                            <div id="scenarioPassport" class="scenario-mini-value">Issue</div>
                        </div>
                        <div class="scenario-mini">
                            <div class="scenario-mini-label">Key Lesson</div>
                            <div id="scenarioLesson" class="scenario-mini-value">Proof</div>
                        </div>
                    </div>
                    <div id="scenarioVerdict" class="scenario-verdict">
                        Evidence, controls, approvals, and closure state agree. The batch earns a certified passport.
                    </div>
                    <div id="scenarioBody" class="scenario-body">
                        This is the simplest case: the Factory proves that a portable passport can be issued because the live assurance twin is already green across the full chain.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="market-card">
                <h3>Academic Strength</h3>
                <p>Operationalizes governance into a repeatable, explainable assurance artefact rather than a conceptual dashboard.</p>
            </div>
            <div class="market-card">
                <h3>Commercial Strength</h3>
                <p>Creates a sellable product output that can support diagnostics, pilots, audit readiness, and enterprise subscriptions.</p>
            </div>
            <div class="market-card">
                <h3>Global Strength</h3>
                <p>Works beyond one company or one workflow: pharma, devices, labs, logistics, compounding, and resilience.</p>
            </div>
        </section>

        <section class="panel">
            <h2>Strategic Meaning</h2>
            <p>
                Earlier modules proved individual capabilities: evidence integrity, reconciliation, decision logic,
                closure control, sterile compounding, and recovery governance.
            </p>
            <p>
                <b>Enterprise Assurance Passport Factory™</b> proves the larger product thesis:
                the same governance engine can convert many different regulated objects into a portable, audit-ready
                assurance record — but only after the live twin proves that control, evidence, integrity, dependencies,
                exceptions, recovery, and closure all agree.
            </p>
            <div class="footer-note">
                Recommended next build after this page:
                <b>Governance Assurance Passport™ detail page</b> — the portable output generated per selected object.
            </div>
        </section>
    </div>

    <script>
        const objectProfiles = {
            batch: {
                title: "Governance Assurance Passport™ — Manufacturing Batch",
                id: "BATCH-2026-041",
                twin: "Aligned",
                label: "Manufacturing Batch"
            },
            sop: {
                title: "Governance Assurance Passport™ — SOP / Controlled Procedure",
                id: "SOP-VAL-014",
                twin: "Drift-sensitive",
                label: "SOP / Controlled Procedure"
            },
            ci: {
                title: "Governance Assurance Passport™ — CI / Regulated Asset",
                id: "CI-EQP-221",
                twin: "Cross-system",
                label: "CI / Regulated Asset"
            },
            sterile: {
                title: "Governance Assurance Passport™ — Sterile Compounding Record",
                id: "CSP-2026-009",
                twin: "Release-gated",
                label: "Sterile Compounding Record"
            },
            dr: {
                title: "Governance Assurance Passport™ — DR Event",
                id: "DR-2026-017",
                twin: "Recovery-gated",
                label: "DR Event"
            },
            access: {
                title: "Governance Assurance Passport™ — Access Review",
                id: "AR-NIAGARA-Q2",
                twin: "IAM-linked",
                label: "Access Review"
            },
            capa: {
                title: "Governance Assurance Passport™ — CAPA / Audit Finding",
                id: "CAPA-2026-032",
                twin: "Closure-gated",
                label: "CAPA / Audit Finding"
            }
        };

        const objectSelect = document.getElementById("objectSelect");
        const selectors = {
            control: document.getElementById("controlSelect"),
            evidence: document.getElementById("evidenceSelect"),
            integrity: document.getElementById("integritySelect"),
            reconciliation: document.getElementById("reconciliationSelect"),
            dependency: document.getElementById("dependencySelect"),
            exception: document.getElementById("exceptionSelect"),
            dr: document.getElementById("drSelect"),
            closure: document.getElementById("closureSelect")
        };

        const previewTitle = document.getElementById("previewTitle");
        const objectId = document.getElementById("objectId");
        const twinState = document.getElementById("twinState");
        const passportState = document.getElementById("passportState");
        const primaryBlocker = document.getElementById("primaryBlocker");
        const scoreRing = document.getElementById("scoreRing");
        const scoreValue = document.getElementById("scoreValue");
        const verdictBox = document.getElementById("verdictBox");
        const verdictTitle = document.getElementById("verdictTitle");
        const verdictNote = document.getElementById("verdictNote");
        const previewBadge = document.getElementById("previewBadge");

        const dimensionMap = {
            control: ["barControl", "scoreControl"],
            evidence: ["barEvidence", "scoreEvidence"],
            integrity: ["barIntegrity", "scoreIntegrity"],
            reconciliation: ["barReconciliation", "scoreReconciliation"],
            dependency: ["barDependency", "scoreDependency"],
            exception: ["barException", "scoreException"],
            dr: ["barDr", "scoreDr"],
            closure: ["barClosure", "scoreClosure"]
        };

        const weights = {
            control: 0.12,
            evidence: 0.16,
            integrity: 0.12,
            reconciliation: 0.14,
            dependency: 0.14,
            exception: 0.10,
            dr: 0.10,
            closure: 0.12
        };

        function blockerLabel(key) {
            const labels = {
                control: "Control gap",
                evidence: "Evidence gap",
                integrity: "Integrity not proven",
                reconciliation: "System contradiction",
                dependency: "Dependency blocker",
                exception: "Open exception",
                dr: "Recovery unknown",
                closure: "Closure gate failed"
            };
            return labels[key] || "None";
        }

        function updateFactory() {
            const profile = objectProfiles[objectSelect.value];
            previewTitle.textContent = profile.title;
            objectId.textContent = profile.id;
            twinState.textContent = profile.twin;

            let total = 0;
            let lowestKey = null;
            let lowestValue = 101;

            Object.keys(selectors).forEach(key => {
                const value = Number(selectors[key].value);
                total += value * weights[key];

                if (value < lowestValue) {
                    lowestValue = value;
                    lowestKey = key;
                }

                const [barId, scoreId] = dimensionMap[key];
                document.getElementById(barId).style.width = value + "%";
                document.getElementById(scoreId).textContent = value;
            });

            const score = Math.round(total);
            scoreValue.textContent = score;

            const degrees = Math.round(score * 3.6);
            let ringColor = "#16a34a";
            let bgColor = "#ecfdf5";
            let borderColor = "#a7f3d0";
            let titleColor = "#166534";
            let state = "Issued";
            let badge = "Portable Output";
            let title = "Certified Passport";
            let note = "The full assurance chain is defensible. This governed object is eligible for a portable, audit-ready passport.";
            let blocker = "None";

            if (score < 60 || lowestValue <= 30) {
                ringColor = "#dc2626";
                bgColor = "#fef2f2";
                borderColor = "#fecaca";
                titleColor = "#991b1b";
                state = "Blocked";
                badge = "Passport Withheld";
                title = "Passport Blocked";
                note = "A critical governance condition failed. The object cannot receive a defensible passport until the blocker is resolved.";
                blocker = blockerLabel(lowestKey);
            } else if (score < 85 || lowestValue < 70) {
                ringColor = "#f59e0b";
                bgColor = "#fffbeb";
                borderColor = "#fde68a";
                titleColor = "#92400e";
                state = "Conditional";
                badge = "Conditional Output";
                title = "Conditional Passport";
                note = "The object is reviewable, but one or more assurance dimensions remain incomplete before full certification.";
                blocker = blockerLabel(lowestKey);
            }

            passportState.textContent = state;
            primaryBlocker.textContent = blocker;
            previewBadge.textContent = badge;
            verdictTitle.textContent = title;
            verdictNote.textContent = note;
            verdictBox.style.background = bgColor;
            verdictBox.style.borderColor = borderColor;
            verdictTitle.style.color = titleColor;
            scoreRing.style.background = `conic-gradient(${ringColor} 0deg, ${ringColor} ${degrees}deg, #e5e7eb ${degrees}deg, #e5e7eb 360deg)`;
        }

        objectSelect.addEventListener("change", updateFactory);
        Object.values(selectors).forEach(select => {
            select.addEventListener("change", updateFactory);
        });

        const objectCards = document.querySelectorAll(".object-card");
        objectCards.forEach(card => {
            card.addEventListener("click", () => {
                objectCards.forEach(item => item.classList.remove("active"));
                card.classList.add("active");
                objectSelect.value = card.dataset.object;
                updateFactory();
            });
        });

        updateFactory();

        const scenarios = {
            batch: {
                title: "Batch ready for release",
                object: "Manufacturing Batch",
                twin: "Aligned",
                passport: "Issue",
                lesson: "Proof",
                verdict: "Evidence, controls, approvals, and closure state agree. The batch earns a certified passport.",
                body: "This is the simplest case: the Factory proves that a portable passport can be issued because the live assurance twin is already green across the full chain."
            },
            sop: {
                title: "SOP looks approved, but practice drift exists",
                object: "SOP / Controlled Procedure",
                twin: "Contradicted",
                passport: "Block",
                lesson: "Reconciliation",
                verdict: "Document control is green, but workflow behavior and operational evidence no longer match the approved SOP.",
                body: "This is where the Factory becomes stronger than a document repository: it refuses a clean passport because cross-system truth has drifted."
            },
            ci: {
                title: "CI exists, but access governance is incomplete",
                object: "CI / Regulated Asset",
                twin: "Conditional",
                passport: "Conditional",
                lesson: "Dependencies",
                verdict: "The asset exists and is useful, but the CI cannot be fully assured until MyAccess / role / owner dependencies are cleared.",
                body: "The same passport logic exposes why an asset may be operationally present yet not governance-ready."
            },
            dr: {
                title: "System restored, but GMP restart is blocked",
                object: "DR Event",
                twin: "Recovery-gated",
                passport: "Block",
                lesson: "Restore ≠ Ready",
                verdict: "Technical restoration is complete, but dependency, evidence, and restart gates are still open.",
                body: "This proves the Factory can represent regulated resilience: recovery truth is broader than whether a server is back online."
            }
        };

        const scenarioButtons = document.querySelectorAll(".scenario-btn");
        const scenarioTitle = document.getElementById("scenarioTitle");
        const scenarioObject = document.getElementById("scenarioObject");
        const scenarioTwin = document.getElementById("scenarioTwin");
        const scenarioPassport = document.getElementById("scenarioPassport");
        const scenarioLesson = document.getElementById("scenarioLesson");
        const scenarioVerdict = document.getElementById("scenarioVerdict");
        const scenarioBody = document.getElementById("scenarioBody");

        scenarioButtons.forEach(button => {
            button.addEventListener("click", () => {
                scenarioButtons.forEach(item => item.classList.remove("active"));
                button.classList.add("active");

                const item = scenarios[button.dataset.scenario];
                scenarioTitle.textContent = item.title;
                scenarioObject.textContent = item.object;
                scenarioTwin.textContent = item.twin;
                scenarioPassport.textContent = item.passport;
                scenarioLesson.textContent = item.lesson;
                scenarioVerdict.textContent = item.verdict;
                scenarioBody.textContent = item.body;
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
        print("SKIP: Enterprise Assurance Passport Factory already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/enterprise-assurance-passport-factory")',
        "Enterprise Assurance Passport Factory™",
        "Regulated Operations Assurance Twin™",
        "Interactive Enterprise Assurance Passport Factory",
        "Governed Object Library",
        "Portable Governance Assurance Passport™ Schema",
        "Cross-Domain Scenario Inspector",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /enterprise-assurance-passport-factory route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
