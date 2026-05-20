from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# COBIT_CHAIN_MATURITY_SCORECARD_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# ============================================================
# COBIT_CHAIN_MATURITY_SCORECARD_ACTIVE
# Commercial + academic diagnostic layer for COBIT-Chain™.
# Additive route only; does not modify protected modules.
# ============================================================

@app.route("/cobit-chain-maturity-scorecard")
def cobit_chain_maturity_scorecard_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>COBIT-Chain Maturity Scorecard™ | AssuranceLayer™</title>
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
                radial-gradient(circle at top left, rgba(34,197,94,.18), transparent 28%),
                radial-gradient(circle at bottom right, rgba(59,130,246,.22), transparent 30%),
                linear-gradient(135deg, #071527 0%, #0f2745 42%, #1d4ed8 100%);
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
            max-width: 1220px;
            margin: 0;
            line-height: 1.58;
            font-size: 16px;
            opacity: .96;
        }
        .hero-grid {
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
        .grid-2 {
            display: grid;
            grid-template-columns: 1.05fr .95fr;
            gap: 18px;
            margin-bottom: 18px;
        }
        .grid-3 {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 16px;
            margin-bottom: 18px;
        }
        .statement {
            border-left: 7px solid #1d4ed8;
            border-radius: 18px;
            padding: 18px;
            background: linear-gradient(135deg,#eff6ff,#ffffff);
            line-height: 1.62;
            font-size: 16px;
            font-weight: 800;
        }
        .level-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 12px;
        }
        .level-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .level-card.level-0 { background:#fef2f2; border-color:#fecaca; }
        .level-card.level-1 { background:#fff7ed; border-color:#fed7aa; }
        .level-card.level-2 { background:#fffbeb; border-color:#fde68a; }
        .level-card.level-3 { background:#eff6ff; border-color:#bfdbfe; }
        .level-card.level-4 { background:#ecfdf5; border-color:#a7f3d0; }
        .level-number {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 900;
            margin-bottom: 7px;
        }
        .level-title {
            font-size: 18px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .level-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
        }
        .dimension-schema {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 12px;
        }
        .schema-card {
            border: 1px solid #e2eaf7;
            background: #f8fbff;
            border-radius: 18px;
            padding: 17px;
        }
        .schema-kicker {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 900;
            margin-bottom: 7px;
        }
        .schema-title {
            font-size: 17px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .schema-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
        }
        .preset-row {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 16px;
        }
        .preset-btn {
            border: 0;
            cursor: pointer;
            border-radius: 999px;
            padding: 10px 14px;
            font-size: 13px;
            font-weight: 900;
            background: #e8f0ff;
            color: #173f86;
        }
        .preset-btn.active {
            background: #173f86;
            color: #fff;
        }
        .score-layout {
            display: grid;
            grid-template-columns: 1.02fr .98fr;
            gap: 18px;
        }
        .slider-grid {
            display: grid;
            gap: 12px;
        }
        .slider-row {
            border: 1px solid #e2eaf7;
            background: #f8fbff;
            border-radius: 18px;
            padding: 16px;
        }
        .slider-top {
            display: flex;
            justify-content: space-between;
            gap: 10px;
            align-items: center;
            margin-bottom: 10px;
        }
        .slider-title {
            font-size: 16px;
            font-weight: 900;
        }
        .slider-value {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
            background: #dbeafe;
            color: #1d4ed8;
        }
        .slider-row input[type="range"] {
            width: 100%;
            accent-color: #1d4ed8;
        }
        .slider-foot {
            display: flex;
            justify-content: space-between;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 8px;
            color: #64748b;
            font-size: 12px;
            font-weight: 800;
        }
        .result-card {
            border-radius: 24px;
            padding: 22px;
            background:
                radial-gradient(circle at top right, rgba(59,130,246,.12), transparent 28%),
                linear-gradient(180deg,#ffffff 0%, #f8fbff 100%);
            border: 1px solid #bfdbfe;
        }
        .result-top {
            display: flex;
            justify-content: space-between;
            gap: 12px;
            align-items: flex-start;
            flex-wrap: wrap;
            margin-bottom: 16px;
        }
        .result-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #1d4ed8;
            font-weight: 900;
            margin-bottom: 7px;
        }
        .result-title {
            font-size: 27px;
            font-weight: 900;
        }
        .tier-badge {
            display: inline-block;
            border-radius: 999px;
            padding: 8px 12px;
            font-size: 12px;
            font-weight: 900;
            background: #dbeafe;
            color: #1d4ed8;
        }
        .score-ring {
            width: 138px;
            height: 138px;
            border-radius: 50%;
            background: conic-gradient(#f59e0b 0deg, #f59e0b 180deg, #e5e7eb 180deg, #e5e7eb 360deg);
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
            font-size: 34px;
            font-weight: 900;
        }
        .verdict {
            border-radius: 18px;
            padding: 16px;
            background: #fffbeb;
            border: 1px solid #fde68a;
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
            color: #92400e;
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
            grid-template-columns: 210px 1fr 70px;
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
        .gap-layout {
            display: grid;
            grid-template-columns: 1fr .95fr;
            gap: 18px;
        }
        .gap-list {
            display: grid;
            gap: 12px;
        }
        .gap-card {
            border-radius: 18px;
            padding: 16px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .gap-card.high {
            background: #fef2f2;
            border-color: #fecaca;
        }
        .gap-card.medium {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .gap-card.low {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .gap-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 7px;
        }
        .gap-note {
            color: #516078;
            font-size: 14px;
            line-height: 1.45;
        }
        .action-card {
            border-left: 7px solid #1d4ed8;
            background: linear-gradient(135deg,#eff6ff,#ffffff);
            border-radius: 18px;
            padding: 18px;
        }
        .action-card h3 {
            margin: 0 0 10px;
            font-size: 18px;
        }
        .action-card ul {
            margin: 0;
            padding-left: 20px;
            color: #475569;
            line-height: 1.64;
        }
        .matrix-wrap {
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
        .matrix-focus {
            background: #eff6ff;
            font-weight: 800;
        }
        .commercial-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 14px;
        }
        .commercial-card {
            border-radius: 20px;
            padding: 18px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .commercial-card.recommended {
            background: #ecfdf5;
            border-color: #86efac;
            box-shadow: 0 10px 24px rgba(22,163,74,.10);
        }
        .commercial-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 900;
            margin-bottom: 7px;
        }
        .commercial-title {
            font-size: 20px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .commercial-note {
            color: #516078;
            line-height: 1.48;
            font-size: 14px;
            margin-bottom: 12px;
        }
        .commercial-fit {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
            background: #dbeafe;
            color: #1d4ed8;
        }
        .passport-path {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 12px;
        }
        .path-card {
            border-radius: 18px;
            padding: 17px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .path-card.active {
            background: #eff6ff;
            border-color: #93c5fd;
        }
        .path-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .path-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
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
            .hero-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .grid-2,
            .score-layout,
            .gap-layout {
                grid-template-columns: 1fr;
            }
            .level-grid,
            .passport-path {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .dimension-schema,
            .commercial-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 820px) {
            .hero-grid,
            .level-grid,
            .dimension-schema,
            .mini-grid,
            .commercial-grid,
            .passport-path,
            .grid-3 {
                grid-template-columns: 1fr;
            }
            .profile-row {
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
                <a href="/enterprise-assurance-passport-factory">Passport Factory</a>
                <a href="/governance-assurance-passport/BATCH-2026-041">Sample Passport</a>
                <a href="/command-center">Command Center</a>
                <a href="/modules">Modules Directory</a>
                <a href="/executive-overview">Executive Overview</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Diagnostic + Commercial Layer</div>
            <h1>COBIT-Chain Maturity Scorecard™</h1>
            <p>
                A six-dimension maturity model that measures whether an organization can merely store evidence,
                control evidence, reconcile evidence, or generate truly defensible assurance passports from live
                regulated-operation twins. A dashboard tells leaders what is happening; a maturity scorecard tells them
                what the organization is actually capable of proving.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Dimensions</div>
                    <div class="hero-value">6</div>
                    <div class="hero-note">Evidence to recovery</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Maturity Levels</div>
                    <div class="hero-value">0–4</div>
                    <div class="hero-note">Ad hoc to intelligent</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Academic Use</div>
                    <div class="hero-value">Evaluate</div>
                    <div class="hero-note">Framework maturity</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Commercial Use</div>
                    <div class="hero-value">Diagnose</div>
                    <div class="hero-note">Entry-point offer</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Passport Link</div>
                    <div class="hero-value">Trust</div>
                    <div class="hero-note">Higher maturity, stronger proof</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Why This Matters</h2>
                <div class="statement">
                    The maturity scorecard measures a regulated organization’s ability to move from
                    <b>documented compliance</b> to <b>assurance intelligence</b> — where control coverage,
                    evidence integrity, reconciliation, dependencies, exceptions, and recovery readiness are
                    strong enough to support portable, audit-ready assurance passports.
                </div>
            </div>

            <div class="panel">
                <h2>How It Fits the Product</h2>
                <p>
                    <b>Passport Factory™</b> generates the output. <b>Governance Assurance Passport™</b> shows the proof.
                    <b>COBIT-Chain Maturity Scorecard™</b> tells a buyer, auditor, or dissertation reviewer whether the
                    organization has the capability to produce that proof reliably at scale.
                </p>
                <p>
                    That makes this page useful as an academic evaluation instrument, a consulting diagnostic, and a
                    commercial sales entry point.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>The Five Maturity Levels</h2>
            <div class="level-grid">
                <div class="level-card level-0">
                    <div class="level-number">Level 0</div>
                    <div class="level-title">Ad hoc</div>
                    <div class="level-note">Evidence is scattered, owner-dependent, and difficult to defend.</div>
                </div>
                <div class="level-card level-1">
                    <div class="level-number">Level 1</div>
                    <div class="level-title">Documented</div>
                    <div class="level-note">Records exist, but they remain mostly static and manually assembled.</div>
                </div>
                <div class="level-card level-2">
                    <div class="level-number">Level 2</div>
                    <div class="level-title">Controlled</div>
                    <div class="level-note">Evidence packs, review rules, and closure checks are standardized.</div>
                </div>
                <div class="level-card level-3">
                    <div class="level-number">Level 3</div>
                    <div class="level-title">Integrated</div>
                    <div class="level-note">Systems reconcile, dependencies are visible, and decisions are explainable.</div>
                </div>
                <div class="level-card level-4">
                    <div class="level-number">Level 4</div>
                    <div class="level-title">Assurance-Intelligent</div>
                    <div class="level-note">The organization issues live, portable assurance based on governed truth.</div>
                </div>
            </div>
        </section>

        <section class="panel">
            <h2>Six-Dimension Scorecard Schema</h2>
            <div class="dimension-schema">
                <div class="schema-card">
                    <div class="schema-kicker">Dimension 01</div>
                    <div class="schema-title">Evidence Pack Standardization</div>
                    <div class="schema-note">Are required records complete, repeatable, and packaged consistently?</div>
                </div>
                <div class="schema-card">
                    <div class="schema-kicker">Dimension 02</div>
                    <div class="schema-title">Integrity Anchoring Coverage</div>
                    <div class="schema-note">Can the organization prove records have not been silently altered?</div>
                </div>
                <div class="schema-card">
                    <div class="schema-kicker">Dimension 03</div>
                    <div class="schema-title">Cross-System Reconciliation</div>
                    <div class="schema-note">Do connected systems agree on the same governance truth?</div>
                </div>
                <div class="schema-card">
                    <div class="schema-kicker">Dimension 04</div>
                    <div class="schema-title">Dependency Validation</div>
                    <div class="schema-note">Are readiness blockers and upstream/downstream gates explicit?</div>
                </div>
                <div class="schema-card">
                    <div class="schema-kicker">Dimension 05</div>
                    <div class="schema-title">Exception / CAPA Linkage</div>
                    <div class="schema-note">Are gaps linked to ownership, action, and closure logic?</div>
                </div>
                <div class="schema-card">
                    <div class="schema-kicker">Dimension 06</div>
                    <div class="schema-title">DR Governance Readiness</div>
                    <div class="schema-note">Can recovery prove RTO/RPO, restore, restart, and closure truth?</div>
                </div>
            </div>
        </section>

        <section class="panel">
            <h2>Interactive Maturity Assessment</h2>
            <p>
                Use a preset profile or score the organization manually. The scorecard will calculate maturity,
                identify capability gaps, recommend the right commercial offer, and show what level of assurance passport
                the organization can credibly support today.
            </p>

            <div class="preset-row">
                <button class="preset-btn" data-preset="adhoc">Ad hoc organization</button>
                <button class="preset-btn" data-preset="documented">Documented but manual</button>
                <button class="preset-btn active" data-preset="controlled">Controlled but siloed</button>
                <button class="preset-btn" data-preset="integrated">Integrated enterprise</button>
                <button class="preset-btn" data-preset="intelligent">Assurance-intelligent target</button>
            </div>

            <div class="score-layout">
                <div class="slider-grid">
                    <div class="slider-row">
                        <div class="slider-top">
                            <div class="slider-title">Evidence Pack Standardization</div>
                            <div id="valueEvidence" class="slider-value">2 — Controlled</div>
                        </div>
                        <input id="evidenceSlider" type="range" min="0" max="4" step="1" value="2">
                        <div class="slider-foot">
                            <span>0 Ad hoc</span>
                            <span>4 Assurance-Intelligent</span>
                        </div>
                    </div>

                    <div class="slider-row">
                        <div class="slider-top">
                            <div class="slider-title">Integrity Anchoring Coverage</div>
                            <div id="valueIntegrity" class="slider-value">2 — Controlled</div>
                        </div>
                        <input id="integritySlider" type="range" min="0" max="4" step="1" value="2">
                        <div class="slider-foot">
                            <span>0 Ad hoc</span>
                            <span>4 Assurance-Intelligent</span>
                        </div>
                    </div>

                    <div class="slider-row">
                        <div class="slider-top">
                            <div class="slider-title">Cross-System Reconciliation</div>
                            <div id="valueReconciliation" class="slider-value">1 — Documented</div>
                        </div>
                        <input id="reconciliationSlider" type="range" min="0" max="4" step="1" value="1">
                        <div class="slider-foot">
                            <span>0 Ad hoc</span>
                            <span>4 Assurance-Intelligent</span>
                        </div>
                    </div>

                    <div class="slider-row">
                        <div class="slider-top">
                            <div class="slider-title">Dependency Validation</div>
                            <div id="valueDependency" class="slider-value">1 — Documented</div>
                        </div>
                        <input id="dependencySlider" type="range" min="0" max="4" step="1" value="1">
                        <div class="slider-foot">
                            <span>0 Ad hoc</span>
                            <span>4 Assurance-Intelligent</span>
                        </div>
                    </div>

                    <div class="slider-row">
                        <div class="slider-top">
                            <div class="slider-title">Exception / CAPA Linkage</div>
                            <div id="valueException" class="slider-value">2 — Controlled</div>
                        </div>
                        <input id="exceptionSlider" type="range" min="0" max="4" step="1" value="2">
                        <div class="slider-foot">
                            <span>0 Ad hoc</span>
                            <span>4 Assurance-Intelligent</span>
                        </div>
                    </div>

                    <div class="slider-row">
                        <div class="slider-top">
                            <div class="slider-title">DR Governance Readiness</div>
                            <div id="valueDr" class="slider-value">1 — Documented</div>
                        </div>
                        <input id="drSlider" type="range" min="0" max="4" step="1" value="1">
                        <div class="slider-foot">
                            <span>0 Ad hoc</span>
                            <span>4 Assurance-Intelligent</span>
                        </div>
                    </div>
                </div>

                <div class="result-card">
                    <div class="result-top">
                        <div>
                            <div class="result-kicker">Calculated Maturity</div>
                            <div id="resultTitle" class="result-title">Level 2 — Controlled</div>
                        </div>
                        <div id="tierBadge" class="tier-badge">Recommended Offer: Tier 2</div>
                    </div>

                    <div id="scoreRing" class="score-ring">
                        <div id="scoreValue" class="score-value">1.5</div>
                    </div>

                    <div id="verdictBox" class="verdict">
                        <div class="verdict-label">Capability Verdict</div>
                        <div id="verdictTitle" class="verdict-title">Controlled but not yet integrated</div>
                        <div id="verdictNote" class="verdict-note">
                            The organization can standardize evidence and review it, but it cannot yet issue high-confidence passports across systems.
                        </div>
                    </div>

                    <div class="mini-grid">
                        <div class="mini-card">
                            <div class="mini-label">Average Score</div>
                            <div id="averageScore" class="mini-value">1.5 / 4</div>
                        </div>
                        <div class="mini-card">
                            <div class="mini-label">Weakest Dimension</div>
                            <div id="weakestDimension" class="mini-value">Reconciliation</div>
                        </div>
                        <div class="mini-card">
                            <div class="mini-label">Passport Confidence</div>
                            <div id="passportConfidence" class="mini-value">Conditional</div>
                        </div>
                        <div class="mini-card">
                            <div class="mini-label">Commercial Tier</div>
                            <div id="commercialTier" class="mini-value">Tier 2</div>
                        </div>
                    </div>

                    <div class="profile-grid">
                        <div class="profile-row">
                            <div class="profile-label">Evidence Packs</div>
                            <div class="bar"><span id="barEvidence"></span></div>
                            <div id="scoreEvidence" class="profile-score">2</div>
                        </div>
                        <div class="profile-row">
                            <div class="profile-label">Integrity Anchoring</div>
                            <div class="bar"><span id="barIntegrity"></span></div>
                            <div id="scoreIntegrity" class="profile-score">2</div>
                        </div>
                        <div class="profile-row">
                            <div class="profile-label">Reconciliation</div>
                            <div class="bar"><span id="barReconciliation"></span></div>
                            <div id="scoreReconciliation" class="profile-score">1</div>
                        </div>
                        <div class="profile-row">
                            <div class="profile-label">Dependencies</div>
                            <div class="bar"><span id="barDependency"></span></div>
                            <div id="scoreDependency" class="profile-score">1</div>
                        </div>
                        <div class="profile-row">
                            <div class="profile-label">Exceptions / CAPA</div>
                            <div class="bar"><span id="barException"></span></div>
                            <div id="scoreException" class="profile-score">2</div>
                        </div>
                        <div class="profile-row">
                            <div class="profile-label">DR Governance</div>
                            <div class="bar"><span id="barDr"></span></div>
                            <div id="scoreDr" class="profile-score">1</div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel">
            <h2>Capability Gap Analysis</h2>
            <div class="gap-layout">
                <div id="gapList" class="gap-list">
                    <div class="gap-card medium">
                        <div class="gap-title">Cross-System Reconciliation</div>
                        <div class="gap-note">Current maturity is documented only. Systems do not yet produce a unified governance truth.</div>
                    </div>
                    <div class="gap-card medium">
                        <div class="gap-title">Dependency Validation</div>
                        <div class="gap-note">Readiness blockers are still manually interpreted instead of systematically gated.</div>
                    </div>
                    <div class="gap-card medium">
                        <div class="gap-title">DR Governance Readiness</div>
                        <div class="gap-note">Recovery evidence exists, but restore proof, restart gates, and final closure are not fully integrated.</div>
                    </div>
                </div>

                <div class="action-card">
                    <h3>Recommended Next Actions</h3>
                    <ul id="actionList">
                        <li>Move from static evidence packs to cross-system reconciliation.</li>
                        <li>Introduce dependency gates before readiness or release decisions.</li>
                        <li>Formalize DR evidence, restart approval, and recovery certification.</li>
                    </ul>
                </div>
            </div>
        </section>

        <section class="panel">
            <h2>Maturity Capability Matrix</h2>
            <div class="matrix-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Dimension</th>
                            <th>0 — Ad hoc</th>
                            <th>1 — Documented</th>
                            <th>2 — Controlled</th>
                            <th>3 — Integrated</th>
                            <th>4 — Assurance-Intelligent</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><b>Evidence Packs</b></td>
                            <td>Scattered files</td>
                            <td>Templates exist</td>
                            <td class="matrix-focus">Standard packs</td>
                            <td>Linked across workflows</td>
                            <td>Auto-generated passports</td>
                        </tr>
                        <tr>
                            <td><b>Integrity Anchoring</b></td>
                            <td>No proof</td>
                            <td>Manual review</td>
                            <td class="matrix-focus">Hash / version checks</td>
                            <td>Ledger-linked</td>
                            <td>Continuous trust state</td>
                        </tr>
                        <tr>
                            <td><b>Reconciliation</b></td>
                            <td>Unknown</td>
                            <td class="matrix-focus">Manual comparison</td>
                            <td>Defined matching rules</td>
                            <td>Cross-system verdicts</td>
                            <td>Predictive drift detection</td>
                        </tr>
                        <tr>
                            <td><b>Dependencies</b></td>
                            <td>Implicit</td>
                            <td class="matrix-focus">Known by experts</td>
                            <td>Documented gates</td>
                            <td>Automated validation</td>
                            <td>Decision-aware blast radius</td>
                        </tr>
                        <tr>
                            <td><b>Exceptions / CAPA</b></td>
                            <td>Disconnected</td>
                            <td>Logged</td>
                            <td class="matrix-focus">Owned and reviewed</td>
                            <td>Linked to closure logic</td>
                            <td>Exception intelligence</td>
                        </tr>
                        <tr>
                            <td><b>DR Governance</b></td>
                            <td>Reactive</td>
                            <td class="matrix-focus">Plan documented</td>
                            <td>Restore proof tracked</td>
                            <td>Restart gates linked</td>
                            <td>Recovery twin certified</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <section class="panel">
            <h2>Commercial Tier Mapping</h2>
            <p>
                The scorecard creates a realistic product ladder from advisory work to enterprise software intelligence.
            </p>
            <div class="commercial-grid">
                <div id="tier1Card" class="commercial-card">
                    <div class="commercial-kicker">Tier 1</div>
                    <div class="commercial-title">Assurance Pack</div>
                    <div class="commercial-note">
                        Advisory templates, evidence packs, RACI, cadence, passport template, and baseline scorecard.
                    </div>
                    <div class="commercial-fit">Best for Levels 0–1</div>
                </div>
                <div id="tier2Card" class="commercial-card recommended">
                    <div class="commercial-kicker">Tier 2</div>
                    <div class="commercial-title">Verification Layer</div>
                    <div class="commercial-note">
                        Hash / ledger anchoring, verification, exception workflow, scorecards, and passport generation pilot.
                    </div>
                    <div class="commercial-fit">Best for Level 2</div>
                </div>
                <div id="tier3Card" class="commercial-card">
                    <div class="commercial-kicker">Tier 3</div>
                    <div class="commercial-title">Enterprise Governance Intelligence</div>
                    <div class="commercial-note">
                        Reconciliation, dependency validation, decision engine, recovery twin, and cross-domain assurance.
                    </div>
                    <div class="commercial-fit">Best for Levels 3–4</div>
                </div>
            </div>
        </section>

        <section class="panel">
            <h2>Passport Confidence Path</h2>
            <p>
                The stronger the organization’s maturity, the stronger the passport it can credibly issue.
            </p>
            <div class="passport-path">
                <div id="path0" class="path-card">
                    <div class="path-title">Level 0</div>
                    <div class="path-note">No passport — evidence cannot be defended.</div>
                </div>
                <div id="path1" class="path-card">
                    <div class="path-title">Level 1</div>
                    <div class="path-note">Static report — descriptive, not yet assurance-grade.</div>
                </div>
                <div id="path2" class="path-card active">
                    <div class="path-title">Level 2</div>
                    <div class="path-note">Conditional passport — controlled, but still siloed.</div>
                </div>
                <div id="path3" class="path-card">
                    <div class="path-title">Level 3</div>
                    <div class="path-note">Enterprise passport — cross-system and explainable.</div>
                </div>
                <div id="path4" class="path-card">
                    <div class="path-title">Level 4</div>
                    <div class="path-note">Assurance-intelligent passport — live, predictive, portable.</div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="market-card">
                <h3>Academic Value</h3>
                <p>Gives the dissertation an evaluation-ready maturity instrument rather than only a conceptual framework.</p>
            </div>
            <div class="market-card">
                <h3>Commercial Value</h3>
                <p>Creates a buyer-friendly diagnostic that naturally leads into advisory, pilot, and enterprise offerings.</p>
            </div>
            <div class="market-card">
                <h3>Strategic Value</h3>
                <p>Shows that COBIT-Chain™ is not just software; it is a governance operating model with measurable maturity.</p>
            </div>
        </section>

        <section class="panel">
            <h2>Strategic Meaning</h2>
            <p>
                <b>Enterprise Assurance Passport Factory™</b> proves what COBIT-Chain™ can produce.
                <b>Governance Assurance Passport™</b> proves what the output looks like.
                <b>COBIT-Chain Maturity Scorecard™</b> proves how an organization moves from fragmented compliance
                toward a state where those passports can be issued reliably, explainably, and at enterprise scale.
            </p>
            <div class="footer-note">
                This is the diagnostic layer that makes COBIT-Chain™ academically evaluable and commercially sellable.
            </div>
        </section>
    </div>

    <script>
        const labels = ["Ad hoc", "Documented", "Controlled", "Integrated", "Assurance-Intelligent"];

        const sliders = {
            evidence: document.getElementById("evidenceSlider"),
            integrity: document.getElementById("integritySlider"),
            reconciliation: document.getElementById("reconciliationSlider"),
            dependency: document.getElementById("dependencySlider"),
            exception: document.getElementById("exceptionSlider"),
            dr: document.getElementById("drSlider")
        };

        const valueLabels = {
            evidence: document.getElementById("valueEvidence"),
            integrity: document.getElementById("valueIntegrity"),
            reconciliation: document.getElementById("valueReconciliation"),
            dependency: document.getElementById("valueDependency"),
            exception: document.getElementById("valueException"),
            dr: document.getElementById("valueDr")
        };

        const bars = {
            evidence: [document.getElementById("barEvidence"), document.getElementById("scoreEvidence")],
            integrity: [document.getElementById("barIntegrity"), document.getElementById("scoreIntegrity")],
            reconciliation: [document.getElementById("barReconciliation"), document.getElementById("scoreReconciliation")],
            dependency: [document.getElementById("barDependency"), document.getElementById("scoreDependency")],
            exception: [document.getElementById("barException"), document.getElementById("scoreException")],
            dr: [document.getElementById("barDr"), document.getElementById("scoreDr")]
        };

        const dimensionNames = {
            evidence: "Evidence Pack Standardization",
            integrity: "Integrity Anchoring Coverage",
            reconciliation: "Cross-System Reconciliation",
            dependency: "Dependency Validation",
            exception: "Exception / CAPA Linkage",
            dr: "DR Governance Readiness"
        };

        const dimensionShortNames = {
            evidence: "Evidence Packs",
            integrity: "Integrity Anchoring",
            reconciliation: "Reconciliation",
            dependency: "Dependencies",
            exception: "Exceptions / CAPA",
            dr: "DR Governance"
        };

        const presets = {
            adhoc: {
                evidence: 0, integrity: 0, reconciliation: 0, dependency: 0, exception: 0, dr: 0
            },
            documented: {
                evidence: 1, integrity: 1, reconciliation: 1, dependency: 1, exception: 1, dr: 1
            },
            controlled: {
                evidence: 2, integrity: 2, reconciliation: 1, dependency: 1, exception: 2, dr: 1
            },
            integrated: {
                evidence: 3, integrity: 3, reconciliation: 3, dependency: 3, exception: 3, dr: 3
            },
            intelligent: {
                evidence: 4, integrity: 4, reconciliation: 4, dependency: 4, exception: 4, dr: 4
            }
        };

        const resultTitle = document.getElementById("resultTitle");
        const tierBadge = document.getElementById("tierBadge");
        const scoreRing = document.getElementById("scoreRing");
        const scoreValue = document.getElementById("scoreValue");
        const verdictBox = document.getElementById("verdictBox");
        const verdictTitle = document.getElementById("verdictTitle");
        const verdictNote = document.getElementById("verdictNote");
        const averageScore = document.getElementById("averageScore");
        const weakestDimension = document.getElementById("weakestDimension");
        const passportConfidence = document.getElementById("passportConfidence");
        const commercialTier = document.getElementById("commercialTier");
        const gapList = document.getElementById("gapList");
        const actionList = document.getElementById("actionList");

        const tierCards = {
            tier1: document.getElementById("tier1Card"),
            tier2: document.getElementById("tier2Card"),
            tier3: document.getElementById("tier3Card")
        };

        const pathCards = {
            0: document.getElementById("path0"),
            1: document.getElementById("path1"),
            2: document.getElementById("path2"),
            3: document.getElementById("path3"),
            4: document.getElementById("path4")
        };

        function maturityBand(avg) {
            if (avg < 0.5) return 0;
            if (avg < 1.5) return 1;
            if (avg < 2.5) return 2;
            if (avg < 3.5) return 3;
            return 4;
        }

        function getResultProfile(level) {
            if (level === 0) {
                return {
                    title: "Level 0 — Ad hoc",
                    verdict: "Evidence cannot yet support assurance",
                    note: "Records are fragmented and owner-dependent. The organization is not ready to issue defensible passports.",
                    confidence: "None",
                    tier: "Tier 1",
                    color: "#dc2626",
                    bg: "#fef2f2",
                    border: "#fecaca",
                    titleColor: "#991b1b"
                };
            }
            if (level === 1) {
                return {
                    title: "Level 1 — Documented",
                    verdict: "Documented but still manual",
                    note: "The organization can describe its evidence, but cannot yet prove integrated governance truth.",
                    confidence: "Static report",
                    tier: "Tier 1",
                    color: "#ea580c",
                    bg: "#fff7ed",
                    border: "#fed7aa",
                    titleColor: "#9a3412"
                };
            }
            if (level === 2) {
                return {
                    title: "Level 2 — Controlled",
                    verdict: "Controlled but not yet integrated",
                    note: "The organization can standardize evidence and review it, but it cannot yet issue high-confidence passports across systems.",
                    confidence: "Conditional",
                    tier: "Tier 2",
                    color: "#f59e0b",
                    bg: "#fffbeb",
                    border: "#fde68a",
                    titleColor: "#92400e"
                };
            }
            if (level === 3) {
                return {
                    title: "Level 3 — Integrated",
                    verdict: "Enterprise-ready assurance",
                    note: "Systems reconcile, dependencies are visible, and enterprise passports become explainable and defensible.",
                    confidence: "Enterprise-ready",
                    tier: "Tier 3",
                    color: "#2563eb",
                    bg: "#eff6ff",
                    border: "#bfdbfe",
                    titleColor: "#1d4ed8"
                };
            }
            return {
                title: "Level 4 — Assurance-Intelligent",
                verdict: "Live assurance intelligence achieved",
                note: "The organization can generate portable, predictive, cross-domain assurance from governed truth.",
                confidence: "Assurance-intelligent",
                tier: "Tier 3",
                color: "#16a34a",
                bg: "#ecfdf5",
                border: "#a7f3d0",
                titleColor: "#166534"
            };
        }

        function gapSeverity(value) {
            if (value <= 1) return "high";
            if (value === 2) return "medium";
            return "low";
        }

        function gapMessage(key, value) {
            const messages = {
                evidence: {
                    0: "Evidence is scattered and not yet packaged in a repeatable way.",
                    1: "Templates exist, but evidence is still manually assembled.",
                    2: "Standardized packs exist; next step is to connect them across workflows.",
                    3: "Evidence packs are integrated across workflows.",
                    4: "Evidence is generated as live passport-ready output."
                },
                integrity: {
                    0: "There is no reliable proof that evidence has remained unchanged.",
                    1: "Integrity relies mainly on manual review.",
                    2: "Hash / version checks exist; next step is ledger-linked trust.",
                    3: "Integrity is linked across the chain.",
                    4: "Trust state is continuous and portable."
                },
                reconciliation: {
                    0: "The organization cannot yet prove that systems agree.",
                    1: "Current maturity is documented only. Systems do not yet produce a unified governance truth.",
                    2: "Matching rules exist; next step is governed cross-system verdicts.",
                    3: "Cross-system reconciliation is enterprise-ready.",
                    4: "The organization can detect governance drift predictively."
                },
                dependency: {
                    0: "Readiness dependencies are largely invisible.",
                    1: "Readiness blockers are still manually interpreted instead of systematically gated.",
                    2: "Dependency rules exist; next step is automated validation.",
                    3: "Dependencies are integrated into decision logic.",
                    4: "The organization can model blast radius and decision impact."
                },
                exception: {
                    0: "Exceptions are disconnected from closure logic.",
                    1: "Exceptions are logged, but not yet well linked to readiness.",
                    2: "Exceptions are owned and reviewed; next step is direct closure integration.",
                    3: "Exceptions and CAPA are linked to final readiness.",
                    4: "Exception intelligence is proactive and explainable."
                },
                dr: {
                    0: "Recovery is reactive and difficult to prove.",
                    1: "Recovery evidence exists, but restore proof, restart gates, and final closure are not fully integrated.",
                    2: "Restore proof is tracked; next step is restart and closure linkage.",
                    3: "Recovery decisions are integrated into governance.",
                    4: "A recovery twin supports certified resilience."
                }
            };
            return messages[key][value];
        }

        function recommendedActions(values, level) {
            const actions = [];
            const sorted = Object.entries(values).sort((a, b) => a[1] - b[1]);

            sorted.slice(0, 3).forEach(([key, value]) => {
                if (key === "evidence" && value < 3) {
                    actions.push("Standardize evidence packs and define mandatory artefacts per governed object.");
                }
                if (key === "integrity" && value < 3) {
                    actions.push("Extend integrity from review-based controls into hash / ledger-backed verification.");
                }
                if (key === "reconciliation" && value < 3) {
                    actions.push("Move from isolated records to cross-system reconciliation verdicts.");
                }
                if (key === "dependency" && value < 3) {
                    actions.push("Introduce dependency gates before release, restart, or closure decisions.");
                }
                if (key === "exception" && value < 3) {
                    actions.push("Link exceptions and CAPA directly to readiness and closure logic.");
                }
                if (key === "dr" && value < 3) {
                    actions.push("Formalize DR evidence, restart approval, and recovery certification.");
                }
            });

            if (level >= 3) {
                actions.push("Scale passports across additional regulated objects and benchmark performance by domain.");
            }
            if (level === 4) {
                actions.push("Use predictive governance drift and recovery-twin analytics as differentiated enterprise intelligence.");
            }

            return [...new Set(actions)].slice(0, 4);
        }

        function updateCommercialTier(tier) {
            Object.values(tierCards).forEach(card => card.classList.remove("recommended"));
            if (tier === "Tier 1") tierCards.tier1.classList.add("recommended");
            if (tier === "Tier 2") tierCards.tier2.classList.add("recommended");
            if (tier === "Tier 3") tierCards.tier3.classList.add("recommended");
        }

        function updatePassportPath(level) {
            Object.values(pathCards).forEach(card => card.classList.remove("active"));
            pathCards[level].classList.add("active");
        }

        function updateScorecard() {
            const values = {};
            Object.keys(sliders).forEach(key => {
                const value = Number(sliders[key].value);
                values[key] = value;
                valueLabels[key].textContent = value + " — " + labels[value];
                bars[key][0].style.width = (value * 25) + "%";
                bars[key][1].textContent = value;
            });

            const total = Object.values(values).reduce((sum, value) => sum + value, 0);
            const avg = total / 6;
            const level = maturityBand(avg);
            const profile = getResultProfile(level);

            const sorted = Object.entries(values).sort((a, b) => a[1] - b[1]);
            const weakestKey = sorted[0][0];

            resultTitle.textContent = profile.title;
            tierBadge.textContent = "Recommended Offer: " + profile.tier;
            scoreValue.textContent = avg.toFixed(1);
            averageScore.textContent = avg.toFixed(1) + " / 4";
            weakestDimension.textContent = dimensionShortNames[weakestKey];
            passportConfidence.textContent = profile.confidence;
            commercialTier.textContent = profile.tier;
            verdictTitle.textContent = profile.verdict;
            verdictNote.textContent = profile.note;

            const degrees = Math.round((avg / 4) * 360);
            scoreRing.style.background = `conic-gradient(${profile.color} 0deg, ${profile.color} ${degrees}deg, #e5e7eb ${degrees}deg, #e5e7eb 360deg)`;
            verdictBox.style.background = profile.bg;
            verdictBox.style.borderColor = profile.border;
            verdictTitle.style.color = profile.titleColor;

            gapList.innerHTML = "";
            sorted.slice(0, 3).forEach(([key, value]) => {
                const card = document.createElement("div");
                card.className = "gap-card " + gapSeverity(value);
                card.innerHTML = `
                    <div class="gap-title">${dimensionNames[key]}</div>
                    <div class="gap-note">${gapMessage(key, value)}</div>
                `;
                gapList.appendChild(card);
            });

            actionList.innerHTML = "";
            recommendedActions(values, level).forEach(action => {
                const li = document.createElement("li");
                li.textContent = action;
                actionList.appendChild(li);
            });

            updateCommercialTier(profile.tier);
            updatePassportPath(level);
        }

        Object.values(sliders).forEach(slider => {
            slider.addEventListener("input", () => {
                document.querySelectorAll(".preset-btn").forEach(btn => btn.classList.remove("active"));
                updateScorecard();
            });
        });

        document.querySelectorAll(".preset-btn").forEach(button => {
            button.addEventListener("click", () => {
                document.querySelectorAll(".preset-btn").forEach(btn => btn.classList.remove("active"));
                button.classList.add("active");

                const preset = presets[button.dataset.preset];
                Object.entries(preset).forEach(([key, value]) => {
                    sliders[key].value = value;
                });

                updateScorecard();
            });
        });

        updateScorecard();
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
        print("SKIP: COBIT-Chain Maturity Scorecard already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/cobit-chain-maturity-scorecard")',
        "COBIT-Chain Maturity Scorecard™",
        "Interactive Maturity Assessment",
        "Capability Gap Analysis",
        "Maturity Capability Matrix",
        "Commercial Tier Mapping",
        "Passport Confidence Path",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /cobit-chain-maturity-scorecard route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
