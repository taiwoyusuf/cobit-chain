from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# GOVERNANCE_LEARNING_LOOP_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# GOVERNANCE_LEARNING_LOOP_ACTIVE
@app.route("/governance-learning-loop")
def governance_learning_loop_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Governance Learning Loop™ | COBIT-Chain™ / AssuranceLayer™</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #f4f7fb;
            color: #172033;
        }
        .shell {
            max-width: 1420px;
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
            background: linear-gradient(135deg, #172554 0%, #4338ca 48%, #0f766e 100%);
            color: #fff;
            border-radius: 26px;
            padding: 28px;
            box-shadow: 0 16px 42px rgba(23, 37, 84, .22);
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
            max-width: 1040px;
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
            background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
            border: 1px solid #dbe7f8;
            border-radius: 22px;
            padding: 20px;
        }
        .case-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #4f46e5;
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
        .risk-comparison {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 14px;
        }
        .risk-card {
            border-radius: 20px;
            padding: 18px;
            border: 1px solid #e2eaf7;
        }
        .risk-card.before {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .risk-card.after {
            background: #ecfdf5;
            border-color: #a7f3d0;
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
            font-size: 34px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .risk-card.before .risk-value { color: #991b1b; }
        .risk-card.after .risk-value { color: #166534; }
        .risk-note {
            color: #53637b;
            line-height: 1.45;
            font-size: 14px;
        }
        .learning-flow {
            display: grid;
            grid-template-columns: repeat(6, minmax(0, 1fr));
            gap: 12px;
        }
        .flow-step {
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .flow-number {
            width: 32px;
            height: 32px;
            border-radius: 11px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #4338ca;
            color: #fff;
            font-weight: 900;
            margin-bottom: 12px;
        }
        .flow-step h3 {
            margin: 0 0 8px;
            font-size: 16px;
        }
        .flow-step p {
            margin: 0;
            font-size: 14px;
        }
        .pattern-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .pattern-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .pattern-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .pattern-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .pattern-card.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .pattern-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .pattern-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .pattern-title {
            font-size: 17px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .pattern-note {
            font-size: 14px;
            line-height: 1.45;
            color: #516078;
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
        .pill.red {
            background: #fee2e2;
            color: #991b1b;
        }
        .pill.amber {
            background: #fef3c7;
            color: #92400e;
        }
        .pill.green {
            background: #dcfce7;
            color: #166534;
        }
        .pill.blue {
            background: #dbeafe;
            color: #1d4ed8;
        }
        .feedback-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .feedback-card {
            border-radius: 20px;
            padding: 18px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .feedback-card h3 {
            margin: 0 0 8px;
            font-size: 16px;
        }
        .feedback-card p {
            margin: 0 0 12px;
            font-size: 14px;
        }
        .feedback-state {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            background: #e0e7ff;
            color: #3730a3;
            font-size: 12px;
            font-weight: 900;
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
            background: #4338ca;
            color: #fff;
            font-weight: 900;
            font-size: 13px;
            white-space: nowrap;
        }
        .console-result {
            border-radius: 22px;
            padding: 22px;
            background: #eef2ff;
            border: 1px solid #c7d2fe;
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
            color: #3730a3;
            margin-bottom: 10px;
        }
        .console-note {
            color: #4d5b73;
            line-height: 1.55;
        }
        .maturity-card {
            border-left: 5px solid #4338ca;
            background: #eef2ff;
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
        @media (max-width: 1220px) {
            .hero-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .grid-2,
            .grid-3,
            .action-console {
                grid-template-columns: 1fr;
            }
            .learning-flow {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .pattern-grid,
            .feedback-grid,
            .case-meta {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .learning-flow,
            .pattern-grid,
            .feedback-grid,
            .case-meta,
            .risk-comparison {
                grid-template-columns: 1fr;
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
                <a href="/governance-closure-certificate">Closure Certificate</a>
                <a href="/predictive-governance-drift">Predictive Drift</a>
                <a href="/ai-governance-copilot">AI Governance Copilot</a>
                <a href="/governance-assurance-register">Assurance Register</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Continuous Enterprise Governance Intelligence</div>
            <h1>Governance Learning Loop™</h1>
            <p>
                The feedback layer that prevents closed cases from becoming forgotten cases.
                Once a Governance Closure Certificate™ is issued, COBIT-Chain™ extracts the root pattern,
                updates future watchlists, tunes predictive drift signals, strengthens AI guidance, and turns
                one repaired failure into enterprise-wide preventive intelligence.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Learning Source</div>
                    <div class="hero-value">GCC-2026-001</div>
                    <div class="hero-note">Closed false-closure case</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Pattern Extracted</div>
                    <div class="hero-value">1</div>
                    <div class="hero-note">False closure + cross-system drift</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Watchlists Updated</div>
                    <div class="hero-value">3</div>
                    <div class="hero-note">ServiceNow, myAccess, Veeva</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Rules Proposed</div>
                    <div class="hero-value">4</div>
                    <div class="hero-note">Preventive governance controls</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Recurrence Risk</div>
                    <div class="hero-value">72% → 28%</div>
                    <div class="hero-note">After learning applied</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Learning State</div>
                    <div class="hero-value">Active</div>
                    <div class="hero-note">Feedback loop operating</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Closed Case Feeding the Loop</h2>
                <div class="case-card">
                    <div class="case-kicker">Source Certificate</div>
                    <div class="case-title">GCC-2026-001 — False Closure Before Release</div>
                    <div class="case-note">
                        The enterprise learned that a locally closed ServiceNow item can still be unsafe when CAPA status,
                        access approval, and operational-state reconciliation remain unresolved elsewhere.
                    </div>

                    <div class="case-meta">
                        <div class="meta-card">
                            <div class="meta-label">Original Finding</div>
                            <div class="meta-value">False Closure</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Broken Chain</div>
                            <div class="meta-value">SN → Veeva → Blue Mountain</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Root Pattern</div>
                            <div class="meta-value">Local ≠ Enterprise Truth</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Outcome</div>
                            <div class="meta-value">Certified Re-Closure</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Recurrence Risk Before vs After Learning</h2>
                <div class="risk-comparison">
                    <div class="risk-card before">
                        <div class="risk-label">Before Learning</div>
                        <div class="risk-value">72%</div>
                        <div class="risk-note">
                            Similar false-closure conditions could recur because the pattern had not yet been promoted into preventive controls.
                        </div>
                    </div>
                    <div class="risk-card after">
                        <div class="risk-label">After Learning</div>
                        <div class="risk-value">28%</div>
                        <div class="risk-note">
                            Updated drift monitoring, control rules, and watchlists now reduce the chance of repeat failure.
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>How the Governance Learning Loop™ Works</h2>
            <div class="learning-flow">
                <div class="flow-step">
                    <div class="flow-number">1</div>
                    <h3>Close</h3>
                    <p>A certified case reaches defensible closure.</p>
                </div>
                <div class="flow-step">
                    <div class="flow-number">2</div>
                    <h3>Extract</h3>
                    <p>The platform isolates the true failure pattern.</p>
                </div>
                <div class="flow-step">
                    <div class="flow-number">3</div>
                    <h3>Classify</h3>
                    <p>The issue is linked to systems, controls, and recurrence risk.</p>
                </div>
                <div class="flow-step">
                    <div class="flow-number">4</div>
                    <h3>Teach</h3>
                    <p>AI guidance and drift models absorb the new lesson.</p>
                </div>
                <div class="flow-step">
                    <div class="flow-number">5</div>
                    <h3>Prevent</h3>
                    <p>New rules and watchlists flag the pattern earlier next time.</p>
                </div>
                <div class="flow-step">
                    <div class="flow-number">6</div>
                    <h3>Improve</h3>
                    <p>The assurance register becomes stronger after every case.</p>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Pattern Intelligence Extracted</h2>
            <p>
                The closed case is not stored only as history. It is decomposed into reusable governance intelligence.
            </p>

            <div class="pattern-grid">
                <div class="pattern-card red">
                    <div class="pattern-label">Pattern 01</div>
                    <div class="pattern-title">False Closure Trigger</div>
                    <div class="pattern-note">
                        A workflow is marked closed before cross-system dependencies are reconciled.
                    </div>
                </div>
                <div class="pattern-card amber">
                    <div class="pattern-label">Pattern 02</div>
                    <div class="pattern-title">Evidence Mismatch</div>
                    <div class="pattern-note">
                        Approved access and granted access diverge across linked records.
                    </div>
                </div>
                <div class="pattern-card blue">
                    <div class="pattern-label">Pattern 03</div>
                    <div class="pattern-title">Release Exposure</div>
                    <div class="pattern-note">
                        Open CAPA or downstream dependency remains hidden until late-stage review.
                    </div>
                </div>
                <div class="pattern-card green">
                    <div class="pattern-label">Pattern 04</div>
                    <div class="pattern-title">Recovery Signature</div>
                    <div class="pattern-note">
                        A defensible repair requires intervention, gate validation, and certified closure.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Preventive Rules Proposed</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Rule</th>
                            <th>New Preventive Logic</th>
                            <th>Target Module</th>
                            <th>Effect</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Rule 01</td>
                            <td>Do not accept ServiceNow closure if linked CAPA remains open.</td>
                            <td>Dependency Validation</td>
                            <td><span class="pill red">Block false closure</span></td>
                        </tr>
                        <tr>
                            <td>Rule 02</td>
                            <td>Raise drift signal when approved role ≠ granted role.</td>
                            <td>Predictive Drift</td>
                            <td><span class="pill amber">Earlier detection</span></td>
                        </tr>
                        <tr>
                            <td>Rule 03</td>
                            <td>Escalate Veeva ↔ Blue Mountain mismatch on release-sensitive records.</td>
                            <td>Reconciliation Layer</td>
                            <td><span class="pill blue">Higher visibility</span></td>
                        </tr>
                        <tr>
                            <td>Rule 04</td>
                            <td>Require closure certificate before similar cases leave the watchlist.</td>
                            <td>Assurance Register</td>
                            <td><span class="pill green">Sustained control</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="panel">
                <h2>Feedback Destinations</h2>
                <div class="feedback-grid">
                    <div class="feedback-card">
                        <h3>Predictive Drift</h3>
                        <p>New trigger added for premature closure with unresolved dependencies.</p>
                        <div class="feedback-state">Signal Strengthened</div>
                    </div>
                    <div class="feedback-card">
                        <h3>AI Governance Copilot</h3>
                        <p>New guidance added: “Closed locally does not mean true globally.”</p>
                        <div class="feedback-state">Prompt Updated</div>
                    </div>
                    <div class="feedback-card">
                        <h3>Assurance Register</h3>
                        <p>Similar open cases are grouped into a repeat-pattern watchlist.</p>
                        <div class="feedback-state">Watchlist Expanded</div>
                    </div>
                    <div class="feedback-card">
                        <h3>Decision Engine</h3>
                        <p>Decision weighting increases when the pattern touches release-sensitive chains.</p>
                        <div class="feedback-state">Rule Tuned</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Learning Promotion Console</h2>
            <p>
                This simulation shows how one closed certificate can be promoted into future enterprise controls.
            </p>

            <div class="action-console">
                <div class="action-list">
                    <div class="action-item">
                        <div>
                            <h3>Promote false-closure pattern into watchlist</h3>
                            <p>Track similar ServiceNow closures carrying unresolved linked dependencies.</p>
                        </div>
                        <button class="action-btn" data-action="watchlist">Promote</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Train drift model with repaired case signature</h3>
                            <p>Use this case to strengthen future recurrence detection.</p>
                        </div>
                        <button class="action-btn" data-action="drift">Apply</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Update AI copilot guidance</h3>
                            <p>Add a reusable explanation for local closure versus enterprise truth.</p>
                        </div>
                        <button class="action-btn" data-action="copilot">Update</button>
                    </div>
                    <div class="action-item">
                        <div>
                            <h3>Publish preventive rule set</h3>
                            <p>Make the extracted logic available to future governance decisions.</p>
                        </div>
                        <button class="action-btn" data-action="rules">Publish</button>
                    </div>
                </div>

                <div id="consoleResult" class="console-result">
                    <div class="console-label">Learning Outcome</div>
                    <div id="consoleTitle" class="console-title">Awaiting Promotion</div>
                    <div id="consoleNote" class="console-note">
                        Select a learning action to see how the closed case strengthens future governance controls.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>Before</h3>
                <p>
                    The platform could prove that a case was repaired.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Now</h3>
                <p>
                    The platform also remembers why it failed and applies that lesson forward.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    Every certified case makes the enterprise harder to surprise in the same way twice.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by the Learning Loop</h2>
            <p>
                The Governance Closure Certificate™ answers: <strong>“Why is this issue now safely closed?”</strong>
            </p>
            <p>
                The Governance Learning Loop™ answers: <strong>“What did the enterprise learn from this issue, and how will that reduce future recurrence?”</strong>
            </p>
            <p>
                That is the difference between a system that records governance and a system that compounds governance intelligence over time.
                COBIT-Chain™ now does not merely manage controls; it learns from control failures and feeds stronger preventive logic back into the enterprise.
            </p>
            <div class="footer-note">
                Simulation chain: pain point detection → dependency validation → reconciliation → decision intelligence →
                Governance Passport™ → Governance Assurance Register™ → Governance Intervention Workbench™ →
                Governance Re-Closure Gate™ → Governance Closure Certificate™ → Governance Learning Loop™.
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".action-btn");
        const consoleResult = document.getElementById("consoleResult");
        const consoleTitle = document.getElementById("consoleTitle");
        const consoleNote = document.getElementById("consoleNote");

        const outcomes = {
            watchlist: {
                title: "Watchlist Expanded",
                note: "Similar ServiceNow closures with unresolved linked dependencies will now be surfaced earlier in the Assurance Register."
            },
            drift: {
                title: "Drift Model Strengthened",
                note: "The repaired-case signature has been fed into predictive monitoring to lower recurrence risk on future cases."
            },
            copilot: {
                title: "Copilot Guidance Updated",
                note: "The AI Governance Copilot now carries a reusable lesson: local workflow closure is not the same as enterprise truth."
            },
            rules: {
                title: "Preventive Rules Published",
                note: "The extracted governance logic is now available for future dependency validation, reconciliation, and closure decisions."
            }
        };

        buttons.forEach(button => {
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
        print("SKIP: GOVERNANCE_LEARNING_LOOP_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/governance-learning-loop")',
        "Governance Learning Loop™",
        "Pattern Intelligence Extracted",
        "Preventive Rules Proposed",
        "Learning Promotion Console",
        "Watchlist Expanded",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /governance-learning-loop route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
