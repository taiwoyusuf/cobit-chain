from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# GOVERNANCE_RULE_FACTORY_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# GOVERNANCE_RULE_FACTORY_ACTIVE
@app.route("/governance-rule-factory")
def governance_rule_factory_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Governance Rule Factory™ | COBIT-Chain™ / AssuranceLayer™</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #f4f7fb;
            color: #172033;
        }
        .shell {
            max-width: 1440px;
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
            background: linear-gradient(135deg, #111827 0%, #312e81 48%, #0f766e 100%);
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
            max-width: 1080px;
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
        .source-card {
            border-radius: 22px;
            padding: 20px;
            background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
            border: 1px solid #dbe7f8;
        }
        .source-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #4338ca;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .source-title {
            font-size: 24px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .source-note {
            color: #4c5b73;
            line-height: 1.55;
            margin-bottom: 16px;
        }
        .source-meta {
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
        .factory-summary {
            display: grid;
            gap: 12px;
        }
        .summary-item {
            display: grid;
            grid-template-columns: 46px 1fr;
            gap: 13px;
            align-items: start;
            border-radius: 18px;
            padding: 15px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .summary-no {
            width: 36px;
            height: 36px;
            border-radius: 12px;
            background: #312e81;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 900;
        }
        .summary-title {
            font-weight: 900;
            margin-bottom: 5px;
        }
        .summary-note {
            color: #53637b;
            line-height: 1.45;
            font-size: 14px;
        }
        .rule-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .rule-card {
            border-radius: 20px;
            padding: 18px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .rule-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .rule-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .rule-card.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .rule-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .rule-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .rule-title {
            font-size: 17px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .rule-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
            margin-bottom: 12px;
        }
        .rule-chip {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
            background: rgba(255,255,255,.72);
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
        .pipeline {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 12px;
        }
        .stage {
            border-radius: 18px;
            padding: 16px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .stage-number {
            width: 32px;
            height: 32px;
            border-radius: 11px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #312e81;
            color: #fff;
            font-weight: 900;
            margin-bottom: 12px;
        }
        .stage h3 {
            margin: 0 0 8px;
            font-size: 16px;
        }
        .stage p {
            margin: 0;
            font-size: 14px;
        }
        .builder {
            display: grid;
            grid-template-columns: 1fr .86fr;
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
        .output-card {
            border-radius: 22px;
            padding: 22px;
            background: #eef2ff;
            border: 1px solid #c7d2fe;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        .output-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .output-title {
            font-size: 26px;
            font-weight: 900;
            color: #3730a3;
            margin-bottom: 10px;
        }
        .output-rule {
            border-radius: 18px;
            background: rgba(255,255,255,.72);
            padding: 16px;
            font-weight: 800;
            line-height: 1.5;
            margin-bottom: 12px;
        }
        .output-note {
            color: #4d5b73;
            line-height: 1.55;
        }
        .impact-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .impact-card {
            border-radius: 18px;
            padding: 17px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
        }
        .impact-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .impact-value {
            font-size: 28px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .impact-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
        }
        .publish-console {
            display: grid;
            grid-template-columns: 1fr .82fr;
            gap: 18px;
        }
        .publish-list {
            display: grid;
            gap: 12px;
        }
        .publish-item {
            display: flex;
            justify-content: space-between;
            gap: 14px;
            align-items: center;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .publish-item h3 {
            margin: 0 0 5px;
            font-size: 16px;
        }
        .publish-item p {
            margin: 0;
            font-size: 14px;
        }
        .publish-btn {
            border: 0;
            cursor: pointer;
            border-radius: 999px;
            padding: 10px 14px;
            background: #312e81;
            color: #fff;
            font-weight: 900;
            font-size: 13px;
            white-space: nowrap;
        }
        .publish-result {
            border-radius: 22px;
            padding: 22px;
            background: #eef2ff;
            border: 1px solid #c7d2fe;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        .publish-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .publish-title {
            font-size: 28px;
            font-weight: 900;
            color: #3730a3;
            margin-bottom: 10px;
        }
        .publish-note {
            color: #4d5b73;
            line-height: 1.55;
        }
        .maturity-card {
            border-left: 5px solid #312e81;
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
        @media (max-width: 1240px) {
            .hero-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .grid-2,
            .grid-3,
            .builder,
            .publish-console {
                grid-template-columns: 1fr;
            }
            .rule-grid,
            .impact-grid,
            .source-meta {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
            .pipeline {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .rule-grid,
            .impact-grid,
            .source-meta,
            .pipeline {
                grid-template-columns: 1fr;
            }
            .publish-item {
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
                <a href="/governance-learning-loop">Learning Loop</a>
                <a href="/predictive-governance-drift">Predictive Drift</a>
                <a href="/governance-decision-engine">Decision Engine</a>
                <a href="/governance-assurance-register">Assurance Register</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Preventive Control Evolution Layer</div>
            <h1>Governance Rule Factory™</h1>
            <p>
                The point where enterprise learning becomes enforceable governance logic.
                After the Governance Learning Loop™ extracts a failure pattern, the Rule Factory converts that pattern
                into candidate controls, tests the likely impact, routes them through governance review, and prepares
                new preventive rules for use across future workflows.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Source Lesson</div>
                    <div class="hero-value">GCC-2026-001</div>
                    <div class="hero-note">False closure before release</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Candidate Rules</div>
                    <div class="hero-value">4</div>
                    <div class="hero-note">Generated from one closed case</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Rules in Review</div>
                    <div class="hero-value">3</div>
                    <div class="hero-note">Awaiting formal approval</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Ready to Publish</div>
                    <div class="hero-value">1</div>
                    <div class="hero-note">Validated preventive rule</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Control Coverage Gain</div>
                    <div class="hero-value">+22%</div>
                    <div class="hero-note">Release-sensitive scenarios</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Factory State</div>
                    <div class="hero-value">Active</div>
                    <div class="hero-note">Learning converted to control</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Learning Source Entering the Factory</h2>
                <div class="source-card">
                    <div class="source-kicker">Governance Learning Input</div>
                    <div class="source-title">Closed Pattern: Local Closure ≠ Enterprise Truth</div>
                    <div class="source-note">
                        The source case proved that a ServiceNow item can appear complete while release-sensitive truth
                        is still broken across Veeva, myAccess, and Blue Mountain. The Rule Factory converts that lesson
                        into preventive logic that can stop similar cases earlier next time.
                    </div>

                    <div class="source-meta">
                        <div class="meta-card">
                            <div class="meta-label">Source Certificate</div>
                            <div class="meta-value">GCC-2026-001</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Pattern Class</div>
                            <div class="meta-value">False Closure</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Primary Systems</div>
                            <div class="meta-value">SN / Veeva / BM</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Rule Goal</div>
                            <div class="meta-value">Prevent Recurrence</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Factory Logic</h2>
                <div class="factory-summary">
                    <div class="summary-item">
                        <div class="summary-no">1</div>
                        <div>
                            <div class="summary-title">Translate the lesson</div>
                            <div class="summary-note">
                                Convert a closed governance failure into explicit conditions, signals, and actions.
                            </div>
                        </div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-no">2</div>
                        <div>
                            <div class="summary-title">Design candidate controls</div>
                            <div class="summary-note">
                                Express the lesson as enforceable rules across dependency, drift, reconciliation, and closure layers.
                            </div>
                        </div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-no">3</div>
                        <div>
                            <div class="summary-title">Test impact before publishing</div>
                            <div class="summary-note">
                                Estimate prevention gain, escalation burden, false-positive risk, and affected workflows.
                            </div>
                        </div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-no">4</div>
                        <div>
                            <div class="summary-title">Promote approved rules</div>
                            <div class="summary-note">
                                Move validated logic into active platform controls and future governance decisions.
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Candidate Preventive Rules</h2>
            <p>
                These are the rules generated from one certified governance lesson before formal publication.
            </p>

            <div class="rule-grid">
                <div class="rule-card red">
                    <div class="rule-label">Rule Candidate 01</div>
                    <div class="rule-title">Closure Blocker</div>
                    <div class="rule-note">
                        Block closure when a linked Veeva CAPA remains open on a release-sensitive record.
                    </div>
                    <div class="rule-chip">High consequence</div>
                </div>
                <div class="rule-card amber">
                    <div class="rule-label">Rule Candidate 02</div>
                    <div class="rule-title">Access Drift Alert</div>
                    <div class="rule-note">
                        Raise drift when requested role, approved role, and granted role are not aligned.
                    </div>
                    <div class="rule-chip">Early warning</div>
                </div>
                <div class="rule-card blue">
                    <div class="rule-label">Rule Candidate 03</div>
                    <div class="rule-title">Reconciliation Requirement</div>
                    <div class="rule-note">
                        Require Veeva ↔ Blue Mountain consistency before release-sensitive re-closure.
                    </div>
                    <div class="rule-chip">Truth validation</div>
                </div>
                <div class="rule-card green">
                    <div class="rule-label">Rule Candidate 04</div>
                    <div class="rule-title">Certificate Requirement</div>
                    <div class="rule-note">
                        Keep repeat-pattern cases active until a formal closure certificate is issued.
                    </div>
                    <div class="rule-chip">Sustained control</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Rule Review Register</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Rule ID</th>
                            <th>Control Intent</th>
                            <th>Target Layer</th>
                            <th>Review State</th>
                            <th>Expected Effect</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>GRF-001</td>
                            <td>Block closure with open CAPA</td>
                            <td>Dependency Validation</td>
                            <td><span class="pill green">Ready</span></td>
                            <td>Prevents false completion</td>
                        </tr>
                        <tr>
                            <td>GRF-002</td>
                            <td>Flag approved-role / granted-role mismatch</td>
                            <td>Predictive Drift</td>
                            <td><span class="pill amber">In Review</span></td>
                            <td>Earlier access-risk signal</td>
                        </tr>
                        <tr>
                            <td>GRF-003</td>
                            <td>Require Veeva ↔ Blue Mountain match</td>
                            <td>Reconciliation Layer</td>
                            <td><span class="pill amber">In Review</span></td>
                            <td>Improves operational truth</td>
                        </tr>
                        <tr>
                            <td>GRF-004</td>
                            <td>Require closure certificate before exit</td>
                            <td>Assurance Register</td>
                            <td><span class="pill blue">Draft</span></td>
                            <td>Reduces repeat-pattern leakage</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="panel">
                <h2>Control Publication Pipeline</h2>
                <div class="pipeline">
                    <div class="stage">
                        <div class="stage-number">1</div>
                        <h3>Lesson</h3>
                        <p>Pattern enters from the Governance Learning Loop™.</p>
                    </div>
                    <div class="stage">
                        <div class="stage-number">2</div>
                        <h3>Draft</h3>
                        <p>Rule logic is written as trigger, condition, and action.</p>
                    </div>
                    <div class="stage">
                        <div class="stage-number">3</div>
                        <h3>Test</h3>
                        <p>Impact, exceptions, and false positives are reviewed.</p>
                    </div>
                    <div class="stage">
                        <div class="stage-number">4</div>
                        <h3>Approve</h3>
                        <p>QA / governance owners formally authorize the rule.</p>
                    </div>
                    <div class="stage">
                        <div class="stage-number">5</div>
                        <h3>Publish</h3>
                        <p>The rule becomes active future control logic.</p>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Interactive Rule Builder</h2>
            <p>
                This simulation shows how a governance lesson is converted into formal rule logic.
            </p>

            <div class="builder">
                <div class="builder-grid">
                    <div class="builder-row">
                        <label for="triggerSelect">Trigger</label>
                        <select id="triggerSelect">
                            <option value="closure">Workflow marked closed</option>
                            <option value="role">Privileged role change requested</option>
                            <option value="release">Release-sensitive record enters final review</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label for="conditionSelect">Condition</label>
                        <select id="conditionSelect">
                            <option value="capa">linked CAPA remains open</option>
                            <option value="access">approved role does not match granted role</option>
                            <option value="reconciliation">Veeva and Blue Mountain do not reconcile</option>
                        </select>
                    </div>
                    <div class="builder-row">
                        <label for="actionSelect">Governance Action</label>
                        <select id="actionSelect">
                            <option value="block">block closure and route to QA review</option>
                            <option value="drift">raise predictive drift alert</option>
                            <option value="hold">hold release until reconciliation passes</option>
                        </select>
                    </div>
                </div>

                <div class="output-card">
                    <div class="output-label">Generated Rule Logic</div>
                    <div id="ruleTitle" class="output-title">Rule Draft Ready</div>
                    <div id="ruleSentence" class="output-rule">
                        When a workflow is marked closed, if a linked CAPA remains open, then block closure and route to QA review.
                    </div>
                    <div id="ruleNote" class="output-note">
                        This rule directly prevents the same false-closure pattern observed in GCC-2026-001.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Projected Rule Impact</h2>
            <div class="impact-grid">
                <div class="impact-card">
                    <div class="impact-label">False Closures Prevented</div>
                    <div class="impact-value">4 / quarter</div>
                    <div class="impact-note">
                        Estimated repeat-pattern cases stopped before unsafe closure.
                    </div>
                </div>
                <div class="impact-card">
                    <div class="impact-label">Audit Defensibility Gain</div>
                    <div class="impact-value">+18%</div>
                    <div class="impact-note">
                        More release-sensitive records carry complete evidence logic.
                    </div>
                </div>
                <div class="impact-card">
                    <div class="impact-label">Recurrence Risk Reduction</div>
                    <div class="impact-value">72% → 28%</div>
                    <div class="impact-note">
                        Learning becomes preventive control rather than passive history.
                    </div>
                </div>
                <div class="impact-card">
                    <div class="impact-label">Escalation Burden</div>
                    <div class="impact-value">Low</div>
                    <div class="impact-note">
                        Rules target high-consequence conditions, not every minor mismatch.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Rule Publication Console</h2>
            <p>
                The factory does not immediately push every idea into production. It distinguishes draft logic from reviewed,
                approved, and active governance control.
            </p>

            <div class="publish-console">
                <div class="publish-list">
                    <div class="publish-item">
                        <div>
                            <h3>Approve GRF-001 — Closure Blocker</h3>
                            <p>Validated rule preventing closure while linked CAPA remains unresolved.</p>
                        </div>
                        <button class="publish-btn" data-action="approve">Approve</button>
                    </div>
                    <div class="publish-item">
                        <div>
                            <h3>Publish to Dependency Validation</h3>
                            <p>Promote the approved rule into future release-sensitive workflow checks.</p>
                        </div>
                        <button class="publish-btn" data-action="publish">Publish</button>
                    </div>
                    <div class="publish-item">
                        <div>
                            <h3>Send feedback to AI Copilot</h3>
                            <p>Teach the copilot to explain why the new rule exists and when it applies.</p>
                        </div>
                        <button class="publish-btn" data-action="copilot">Send</button>
                    </div>
                    <div class="publish-item">
                        <div>
                            <h3>Add pattern to monitoring watchlist</h3>
                            <p>Track cases that resemble the false-closure signature in future portfolios.</p>
                        </div>
                        <button class="publish-btn" data-action="watchlist">Add</button>
                    </div>
                </div>

                <div id="publishResult" class="publish-result">
                    <div class="publish-label">Factory Outcome</div>
                    <div id="publishTitle" class="publish-title">Awaiting Action</div>
                    <div id="publishNote" class="publish-note">
                        Select a publication action to see how learned governance becomes active enterprise control.
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="maturity-card">
                <h3>Learning Loop</h3>
                <p>
                    Captures the lesson from a resolved governance failure.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Rule Factory</h3>
                <p>
                    Converts the lesson into reviewed, testable, enforceable control logic.
                </p>
            </div>
            <div class="maturity-card">
                <h3>Strategic Value</h3>
                <p>
                    The platform evolves its own control environment instead of only reporting what already happened.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by the Rule Factory</h2>
            <p>
                The Governance Learning Loop™ answers: <strong>“What did the enterprise learn?”</strong>
            </p>
            <p>
                The Governance Rule Factory™ answers: <strong>“How is that lesson converted into a stronger preventive control?”</strong>
            </p>
            <p>
                That is a major step beyond dashboards, workflow trackers, or even after-action reviews.
                COBIT-Chain™ now demonstrates how governance intelligence is operationalized into future control design,
                making the enterprise more difficult to fail in the same way twice.
            </p>
            <div class="footer-note">
                Simulation chain: pain point detection → dependency validation → reconciliation → decision intelligence →
                Governance Passport™ → Governance Assurance Register™ → Governance Intervention Workbench™ →
                Governance Re-Closure Gate™ → Governance Closure Certificate™ → Governance Learning Loop™ →
                Governance Rule Factory™.
            </div>
        </section>
    </div>

    <script>
        const triggerSelect = document.getElementById("triggerSelect");
        const conditionSelect = document.getElementById("conditionSelect");
        const actionSelect = document.getElementById("actionSelect");
        const ruleSentence = document.getElementById("ruleSentence");
        const ruleNote = document.getElementById("ruleNote");

        const triggerText = {
            closure: "a workflow is marked closed",
            role: "a privileged role change is requested",
            release: "a release-sensitive record enters final review"
        };

        const conditionText = {
            capa: "a linked CAPA remains open",
            access: "the approved role does not match the granted role",
            reconciliation: "Veeva and Blue Mountain do not reconcile"
        };

        const actionText = {
            block: "block closure and route to QA review",
            drift: "raise a predictive drift alert",
            hold: "hold release until reconciliation passes"
        };

        function updateRule() {
            const trigger = triggerText[triggerSelect.value];
            const condition = conditionText[conditionSelect.value];
            const action = actionText[actionSelect.value];

            ruleSentence.textContent = "When " + trigger + ", if " + condition + ", then " + action + ".";

            if (triggerSelect.value === "closure" && conditionSelect.value === "capa") {
                ruleNote.textContent = "This rule directly prevents the same false-closure pattern observed in GCC-2026-001.";
            } else if (conditionSelect.value === "access") {
                ruleNote.textContent = "This rule strengthens access governance by detecting approval-versus-entitlement drift earlier.";
            } else if (conditionSelect.value === "reconciliation") {
                ruleNote.textContent = "This rule prevents release-sensitive decisions from proceeding while enterprise truth remains split.";
            } else {
                ruleNote.textContent = "This rule converts a learned governance pattern into future preventive control logic.";
            }
        }

        triggerSelect.addEventListener("change", updateRule);
        conditionSelect.addEventListener("change", updateRule);
        actionSelect.addEventListener("change", updateRule);

        const publishButtons = document.querySelectorAll(".publish-btn");
        const publishResult = document.getElementById("publishResult");
        const publishTitle = document.getElementById("publishTitle");
        const publishNote = document.getElementById("publishNote");

        const publishOutcomes = {
            approve: {
                title: "GRF-001 Approved",
                note: "The closure-blocker rule has completed review and is now eligible for controlled publication."
            },
            publish: {
                title: "Rule Published",
                note: "GRF-001 is now available to the Dependency Validation layer for future release-sensitive workflow checks."
            },
            copilot: {
                title: "Copilot Updated",
                note: "The AI Governance Copilot can now explain the new rule, its origin, and the failure pattern it prevents."
            },
            watchlist: {
                title: "Watchlist Expanded",
                note: "Future cases resembling the false-closure signature will be surfaced earlier in governance monitoring."
            }
        };

        publishButtons.forEach(button => {
            button.addEventListener("click", () => {
                const outcome = publishOutcomes[button.dataset.action];
                publishTitle.textContent = outcome.title;
                publishNote.textContent = outcome.note;
                publishResult.style.background = "#ecfdf5";
                publishResult.style.borderColor = "#a7f3d0";
                publishTitle.style.color = "#166534";
            });
        });

        updateRule();
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
        print("SKIP: GOVERNANCE_RULE_FACTORY_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/governance-rule-factory")',
        "Governance Rule Factory™",
        "Candidate Preventive Rules",
        "Interactive Rule Builder",
        "Rule Publication Console",
        "Rule Published",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /governance-rule-factory route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
