from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_READINESS_COMMAND_CENTER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/readiness-command-center")'
ROUTE_ALIAS = '@app.route("/citrust/command-center")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Readiness Command Center already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_READINESS_COMMAND_CENTER_V1_ACTIVE
# ============================================================

@app.route("/citrust/readiness-command-center")
@app.route("/citrust/command-center")
def citrust_readiness_command_center():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Readiness Command Center</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <style>
            :root {
                --bg: #050d19;
                --line: rgba(255,255,255,0.12);
                --text: #eef5ff;
                --muted: #a9bdd6;
                --green: #31d07d;
                --yellow: #f7c948;
                --red: #ff5c70;
                --blue: #5cc8ff;
                --purple: #b49cff;
                --orange: #ffb86b;
            }

            body {
                margin: 0;
                font-family: Arial, Helvetica, sans-serif;
                background:
                    radial-gradient(circle at top left, rgba(92,200,255,0.18), transparent 30%),
                    radial-gradient(circle at top right, rgba(180,156,255,0.16), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(49,208,125,0.08), transparent 30%),
                    var(--bg);
                color: var(--text);
            }

            .page {
                max-width: 1420px;
                margin: 0 auto;
                padding: 28px;
            }

            .hero {
                border: 1px solid var(--line);
                background: linear-gradient(135deg, rgba(16,29,47,0.98), rgba(20,40,66,0.92));
                border-radius: 24px;
                padding: 28px;
                box-shadow: 0 22px 75px rgba(0,0,0,0.40);
            }

            .eyebrow {
                color: var(--blue);
                font-size: 13px;
                text-transform: uppercase;
                letter-spacing: 1.8px;
                font-weight: 800;
                margin-bottom: 10px;
            }

            h1 {
                margin: 0;
                font-size: 40px;
                line-height: 1.1;
            }

            .subtitle {
                color: var(--muted);
                font-size: 16px;
                line-height: 1.6;
                max-width: 1120px;
                margin-top: 14px;
            }

            .positioning {
                margin-top: 18px;
                padding: 16px 18px;
                border: 1px solid rgba(92,200,255,0.30);
                background: rgba(92,200,255,0.08);
                border-radius: 16px;
                color: #d9f3ff;
                line-height: 1.55;
            }

            .nav {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                margin-top: 22px;
            }

            .nav a {
                color: var(--text);
                text-decoration: none;
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.06);
                padding: 10px 13px;
                border-radius: 999px;
                font-size: 13px;
            }

            .nav a:hover {
                border-color: rgba(92,200,255,0.7);
                background: rgba(92,200,255,0.12);
            }

            .kpis {
                display: grid;
                grid-template-columns: repeat(6, 1fr);
                gap: 14px;
                margin-top: 20px;
            }

            .metric {
                border: 1px solid var(--line);
                background: rgba(16,29,47,0.9);
                border-radius: 18px;
                padding: 18px;
            }

            .metric .label {
                color: var(--muted);
                font-size: 13px;
                margin-bottom: 8px;
            }

            .metric .value {
                font-size: 30px;
                font-weight: 850;
            }

            .metric .note {
                margin-top: 8px;
                color: var(--muted);
                font-size: 12px;
                line-height: 1.4;
            }

            .section {
                margin-top: 24px;
                border: 1px solid var(--line);
                background: rgba(16,29,47,0.9);
                border-radius: 22px;
                padding: 22px;
            }

            .section h2 {
                margin: 0 0 8px 0;
                font-size: 22px;
            }

            .section p {
                color: var(--muted);
                line-height: 1.55;
                margin-top: 0;
            }

            .answer {
                border: 1px solid rgba(92,200,255,0.36);
                background: rgba(92,200,255,0.10);
                color: #d9f3ff;
                border-radius: 18px;
                padding: 20px;
                margin-top: 16px;
                line-height: 1.65;
                font-size: 15px;
            }

            .badge {
                display: inline-block;
                padding: 6px 9px;
                border-radius: 999px;
                font-size: 12px;
                font-weight: 800;
                white-space: nowrap;
            }

            .green { color: #05140b; background: var(--green); }
            .yellow { color: #1d1600; background: var(--yellow); }
            .red { color: #fff; background: var(--red); }
            .blue { color: #06101d; background: var(--blue); }
            .purple { color: #120b24; background: var(--purple); }
            .orange { color: #211100; background: var(--orange); }

            .module-grid {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 16px;
                margin-top: 16px;
            }

            .module-card {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 18px;
                min-height: 165px;
            }

            .module-card h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .module-card p {
                margin: 0 0 14px 0;
                color: var(--muted);
                font-size: 14px;
                line-height: 1.55;
            }

            .module-card a {
                color: #d9f3ff;
                text-decoration: none;
                border: 1px solid rgba(92,200,255,0.35);
                background: rgba(92,200,255,0.10);
                padding: 8px 10px;
                border-radius: 999px;
                font-size: 12px;
                display: inline-block;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                overflow: hidden;
                border-radius: 16px;
                margin-top: 16px;
            }

            th {
                text-align: left;
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 0.8px;
                color: #c9dbef;
                background: rgba(255,255,255,0.07);
                padding: 13px 12px;
                border-bottom: 1px solid var(--line);
            }

            td {
                padding: 13px 12px;
                border-bottom: 1px solid rgba(255,255,255,0.08);
                color: #e9f2ff;
                vertical-align: top;
                font-size: 14px;
            }

            tr:hover td {
                background: rgba(92,200,255,0.05);
            }

            .soft-green {
                color: #dfffea;
                background: rgba(49,208,125,0.16);
                border: 1px solid rgba(49,208,125,0.35);
            }

            .soft-yellow {
                color: #fff4cc;
                background: rgba(247,201,72,0.15);
                border: 1px solid rgba(247,201,72,0.38);
            }

            .soft-red {
                color: #ffe5e9;
                background: rgba(255,92,112,0.15);
                border: 1px solid rgba(255,92,112,0.38);
            }

            .soft-blue {
                color: #d9f3ff;
                background: rgba(92,200,255,0.12);
                border: 1px solid rgba(92,200,255,0.34);
            }

            .two-col {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 16px;
                margin-top: 16px;
            }

            .logic-box {
                border: 1px solid var(--line);
                border-radius: 18px;
                background: rgba(255,255,255,0.045);
                padding: 18px;
            }

            .logic-box h3 {
                margin: 0 0 10px 0;
                font-size: 17px;
            }

            .logic-box ul {
                margin: 0;
                padding-left: 20px;
                color: var(--muted);
                line-height: 1.7;
                font-size: 14px;
            }

            .footer {
                color: var(--muted);
                font-size: 12px;
                margin-top: 22px;
                line-height: 1.6;
            }

            @media (max-width: 1180px) {
                .kpis, .module-grid, .two-col {
                    grid-template-columns: 1fr;
                }

                h1 {
                    font-size: 30px;
                }

                table {
                    display: block;
                    overflow-x: auto;
                    white-space: nowrap;
                }
            }
        </style>
    </head>

    <body>
        <div class="page">

            <section class="hero">
                <div class="eyebrow">CITrust™ / ServiceNow / CMDB Governance Assurance</div>
                <h1>CITrust™ Readiness Command Center</h1>

                <div class="subtitle">
                    Unified CITrust™ command layer for answering the executive question: can this Configuration Item be operationally trusted across ownership, support group, MyAccess, lifecycle, evidence, dependency, classification, data quality, audit readiness, change impact, remediation, and ServiceNow-readiness?
                </div>

                <div class="positioning">
                    <strong>Command center boundary:</strong>
                    ServiceNow remains the system of record. CITrust™ is the governance assurance overlay. This command center does not create ServiceNow CIs, does not write directly into ServiceNow, and does not replace ServiceNow, CMDB governance, MyAccess, change management, or human approval.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/servicenow-ci-readiness">ServiceNow CI Readiness</a>
                    <a href="/ci-candidate-review">Candidate Review Board</a>
                    <a href="/ci-submission-pack">Submission Pack</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                    <a href="/citrust/executive-reasoning-panel">Executive Reasoning</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Total CI Population</div>
                    <div class="value">42</div>
                    <div class="note">ServiceNow-style records, candidates, assets, and operational dependencies.</div>
                </div>

                <div class="metric">
                    <div class="label">Trusted</div>
                    <div class="value" style="color: var(--green);">18</div>
                    <div class="note">Governed enough for operational reliance.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional</div>
                    <div class="value" style="color: var(--yellow);">15</div>
                    <div class="note">Requires remediation or confirmation.</div>
                </div>

                <div class="metric">
                    <div class="label">Blocked</div>
                    <div class="value" style="color: var(--red);">9</div>
                    <div class="note">Not ready for trust or submission.</div>
                </div>

                <div class="metric">
                    <div class="label">ServiceNow-Ready</div>
                    <div class="value" style="color: var(--blue);">5</div>
                    <div class="note">Ready for submission-pack preparation.</div>
                </div>

                <div class="metric">
                    <div class="label">Open Remediation</div>
                    <div class="value" style="color: var(--orange);">24</div>
                    <div class="note">Actions needed to unlock readiness.</div>
                </div>
            </section>

            <section class="section">
                <h2>Command Center Answer</h2>
                <p>
                    This command center consolidates the CITrust™ product into one leadership-ready readiness view.
                </p>

                <div class="answer">
                    <strong>Current executive interpretation:</strong>
                    The CI estate is partially trusted. A controlled subset can be operationally defended, but several records remain conditional or blocked due to evidence gaps, orphan exposure, incomplete MyAccess routing, unresolved lifecycle closure, partial support-group mapping, hidden dependencies, and data-quality issues. Leadership should rely only on trusted records while using the remediation board to move conditional and blocked records forward.
                </div>
            </section>

            <section class="section">
                <h2>CITrust™ Command Modules</h2>
                <p>
                    Use this as the main navigation layer after the product home.
                </p>

                <div class="module-grid">
                    <div class="module-card">
                        <h3>Executive Dashboard</h3>
                        <p>Leadership view of trusted, conditional, blocked, orphaned, and ServiceNow-ready records.</p>
                        <a href="/citrust/executive-dashboard">Open Dashboard</a>
                    </div>

                    <div class="module-card">
                        <h3>Executive Reasoning</h3>
                        <p>Explains why a CI is trusted, conditional, blocked, or not ServiceNow-ready.</p>
                        <a href="/citrust/executive-reasoning-panel">Open Reasoning</a>
                    </div>

                    <div class="module-card">
                        <h3>Trust Score Model</h3>
                        <p>Converts readiness domains into an explainable CI trust score.</p>
                        <a href="/citrust/trust-score-model">Open Scoring</a>
                    </div>

                    <div class="module-card">
                        <h3>Risk Heatmap</h3>
                        <p>Prioritizes CI governance risks across audit, access, support, evidence, lifecycle, and dependency.</p>
                        <a href="/citrust/risk-heatmap">Open Heatmap</a>
                    </div>

                    <div class="module-card">
                        <h3>Bottleneck Analysis</h3>
                        <p>Shows what is blocking CIs from becoming trusted, audit-ready, or ServiceNow-ready.</p>
                        <a href="/citrust/bottleneck-analysis">Open Bottlenecks</a>
                    </div>

                    <div class="module-card">
                        <h3>Remediation Board</h3>
                        <p>Turns CITrust™ findings into governed actions, owners, evidence needs, and target readiness states.</p>
                        <a href="/citrust/remediation-board">Open Remediation</a>
                    </div>

                    <div class="module-card">
                        <h3>MyAccess Readiness</h3>
                        <p>Validates access roles, approver paths, support routing, and owner alignment.</p>
                        <a href="/citrust/myaccess-readiness">Open MyAccess</a>
                    </div>

                    <div class="module-card">
                        <h3>Audit Readiness</h3>
                        <p>Tests whether CIs can survive audit questions about owner, support, SOP, evidence, and lifecycle.</p>
                        <a href="/citrust/audit-readiness">Open Audit Readiness</a>
                    </div>

                    <div class="module-card">
                        <h3>Evidence Lineage</h3>
                        <p>Validates whether CI fields are backed by SOP, backup, audit trail, closure, validation, or access evidence.</p>
                        <a href="/citrust/evidence-lineage">Open Evidence</a>
                    </div>

                    <div class="module-card">
                        <h3>Dependency Lineage</h3>
                        <p>Maps upstream, downstream, infrastructure, workstation, support, and access dependencies.</p>
                        <a href="/citrust/dependency-lineage">Open Dependencies</a>
                    </div>

                    <div class="module-card">
                        <h3>Lifecycle Readiness</h3>
                        <p>Validates LCM, active state, OOS closure, retirement, cutover, and lifecycle evidence.</p>
                        <a href="/citrust/lifecycle-readiness">Open Lifecycle</a>
                    </div>

                    <div class="module-card">
                        <h3>Data Quality</h3>
                        <p>Checks whether CI fields are complete, consistent, current, non-duplicated, and defensible.</p>
                        <a href="/citrust/data-quality-readiness">Open Data Quality</a>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Readiness Control Board</h2>
                <p>
                    This board shows the current state of major CI governance domains.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th>Current Status</th>
                            <th>Primary Weakness</th>
                            <th>Operational Impact</th>
                            <th>Next Command View</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Ownership / Support</strong></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Support group and escalation path gaps remain for several records.</td>
                            <td>Incident routing and accountability may be delayed.</td>
                            <td><a style="color:#d9f3ff;" href="/citrust/support-group-readiness">Support Routing</a></td>
                        </tr>

                        <tr>
                            <td><strong>MyAccess Routing</strong></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Approver groups and roles need confirmation for selected records.</td>
                            <td>Access approvals may rely on manual interpretation.</td>
                            <td><a style="color:#d9f3ff;" href="/citrust/myaccess-readiness">MyAccess Readiness</a></td>
                        </tr>

                        <tr>
                            <td><strong>Evidence Lineage</strong></td>
                            <td><span class="badge red">High Risk</span></td>
                            <td>Closure, SOP, backup, audit trail, and cutover evidence gaps remain.</td>
                            <td>Audit and inspection defensibility may be weak.</td>
                            <td><a style="color:#d9f3ff;" href="/citrust/evidence-lineage">Evidence Lineage</a></td>
                        </tr>

                        <tr>
                            <td><strong>Lifecycle State</strong></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>OOS, retired, and cutover records need closure or transition evidence.</td>
                            <td>Lifecycle ambiguity can create access and audit exposure.</td>
                            <td><a style="color:#d9f3ff;" href="/citrust/lifecycle-readiness">Lifecycle Readiness</a></td>
                        </tr>

                        <tr>
                            <td><strong>Data Quality</strong></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Partial records, possible duplicates, stale fields, and missing classification exist.</td>
                            <td>Weak data can create poor CMDB-readiness and support confusion.</td>
                            <td><a style="color:#d9f3ff;" href="/citrust/data-quality-readiness">Data Quality</a></td>
                        </tr>

                        <tr>
                            <td><strong>Remediation</strong></td>
                            <td><span class="badge orange">Active</span></td>
                            <td>Twenty-four actions remain open across evidence, ownership, access, and lifecycle.</td>
                            <td>Readiness will not improve without targeted action closure.</td>
                            <td><a style="color:#d9f3ff;" href="/citrust/remediation-board">Remediation Board</a></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Executive Decision Logic</h2>
                <p>
                    The command center keeps CITrust™ advisory and governance-first.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Leadership Can Trust</h3>
                        <ul>
                            <li>Records with clear owner, support group, LCM, MyAccess routing, lifecycle, evidence, and dependency lineage.</li>
                            <li>Records scored trusted by the trust score model and supported by evidence lineage.</li>
                            <li>Records that have passed candidate review and are ready for submission-pack preparation.</li>
                            <li>Records with defensible executive reasoning and no critical bottleneck.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Leadership Should Hold</h3>
                        <ul>
                            <li>Ownerless, supportless, or LCM-missing records.</li>
                            <li>Records with unresolved OOS, retired, or cutover state.</li>
                            <li>Records with missing access, backup, audit trail, SOP, closure, or validation evidence.</li>
                            <li>Records where submission would create weak or orphaned CMDB data.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, MyAccess, CMDB governance, change management, audit systems, or human approval. This readiness command center is a governance assurance overlay that connects CITrust™ modules for CI trust, ServiceNow-readiness, MyAccess readiness, evidence lineage, dependency lineage, lifecycle readiness, data quality, risk heatmap, bottleneck analysis, remediation, executive reasoning, audit readiness, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_READINESS_COMMAND_CENTER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Readiness Command Center installed.")
