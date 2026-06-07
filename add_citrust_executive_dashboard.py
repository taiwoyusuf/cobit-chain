from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_EXECUTIVE_DASHBOARD_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/executive-dashboard")'
ROUTE_ALIAS = '@app.route("/citrust/executive-view")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Executive Dashboard already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_EXECUTIVE_DASHBOARD_V1_ACTIVE
# ============================================================

@app.route("/citrust/executive-dashboard")
@app.route("/citrust/executive-view")
def citrust_executive_dashboard():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Executive Dashboard</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <style>
            :root {
                --bg: #050d19;
                --panel: #101d2f;
                --panel2: #142842;
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
                    radial-gradient(circle at top right, rgba(180,156,255,0.15), transparent 28%),
                    radial-gradient(circle at bottom left, rgba(49,208,125,0.08), transparent 30%),
                    var(--bg);
                color: var(--text);
            }

            .page {
                max-width: 1400px;
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
                font-size: 39px;
                line-height: 1.1;
            }

            .subtitle {
                color: var(--muted);
                font-size: 16px;
                line-height: 1.6;
                max-width: 1080px;
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

            .badge {
                display: inline-block;
                padding: 6px 9px;
                border-radius: 999px;
                font-size: 12px;
                font-weight: 800;
                white-space: nowrap;
            }

            .green {
                color: #05140b;
                background: var(--green);
            }

            .yellow {
                color: #1d1600;
                background: var(--yellow);
            }

            .red {
                color: #fff;
                background: var(--red);
            }

            .blue {
                color: #06101d;
                background: var(--blue);
            }

            .purple {
                color: #120b24;
                background: var(--purple);
            }

            .orange {
                color: #211100;
                background: var(--orange);
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

            .exec-grid {
                display: grid;
                grid-template-columns: 1.1fr 0.9fr;
                gap: 16px;
                margin-top: 16px;
            }

            .decision-card {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 18px;
            }

            .decision-card h3 {
                margin: 0 0 10px 0;
                font-size: 18px;
            }

            .decision-card p {
                margin: 0;
                color: var(--muted);
                font-size: 14px;
                line-height: 1.55;
            }

            .answer {
                border: 1px solid rgba(49,208,125,0.36);
                background: rgba(49,208,125,0.10);
                color: #dfffea;
                border-radius: 18px;
                padding: 20px;
                margin-top: 16px;
                line-height: 1.65;
                font-size: 15px;
            }

            .heatmap {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 14px;
                margin-top: 16px;
            }

            .heat-card {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 18px;
            }

            .heat-card h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .heat-card p {
                margin: 0;
                color: var(--muted);
                font-size: 14px;
                line-height: 1.55;
            }

            .bar-wrap {
                margin-top: 10px;
                height: 9px;
                background: rgba(255,255,255,0.09);
                border-radius: 99px;
                overflow: hidden;
            }

            .bar {
                height: 9px;
                border-radius: 99px;
            }

            .bar.greenbar {
                width: 82%;
                background: var(--green);
            }

            .bar.yellowbar {
                width: 61%;
                background: var(--yellow);
            }

            .bar.redbar {
                width: 38%;
                background: var(--red);
            }

            .bar.bluebar {
                width: 74%;
                background: var(--blue);
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
                .kpis, .exec-grid, .heatmap, .two-col {
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
                <h1>CITrust™ Executive Dashboard</h1>

                <div class="subtitle">
                    Executive command view for answering whether Configuration Items can be operationally trusted across ownership, support group, LCM assignment, MyAccess routing, evidence lineage, CMDB-readiness, orphan exposure, and audit defensibility.
                </div>

                <div class="positioning">
                    <strong>Product boundary:</strong>
                    ServiceNow remains the system of record. CITrust™ is the governance assurance overlay that evaluates whether ServiceNow-style records, CI candidates, and operational asset references are trustworthy before leadership relies on them for access routing, support routing, audit response, and operational readiness.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/servicenow-ci-readiness">ServiceNow CI Readiness</a>
                    <a href="/citrust/myaccess-readiness">MyAccess Readiness</a>
                    <a href="/citrust/reconciliation">CMDB Reconciliation</a>
                    <a href="/citrust/submission-board">Submission Board</a>
                    <a href="/ci-candidate-review">Candidate Review Board</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                    <a href="/citrust/orphans">Orphan CI Intelligence</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Total CI Population</div>
                    <div class="value">42</div>
                    <div class="note">ServiceNow-style records, candidates, master list records, and asset references.</div>
                </div>

                <div class="metric">
                    <div class="label">Operationally Trusted</div>
                    <div class="value" style="color: var(--green);">18</div>
                    <div class="note">Owner, support, access, lifecycle, and evidence are defensible.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Trust</div>
                    <div class="value" style="color: var(--yellow);">14</div>
                    <div class="note">Usable only with documented remediation or governance exception.</div>
                </div>

                <div class="metric">
                    <div class="label">Blocked / Not Trusted</div>
                    <div class="value" style="color: var(--red);">7</div>
                    <div class="note">Core governance gaps prevent operational reliance.</div>
                </div>

                <div class="metric">
                    <div class="label">ServiceNow-Ready</div>
                    <div class="value" style="color: var(--blue);">5</div>
                    <div class="note">Ready for controlled submission-pack preparation.</div>
                </div>

                <div class="metric">
                    <div class="label">Orphan Exposure</div>
                    <div class="value" style="color: var(--orange);">8</div>
                    <div class="note">Missing or unclear owner, support group, LCM, evidence, or access mapping.</div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Answer</h2>
                <p>
                    This section converts CI governance details into a leadership-ready readiness statement.
                </p>

                <div class="answer">
                    <strong>Current executive interpretation:</strong>
                    The CI estate is partially trusted. A controlled subset is ready for ServiceNow-style submission and operational reliance, but several records remain conditional or blocked due to missing support group mapping, unclear lifecycle accountability, incomplete MyAccess routing, missing closure evidence, or disconnected evidence lineage.
                </div>

                <div class="exec-grid">
                    <div class="decision-card">
                        <h3>Can leadership trust the CI estate today?</h3>
                        <p>
                            Leadership can trust only the reconciled and evidence-backed portion of the CI population. Conditional and blocked records should remain under governance review until ownership, support routing, LCM, MyAccess mapping, and evidence lineage are complete.
                        </p>
                    </div>

                    <div class="decision-card">
                        <h3>What is the primary business risk?</h3>
                        <p>
                            The main risk is not whether a record exists. The risk is whether the record can support access approvals, incident routing, audit response, lifecycle decisions, and pre-deviation readiness without relying on tribal knowledge.
                        </p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Risk Heatmap</h2>
                <p>
                    CITrust™ highlights the governance domains most likely to create access failures, orphan records, audit weakness, incident-routing confusion, or ServiceNow-readiness defects.
                </p>

                <div class="heatmap">
                    <div class="heat-card">
                        <h3>Ownership Trust</h3>
                        <span class="badge green">82%</span>
                        <p>Most key records have an owner, but legacy and operationally discovered assets still need confirmation.</p>
                        <div class="bar-wrap"><div class="bar greenbar"></div></div>
                    </div>

                    <div class="heat-card">
                        <h3>Support Group Trust</h3>
                        <span class="badge yellow">61%</span>
                        <p>Support routing is partially mapped, but several candidates still require final operational support-group confirmation.</p>
                        <div class="bar-wrap"><div class="bar yellowbar"></div></div>
                    </div>

                    <div class="heat-card">
                        <h3>Evidence Lineage</h3>
                        <span class="badge red">38%</span>
                        <p>Evidence is the weakest domain. Closure evidence, SOP linkage, validation references, and review artifacts remain incomplete for multiple records.</p>
                        <div class="bar-wrap"><div class="bar redbar"></div></div>
                    </div>

                    <div class="heat-card">
                        <h3>Access Routing Trust</h3>
                        <span class="badge blue">74%</span>
                        <p>MyAccess routing is improving, but approver groups and role mapping still need confirmation for conditional records.</p>
                        <div class="bar-wrap"><div class="bar bluebar"></div></div>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Leadership Readiness Board</h2>
                <p>
                    This board shows which CI groups are ready, conditional, or blocked from operational trust.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>CI Group</th>
                            <th>Total</th>
                            <th>Trusted</th>
                            <th>Conditional</th>
                            <th>Blocked</th>
                            <th>ServiceNow-Ready</th>
                            <th>Main Gap</th>
                            <th>Executive Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>GMP Applications</strong><br><span style="color: var(--muted);">Blue Mountain, Empower, Chromeleon dependencies</span></td>
                            <td>9</td>
                            <td><span class="badge soft-green">5</span></td>
                            <td><span class="badge soft-yellow">3</span></td>
                            <td><span class="badge soft-red">1</span></td>
                            <td><span class="badge blue">2</span></td>
                            <td>Approver group and role mapping evidence</td>
                            <td><span class="badge yellow">Controlled Review</span></td>
                        </tr>

                        <tr>
                            <td><strong>Manufacturing Equipment</strong><br><span style="color: var(--muted);">Speedy Glove and operational equipment records</span></td>
                            <td>12</td>
                            <td><span class="badge soft-green">4</span></td>
                            <td><span class="badge soft-yellow">5</span></td>
                            <td><span class="badge soft-red">3</span></td>
                            <td><span class="badge blue">1</span></td>
                            <td>Lifecycle closure, support group, and evidence gaps</td>
                            <td><span class="badge red">Remediation Needed</span></td>
                        </tr>

                        <tr>
                            <td><strong>Infrastructure Dependencies</strong><br><span style="color: var(--muted);">Jump server, access paths, local servers, workstations</span></td>
                            <td>11</td>
                            <td><span class="badge soft-green">6</span></td>
                            <td><span class="badge soft-yellow">3</span></td>
                            <td><span class="badge soft-red">2</span></td>
                            <td><span class="badge blue">2</span></td>
                            <td>Owner and support-routing consistency</td>
                            <td><span class="badge yellow">Targeted Cleanup</span></td>
                        </tr>

                        <tr>
                            <td><strong>Candidate Intake Queue</strong><br><span style="color: var(--muted);">Planner, Excel, master list, and discovered candidates</span></td>
                            <td>10</td>
                            <td><span class="badge soft-green">3</span></td>
                            <td><span class="badge soft-yellow">3</span></td>
                            <td><span class="badge soft-red">1</span></td>
                            <td><span class="badge blue">0</span></td>
                            <td>Candidate review not complete</td>
                            <td><span class="badge yellow">Keep in Review</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Executive Exceptions Requiring Action</h2>
                <p>
                    These items prevent leadership from defending full CMDB-readiness.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Exception</th>
                            <th>Business Impact</th>
                            <th>Required Action</th>
                            <th>Target Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Out-of-service equipment still lacks complete closure evidence.</td>
                            <td>Access, lifecycle, and audit questions may remain unresolved.</td>
                            <td>Attach closure evidence and confirm access deactivation.</td>
                            <td>Remove orphan exposure.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Operationally discovered workstation lacks owner, LCM, and evidence lineage.</td>
                            <td>Backup review and operational support activities may not route correctly.</td>
                            <td>Create candidate record and route through review board.</td>
                            <td>Convert unknown asset into governed candidate.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Some MyAccess approver paths are only partially mapped.</td>
                            <td>Access approvals may rely on manual interpretation.</td>
                            <td>Confirm approver group and role mapping.</td>
                            <td>Improve access-routing defensibility.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Support group mapping is inconsistent across some records.</td>
                            <td>Incident routing and support accountability may be delayed.</td>
                            <td>Reconcile support group against ServiceNow-style record and operational owner.</td>
                            <td>Improve operational continuity.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>What Leadership Should Ask Next</h2>
                <p>
                    This converts the dashboard into executive governance questions.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Trust Questions</h3>
                        <ul>
                            <li>Which CIs are trusted enough for operational reliance today?</li>
                            <li>Which CIs are only conditionally trusted?</li>
                            <li>Which CIs should remain blocked from ServiceNow-style submission?</li>
                            <li>Which records lack owner, support group, LCM, MyAccess mapping, or evidence?</li>
                            <li>Which records could create audit, access, incident, or pre-deviation risk?</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Decision Questions</h3>
                        <ul>
                            <li>Who owns remediation for each blocked CI?</li>
                            <li>Which support groups must be confirmed before cutover or operational reliance?</li>
                            <li>Which candidates should move to the submission pack?</li>
                            <li>Which records need leadership escalation?</li>
                            <li>Which evidence gaps must be closed before audit readiness can be defended?</li>
                        </ul>
                    </div>
                </div>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, or write directly into ServiceNow in this demo. This executive dashboard is a governance assurance overlay for CI trust, CMDB-readiness, orphan exposure, MyAccess routing readiness, evidence lineage, operational readiness, and audit defensibility.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_EXECUTIVE_DASHBOARD_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Executive Dashboard installed.")
