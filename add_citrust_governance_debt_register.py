from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_GOVERNANCE_DEBT_REGISTER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/governance-debt-register")'
ROUTE_ALIAS = '@app.route("/citrust/governance-debt")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Governance Debt Register already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_GOVERNANCE_DEBT_REGISTER_V1_ACTIVE
# ============================================================

@app.route("/citrust/governance-debt-register")
@app.route("/citrust/governance-debt")
def citrust_governance_debt_register():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Governance Debt Register</title>
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
                    radial-gradient(circle at top left, rgba(255,92,112,0.15), transparent 30%),
                    radial-gradient(circle at top right, rgba(92,200,255,0.16), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(247,201,72,0.08), transparent 30%),
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
                border: 1px solid rgba(255,92,112,0.38);
                background: rgba(255,92,112,0.10);
                color: #ffe5e9;
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

            .cards {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 16px;
                margin-top: 16px;
            }

            .card {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 18px;
            }

            .card h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .card p {
                margin: 0;
                color: var(--muted);
                font-size: 14px;
                line-height: 1.55;
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
                .kpis, .cards, .two-col {
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
                <h1>CITrust™ Governance Debt Register</h1>

                <div class="subtitle">
                    Tracks accumulated CI governance debt across unresolved owner gaps, support group gaps, LCM gaps, MyAccess mapping gaps, evidence debt, lifecycle debt, stale review debt, relationship debt, data-quality debt, and ServiceNow-readiness blockers.
                </div>

                <div class="positioning">
                    <strong>Governance debt boundary:</strong>
                    CITrust™ does not create ServiceNow CIs, does not update CMDB records, and does not replace ServiceNow governance. This register shows where unresolved CI governance gaps are accumulating over time and weakening operational trust.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/governance-cadence">Governance Cadence</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                    <a href="/citrust/bottleneck-analysis">Bottleneck Analysis</a>
                    <a href="/citrust/exception-register">Exception Register</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Total Governance Debt</div>
                    <div class="value">37</div>
                    <div class="note">Open unresolved governance gaps across the CI estate.</div>
                </div>

                <div class="metric">
                    <div class="label">Critical Debt</div>
                    <div class="value" style="color: var(--red);">9</div>
                    <div class="note">Debt that blocks trust, audit readiness, access readiness, or submission.</div>
                </div>

                <div class="metric">
                    <div class="label">Aging Debt</div>
                    <div class="value" style="color: var(--orange);">12</div>
                    <div class="note">Items open long enough to create governance drift.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Debt</div>
                    <div class="value" style="color: var(--yellow);">13</div>
                    <div class="note">Missing SOP, backup, audit trail, closure, access, or cutover evidence.</div>
                </div>

                <div class="metric">
                    <div class="label">Ownership Debt</div>
                    <div class="value" style="color: var(--blue);">8</div>
                    <div class="note">Missing owner, support group, LCM, or escalation accountability.</div>
                </div>

                <div class="metric">
                    <div class="label">Debt Burn-Down Ready</div>
                    <div class="value" style="color: var(--green);">14</div>
                    <div class="note">Items that can be cleared with targeted remediation.</div>
                </div>
            </section>

            <section class="section">
                <h2>Governance Debt Answer</h2>
                <p>
                    This register answers how much unresolved CI governance work is accumulating and what it is doing to operational trust.
                </p>

                <div class="answer">
                    <strong>Current governance debt interpretation:</strong>
                    The largest CITrust™ debt is concentrated in evidence gaps, hidden operational dependencies, OOS lifecycle closure, support group confirmation, MyAccess role mapping, and stale cadence reviews. Debt should not be treated as harmless backlog because it directly weakens ServiceNow-readiness, audit-readiness, access-readiness, and executive trust.
                </div>
            </section>

            <section class="section">
                <h2>Governance Debt Register</h2>
                <p>
                    Each debt item must have a debt type, age, owner, risk level, and retirement condition.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>CI / Record</th>
                            <th>Debt Type</th>
                            <th>Debt Description</th>
                            <th>Age Band</th>
                            <th>Debt Owner</th>
                            <th>Risk Level</th>
                            <th>Retirement Condition</th>
                            <th>Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge red">Hidden Dependency Debt</span></td>
                            <td>No governed CI identity, owner, support group, LCM, access route, or evidence path.</td>
                            <td>Open / Aging</td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td><span class="badge red">Critical</span></td>
                            <td>Create governed candidate and populate mandatory fields.</td>
                            <td><span class="badge red">Burn Down First</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge red">Lifecycle Debt</span></td>
                            <td>OOS closure, access deactivation, support ownership, and lifecycle evidence are not defensible.</td>
                            <td>Overdue</td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td><span class="badge red">Critical</span></td>
                            <td>Attach closure evidence and confirm access removal.</td>
                            <td><span class="badge red">Burn Down First</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">Cutover-sensitive BMS dependency</span></td>
                            <td><span class="badge orange">Cutover Debt</span></td>
                            <td>Support group, MyAccess role, jump path, and cutover evidence remain partial.</td>
                            <td>Active Cutover</td>
                            <td>Infrastructure / MyAccess Governance</td>
                            <td><span class="badge orange">High</span></td>
                            <td>Finalize support routing, role mapping, jump path, and cutover evidence.</td>
                            <td><span class="badge yellow">Controlled Burn-Down</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge yellow">Access Evidence Debt</span></td>
                            <td>Access model is known but formal admin/vendor access procedure evidence should be linked.</td>
                            <td>Due Soon</td>
                            <td>Infrastructure / Access Governance</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Attach admin or vendor access procedure evidence.</td>
                            <td><span class="badge yellow">Remediate</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge yellow">Support / Evidence Debt</span></td>
                            <td>Support group, evidence path, and operational classification need reconciliation.</td>
                            <td>Open</td>
                            <td>Operational Owner / CMDB Governance</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Reconcile owner, support group, lifecycle, and evidence path.</td>
                            <td><span class="badge yellow">Remediate</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge yellow">Access Confirmation Debt</span></td>
                            <td>Approver group and role mapping evidence need confirmation.</td>
                            <td>Due Soon</td>
                            <td>Application Governance / MyAccess Governance</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Confirm approver group and access role evidence.</td>
                            <td><span class="badge yellow">Remediate</span></td>
                        </tr>

                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge green">No Material Debt</span></td>
                            <td>Owner, support group, access, lifecycle, evidence, and classification are sufficiently governed.</td>
                            <td>Current</td>
                            <td>Application Governance</td>
                            <td><span class="badge green">Low</span></td>
                            <td>Maintain periodic review.</td>
                            <td><span class="badge green">Monitor</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Governance Debt Types</h2>
                <p>
                    CITrust™ separates debt into categories so teams know what must be burned down first.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Ownership Debt</h3>
                        <p>Missing or stale CI owner, support group, LCM, or escalation path creates accountability debt.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Debt</h3>
                        <p>Missing SOP, backup, audit trail, validation, closure, access, or cutover evidence weakens audit readiness.</p>
                    </div>

                    <div class="card">
                        <h3>Lifecycle Debt</h3>
                        <p>Unresolved active, OOS, retired, cutover, or closed state creates lifecycle ambiguity.</p>
                    </div>

                    <div class="card">
                        <h3>Access Debt</h3>
                        <p>Unconfirmed MyAccess roles, approver groups, admin paths, or vendor routes weaken access governance.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Governance Debt Decision Logic</h2>
                <p>
                    Governance debt should be actively retired, not normalized.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Debt Can Be Carried Temporarily</h3>
                        <ul>
                            <li>Debt has a named owner.</li>
                            <li>Risk is documented and visible.</li>
                            <li>Remediation path is clear.</li>
                            <li>Closure condition is measurable.</li>
                            <li>Decision is recorded in the decision ledger.</li>
                            <li>Exception is time-bound if trust is being carried conditionally.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Debt Must Be Burned Down</h3>
                        <ul>
                            <li>No owner, support group, LCM, or access route exists.</li>
                            <li>Evidence is missing for audit-sensitive or operationally critical CI.</li>
                            <li>OOS or retired state lacks closure and access removal evidence.</li>
                            <li>Hidden dependency supports recurring operational work.</li>
                            <li>Debt is aging without remediation movement.</li>
                            <li>Debt blocks ServiceNow-readiness or executive trust.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Governance Debt Burn-Down Queue</h2>
                <p>
                    These items should be retired first because they create the greatest trust exposure.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Debt Item</th>
                            <th>Why It Matters</th>
                            <th>Burn-Down Action</th>
                            <th>Expected Readiness Upgrade</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation</td>
                            <td>Operational review dependency exists without governed CI accountability.</td>
                            <td>Create governed candidate and assign owner, support, LCM, access, and evidence.</td>
                            <td>Blocked → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS closure debt</td>
                            <td>Unclosed OOS record creates lifecycle, access, and audit ambiguity.</td>
                            <td>Attach closure evidence and confirm access removal.</td>
                            <td>Blocked → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover governance debt</td>
                            <td>Cutover-sensitive system needs support, access, jump path, and evidence closure.</td>
                            <td>Finalize support group, MyAccess role, jump path, and cutover evidence.</td>
                            <td>Conditional → Trusted</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access procedure evidence debt</td>
                            <td>Admin and vendor access route must be defensible during audit or review.</td>
                            <td>Attach admin/vendor access procedure and support routing evidence.</td>
                            <td>Conditional → Audit-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, update CMDB records, or close governance debt automatically in this demo. This governance debt register is an assurance overlay for tracking unresolved CI ownership debt, support debt, MyAccess debt, lifecycle debt, evidence debt, relationship debt, data-quality debt, stale-review debt, ServiceNow-readiness blockers, audit-readiness exposure, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_GOVERNANCE_DEBT_REGISTER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Governance Debt Register installed.")
