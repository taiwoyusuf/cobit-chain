from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_ESCALATION_PATH_CONSOLE_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/escalation-path-console")'
ROUTE_ALIAS = '@app.route("/citrust/ci-escalation-map")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Escalation Path Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_ESCALATION_PATH_CONSOLE_V1_ACTIVE
# ============================================================

@app.route("/citrust/escalation-path-console")
@app.route("/citrust/ci-escalation-map")
def citrust_escalation_path_console():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Escalation Path Console</title>
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
                    radial-gradient(circle at bottom right, rgba(255,92,112,0.08), transparent 30%),
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
                min-height: 145px;
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
                <h1>CITrust™ Escalation Path Console</h1>

                <div class="subtitle">
                    Validates whether each Configuration Item has a clear escalation chain across CI owner, support group, LCM, MyAccess approver, infrastructure owner, governance reviewer, exception owner, and executive escalation path.
                </div>

                <div class="positioning">
                    <strong>Escalation boundary:</strong>
                    CITrust™ does not create ServiceNow tasks, update CMDB records, assign support groups, or approve access in this demo. It validates whether escalation accountability is complete enough for operational trust, audit defense, incident routing, lifecycle governance, and ServiceNow-style readiness.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/ownership-readiness">Ownership Readiness</a>
                    <a href="/citrust/lcm-assignment-console">LCM Assignment</a>
                    <a href="/citrust/myaccess-readiness">MyAccess Readiness</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                    <a href="/citrust/audit-question-bank">Audit Question Bank</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Escalation-Relevant CIs</div>
                    <div class="value">42</div>
                    <div class="note">Records requiring escalation chain validation.</div>
                </div>

                <div class="metric">
                    <div class="label">Complete Escalation</div>
                    <div class="value" style="color: var(--green);">17</div>
                    <div class="note">CIs with owner, support, LCM, access, and governance escalation mapped.</div>
                </div>

                <div class="metric">
                    <div class="label">Partial Escalation</div>
                    <div class="value" style="color: var(--yellow);">16</div>
                    <div class="note">CIs with known but incomplete escalation coverage.</div>
                </div>

                <div class="metric">
                    <div class="label">Missing Escalation</div>
                    <div class="value" style="color: var(--red);">9</div>
                    <div class="note">Records with escalation gaps that weaken support or audit defense.</div>
                </div>

                <div class="metric">
                    <div class="label">Access Escalation Gaps</div>
                    <div class="value" style="color: var(--orange);">7</div>
                    <div class="note">CIs where MyAccess, admin path, or vendor route escalation is unclear.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Escalations</div>
                    <div class="value" style="color: var(--blue);">4</div>
                    <div class="note">Items requiring leadership visibility due to blocked or aging risk.</div>
                </div>
            </section>

            <section class="section">
                <h2>Escalation Path Answer</h2>
                <p>
                    This console answers who must act when the CI has an operational, access, lifecycle, audit, support, or readiness issue.
                </p>

                <div class="answer">
                    <strong>Current escalation interpretation:</strong>
                    CITrust™ should not allow a CI to be treated as trusted unless the escalation path is clear. A record may have an owner, but if support group, LCM, MyAccess approver, exception owner, or executive escalation path is unclear, the CI remains conditional because operational issues may not route to the right accountable party.
                </div>
            </section>

            <section class="section">
                <h2>Escalation Control Domains</h2>
                <p>
                    CITrust™ separates escalation readiness into the domains that determine whether a CI issue can be handled defensibly.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Operational Escalation</h3>
                        <p>Confirms CI owner, support group, incident path, request path, and escalation group are clear and usable.</p>
                    </div>

                    <div class="card">
                        <h3>Lifecycle Escalation</h3>
                        <p>Confirms LCM, backup LCM, OOS owner, retirement owner, closure owner, and cutover owner are identified.</p>
                    </div>

                    <div class="card">
                        <h3>Access Escalation</h3>
                        <p>Confirms MyAccess approver, admin access owner, vendor access owner, and access review escalation path.</p>
                    </div>

                    <div class="card">
                        <h3>Governance Escalation</h3>
                        <p>Confirms exception owner, remediation owner, decision owner, governance reviewer, and executive escalation path.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Escalation Path Matrix</h2>
                <p>
                    This matrix shows whether each CI can route issues to the right accountable party.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>CI Owner</th>
                            <th>Support Group</th>
                            <th>LCM / Backup</th>
                            <th>MyAccess / Access Escalation</th>
                            <th>Governance Escalation</th>
                            <th>Escalation Decision</th>
                            <th>Next Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Defined</span></td>
                            <td><span class="badge green">Escalation-Ready</span></td>
                            <td>Maintain periodic escalation review.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">Cutover-sensitive BMS dependency</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Needs Confirmation</span></td>
                            <td><span class="badge soft-yellow">Backup Pending</span></td>
                            <td><span class="badge soft-yellow">Role / Jump Path Partial</span></td>
                            <td><span class="badge soft-yellow">Cutover Watchlist</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Finalize support group, backup LCM, MyAccess role, jump path, and cutover escalation.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-yellow">Backup Recommended</span></td>
                            <td><span class="badge soft-yellow">Procedure Evidence Needed</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td><span class="badge yellow">Access Escalation Conditional</span></td>
                            <td>Attach admin/vendor access procedure and define backup escalation owner.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-yellow">Likely / Backup Pending</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Reconcile support group, LCM, access route, and escalation owner.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Defined</span></td>
                            <td><span class="badge yellow">Near Escalation-Ready</span></td>
                            <td>Confirm MyAccess approver group and access escalation evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Closure Owner Missing</span></td>
                            <td><span class="badge soft-red">Access Removal Unclear</span></td>
                            <td><span class="badge soft-red">Escalate</span></td>
                            <td><span class="badge red">Escalation Blocked</span></td>
                            <td>Assign closure owner, confirm support path, attach closure evidence, and confirm access removal.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Escalate</span></td>
                            <td><span class="badge red">No Escalation Chain</span></td>
                            <td>Create governed candidate and assign full escalation path.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Escalation Readiness Decision Logic</h2>
                <p>
                    A CI escalation chain must be actionable, not just named informally.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Escalation-Ready CI</h3>
                        <ul>
                            <li>CI owner is confirmed.</li>
                            <li>Support group is routable and current.</li>
                            <li>LCM and backup lifecycle accountability are defined.</li>
                            <li>MyAccess or access escalation path is mapped.</li>
                            <li>Exception and remediation owner are known when gaps exist.</li>
                            <li>Executive escalation path is defined for critical risk.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Escalation-Blocked CI</h3>
                        <ul>
                            <li>No clear owner or support group exists.</li>
                            <li>LCM or closure owner is missing.</li>
                            <li>Access approval or access removal escalation is unclear.</li>
                            <li>Hidden dependency has no candidate owner.</li>
                            <li>OOS or retired record lacks closure accountability.</li>
                            <li>Issue would stall because no accountable path is defined.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Escalation Remediation Queue</h2>
                <p>
                    These actions close escalation gaps before a CI is treated as operationally trusted.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Escalation Gap</th>
                            <th>Why It Matters</th>
                            <th>Required Action</th>
                            <th>Expected Readiness Upgrade</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no escalation chain.</td>
                            <td>Operational dependency may fail or be questioned with no accountable owner.</td>
                            <td>Create governed candidate and assign owner, support group, LCM, access owner, and governance reviewer.</td>
                            <td>No Escalation Chain → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment lacks closure and access removal escalation.</td>
                            <td>Lifecycle and access risk cannot be closed without accountable escalation.</td>
                            <td>Assign closure owner, confirm access removal owner, and attach closure evidence.</td>
                            <td>Escalation Blocked → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover escalation is partial.</td>
                            <td>Cutover issues require immediate support, access, LCM, and governance routing.</td>
                            <td>Confirm support group, backup LCM, MyAccess approver, jump path owner, and cutover escalation owner.</td>
                            <td>Conditional → Escalation-Ready</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access-path escalation evidence is incomplete.</td>
                            <td>Admin and vendor access issues require clear escalation and evidence.</td>
                            <td>Attach admin/vendor procedure and define access escalation owner.</td>
                            <td>Access Conditional → Audit-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, update CMDB ownership fields, assign support groups, approve access, or create escalation tasks in this demo. This escalation path console is a governance assurance overlay for CI owner escalation, support group escalation, LCM escalation, MyAccess escalation, access-removal escalation, exception escalation, remediation escalation, executive escalation, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_ESCALATION_PATH_CONSOLE_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Escalation Path Console installed.")
