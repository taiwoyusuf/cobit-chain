from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_EXCEPTION_REGISTER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/exception-register")'
ROUTE_ALIAS = '@app.route("/citrust/governance-exceptions")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Exception Register already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_EXCEPTION_REGISTER_V1_ACTIVE
# ============================================================

@app.route("/citrust/exception-register")
@app.route("/citrust/governance-exceptions")
def citrust_exception_register():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Governance Exception Register</title>
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
                    radial-gradient(circle at top left, rgba(247,201,72,0.16), transparent 30%),
                    radial-gradient(circle at top right, rgba(92,200,255,0.16), transparent 28%),
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
                border: 1px solid rgba(247,201,72,0.38);
                background: rgba(247,201,72,0.10);
                color: #fff4cc;
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
                <h1>CITrust™ Governance Exception Register</h1>

                <div class="subtitle">
                    Tracks conditional CI governance exceptions where a Configuration Item is not fully trusted, but may remain under controlled review with a named owner, documented risk, expiry condition, remediation path, and executive visibility.
                </div>

                <div class="positioning">
                    <strong>Exception boundary:</strong>
                    CITrust™ exceptions are not automatic approvals, not ServiceNow changes, and not permanent waivers. This register documents conditional governance risk so leadership can see why a CI is being carried temporarily and what must be remediated before full trust is granted.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                    <a href="/citrust/bottleneck-analysis">Bottleneck Analysis</a>
                    <a href="/citrust/executive-reasoning-panel">Executive Reasoning</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                    <a href="/citrust/pre-deviation-readiness">Pre-Deviation Readiness</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Open Exceptions</div>
                    <div class="value">11</div>
                    <div class="note">Conditional records being carried under governance visibility.</div>
                </div>

                <div class="metric">
                    <div class="label">Critical Exceptions</div>
                    <div class="value" style="color: var(--red);">3</div>
                    <div class="note">High-risk items requiring fast remediation or escalation.</div>
                </div>

                <div class="metric">
                    <div class="label">Access Exceptions</div>
                    <div class="value" style="color: var(--blue);">4</div>
                    <div class="note">MyAccess, approver, admin path, or vendor route exceptions.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Exceptions</div>
                    <div class="value" style="color: var(--orange);">5</div>
                    <div class="note">Missing or partial SOP, backup, audit trail, closure, or cutover evidence.</div>
                </div>

                <div class="metric">
                    <div class="label">Lifecycle Exceptions</div>
                    <div class="value" style="color: var(--yellow);">3</div>
                    <div class="note">OOS, retired, cutover, or transition-state exceptions.</div>
                </div>

                <div class="metric">
                    <div class="label">Ready to Close</div>
                    <div class="value" style="color: var(--green);">2</div>
                    <div class="note">Exceptions with remediation nearly complete.</div>
                </div>
            </section>

            <section class="section">
                <h2>Exception Register Answer</h2>
                <p>
                    This board answers which conditional CI risks are being accepted temporarily, why they exist, and what must happen before they are closed.
                </p>

                <div class="answer">
                    <strong>Current exception interpretation:</strong>
                    CITrust™ should allow conditional records only when the exception is documented, owned, time-bound, risk-rated, and linked to a remediation action. Any CI with missing owner, support group, LCM, access route, or evidence should remain blocked unless leadership accepts a controlled exception with a defined closure path.
                </div>
            </section>

            <section class="section">
                <h2>Governance Exception Register</h2>
                <p>
                    Each exception must have a reason, owner, risk level, remediation path, and closure condition.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>CI / Record</th>
                            <th>Exception Type</th>
                            <th>Reason</th>
                            <th>Risk Level</th>
                            <th>Exception Owner</th>
                            <th>Allowed State</th>
                            <th>Closure Condition</th>
                            <th>Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">Cutover-sensitive BMS dependency</span></td>
                            <td><span class="badge soft-yellow">Cutover Exception</span></td>
                            <td>Support routing, jump path, MyAccess role, and cutover evidence are still partial.</td>
                            <td><span class="badge orange">High</span></td>
                            <td>Infrastructure / MyAccess Governance</td>
                            <td>Conditional Watchlist</td>
                            <td>Confirm support group, role mapping, jump path evidence, and cutover evidence.</td>
                            <td><span class="badge yellow">Controlled Exception</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Admin and vendor access route</span></td>
                            <td><span class="badge soft-blue">Access Evidence Exception</span></td>
                            <td>Access model is known, but admin-access procedure evidence needs formal linkage.</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Infrastructure / Access Governance</td>
                            <td>Conditional</td>
                            <td>Attach admin or vendor access procedure evidence and support routing context.</td>
                            <td><span class="badge yellow">Controlled Exception</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-blue">MyAccess Exception</span></td>
                            <td>Approver group and role mapping require confirmation before full access-readiness.</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Application Governance / MyAccess Governance</td>
                            <td>Conditional</td>
                            <td>Confirm approver group, requestable role, and access evidence.</td>
                            <td><span class="badge yellow">Controlled Exception</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-yellow">Support Exception</span></td>
                            <td>Support group, evidence path, and data quality need reconciliation.</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Operational Owner / CMDB Governance</td>
                            <td>Conditional</td>
                            <td>Reconcile owner, support group, lifecycle state, and evidence path.</td>
                            <td><span class="badge yellow">Controlled Exception</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">Lifecycle Closure Exception</span></td>
                            <td>OOS closure, access deactivation, support ownership, and lifecycle evidence are not defensible.</td>
                            <td><span class="badge red">Critical</span></td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td>Blocked</td>
                            <td>Attach closure evidence, confirm access removal, and reconcile lifecycle owner.</td>
                            <td><span class="badge red">Do Not Accept Without Escalation</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Hidden Dependency Exception</span></td>
                            <td>Record lacks owner, support group, LCM, access mapping, classification, and evidence.</td>
                            <td><span class="badge red">Critical</span></td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td>Blocked</td>
                            <td>Create governed candidate and assign full accountability and evidence lineage.</td>
                            <td><span class="badge red">Do Not Accept Without Escalation</span></td>
                        </tr>

                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">No Active Exception</span></td>
                            <td>Record is sufficiently trusted with owner, support, evidence, and operational classification.</td>
                            <td><span class="badge green">Low</span></td>
                            <td>Application Governance</td>
                            <td>Trusted</td>
                            <td>Maintain periodic review.</td>
                            <td><span class="badge green">No Exception Needed</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Exception Governance Rules</h2>
                <p>
                    CITrust™ keeps exceptions controlled so weak records do not become silently trusted.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Named Owner Required</h3>
                        <p>Every exception must have an accountable owner. No exception should exist under anonymous or informal ownership.</p>
                    </div>

                    <div class="card">
                        <h3>Risk Must Be Visible</h3>
                        <p>The exception must state the operational, audit, access, support, lifecycle, or ServiceNow-readiness risk.</p>
                    </div>

                    <div class="card">
                        <h3>Closure Condition Required</h3>
                        <p>The register must define exactly what evidence or action closes the exception.</p>
                    </div>

                    <div class="card">
                        <h3>No Permanent Exception</h3>
                        <p>Conditional status is temporary. Any long-running exception should escalate to leadership review.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Exception Decision Logic</h2>
                <p>
                    Exceptions must never be used to hide an uncontrolled CI.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Accept Controlled Exception</h3>
                        <ul>
                            <li>CI has an accountable exception owner.</li>
                            <li>Risk is documented and understood.</li>
                            <li>Remediation action is defined.</li>
                            <li>Closure condition is measurable.</li>
                            <li>Exception does not hide a critical missing owner, support group, LCM, or access path.</li>
                            <li>Leadership can explain why the CI remains conditional.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Reject Exception</h3>
                        <ul>
                            <li>No owner, support group, LCM, or escalation path exists.</li>
                            <li>Access approval route cannot be defended.</li>
                            <li>Evidence is missing for a critical or audit-sensitive CI.</li>
                            <li>OOS or retired record lacks closure and access removal evidence.</li>
                            <li>Hidden dependency supports recurring operational review without governance.</li>
                            <li>Exception would turn a blocked record into an undocumented waiver.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Exception Closure Queue</h2>
                <p>
                    These actions close or downgrade active exceptions.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Exception</th>
                            <th>Closure Action</th>
                            <th>Evidence Needed</th>
                            <th>Expected Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation</td>
                            <td>Create governed candidate and assign owner, support group, LCM, access route, and evidence path.</td>
                            <td>Backup review evidence, ownership, support group, LCM, access mapping.</td>
                            <td>Blocked → Conditional</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment closure gap</td>
                            <td>Attach closure evidence and confirm access deactivation.</td>
                            <td>Closure record, access removal proof, lifecycle owner confirmation.</td>
                            <td>Blocked → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover exception</td>
                            <td>Finalize support group, MyAccess role, jump path, and cutover evidence.</td>
                            <td>Support confirmation, role mapping, jump path evidence, cutover evidence.</td>
                            <td>Conditional → Trusted</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access approver confirmation</td>
                            <td>Confirm approver group and access role evidence.</td>
                            <td>MyAccess role and approver evidence.</td>
                            <td>Conditional → Access-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow exceptions, create ServiceNow CIs, update CMDB records, or approve waivers in this demo. This governance exception register is a CITrust™ assurance overlay for documenting conditional CI risk, controlled exceptions, remediation ownership, closure evidence, audit defensibility, ServiceNow-readiness, MyAccess-readiness, lifecycle readiness, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_EXCEPTION_REGISTER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Exception Register installed.")
