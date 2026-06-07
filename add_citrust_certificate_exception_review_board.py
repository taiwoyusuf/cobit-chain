from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CERTIFICATE_EXCEPTION_REVIEW_BOARD_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/certificate-exception-review-board")'
ROUTE_ALIAS = '@app.route("/citrust/certificate-exceptions")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Certificate Exception Review Board already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CERTIFICATE_EXCEPTION_REVIEW_BOARD_V1_ACTIVE
# ============================================================

@app.route("/citrust/certificate-exception-review-board")
@app.route("/citrust/certificate-exceptions")
def citrust_certificate_exception_review_board():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Certificate Exception Review Board</title>
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
                    radial-gradient(circle at top left, rgba(255,184,107,0.16), transparent 30%),
                    radial-gradient(circle at top right, rgba(92,200,255,0.15), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(180,156,255,0.10), transparent 30%),
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
                border: 1px solid rgba(255,184,107,0.38);
                background: rgba(255,184,107,0.10);
                color: #ffe8c9;
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
                <h1>CITrust™ Certificate Exception Review Board</h1>

                <div class="subtitle">
                    Governs certificate exceptions by determining whether a CI can remain conditionally trusted while a known evidence, access, support, lifecycle, ownership, or lineage gap is under controlled remediation.
                </div>

                <div class="positioning">
                    <strong>Exception boundary:</strong>
                    CITrust™ does not approve production risk, update ServiceNow, create legal certifications, or replace human governance. This board documents whether a certificate exception is justified, time-bound, evidence-backed, owner-accepted, and safe enough to remain conditional rather than suspended.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/certificate-lifecycle-command-center">Certificate Command Center</a>
                    <a href="/citrust/trust-certificate-registry">Certificate Registry</a>
                    <a href="/citrust/certificate-suspension-center">Suspension Center</a>
                    <a href="/citrust/certificate-renewal-workbench">Renewal Workbench</a>
                    <a href="/citrust/trust-recovery-board">Trust Recovery</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Open Exceptions</div>
                    <div class="value">13</div>
                    <div class="note">Certificate exceptions requiring owner, evidence, risk, or closure review.</div>
                </div>

                <div class="metric">
                    <div class="label">Approved Conditional</div>
                    <div class="value" style="color: var(--yellow);">6</div>
                    <div class="note">Exceptions allowed under controlled conditional certificate status.</div>
                </div>

                <div class="metric">
                    <div class="label">Escalation Needed</div>
                    <div class="value" style="color: var(--orange);">4</div>
                    <div class="note">Exceptions requiring governance, access, support, lifecycle, or executive review.</div>
                </div>

                <div class="metric">
                    <div class="label">Reject / Suspend</div>
                    <div class="value" style="color: var(--red);">3</div>
                    <div class="note">Exceptions too weak to support continued certificate assurance.</div>
                </div>

                <div class="metric">
                    <div class="label">Closure Ready</div>
                    <div class="value" style="color: var(--green);">5</div>
                    <div class="note">Exceptions that can close after evidence refresh or reviewer sign-off.</div>
                </div>

                <div class="metric">
                    <div class="label">Aging Exceptions</div>
                    <div class="value" style="color: var(--blue);">4</div>
                    <div class="note">Exceptions approaching expiry or requiring renewal decision.</div>
                </div>
            </section>

            <section class="section">
                <h2>Certificate Exception Answer</h2>
                <p>
                    This board answers whether a certificate exception is defensible or whether the certificate should be suspended.
                </p>

                <div class="answer">
                    <strong>Current exception interpretation:</strong>
                    Certificate exceptions must be rare, named, time-bound, and evidence-backed. A CI may remain conditionally trusted only when the exception has a clear risk statement, accountable owner, closure condition, expiry date, residual-risk acceptance, and monitoring plan. If the exception hides missing ownership, missing access evidence, lifecycle ambiguity, or broken lineage, the certificate should be suspended instead.
                </div>
            </section>

            <section class="section">
                <h2>Certificate Exception Domains</h2>
                <p>
                    CITrust™ separates certificate exceptions into the governance domains most likely to weaken certificate defensibility.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Evidence Exception</h3>
                        <p>Evidence exists but is incomplete, pending refresh, awaiting reviewer confirmation, or temporarily unavailable.</p>
                    </div>

                    <div class="card">
                        <h3>Access Exception</h3>
                        <p>MyAccess role, approver group, admin path, vendor access, jump route, or access review evidence remains partial.</p>
                    </div>

                    <div class="card">
                        <h3>Lifecycle Exception</h3>
                        <p>Active, cutover, OOS, retired, closed, rollback, or post-change state has an unresolved proof gap.</p>
                    </div>

                    <div class="card">
                        <h3>Lineage Exception</h3>
                        <p>Trust lineage is partially complete but has a known missing link under active remediation.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Certificate Exception Review Matrix</h2>
                <p>
                    This matrix shows whether each exception should be accepted, escalated, closed, or rejected.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Exception Type</th>
                            <th>Exception Rationale</th>
                            <th>Risk Owner</th>
                            <th>Closure Condition</th>
                            <th>Exception Decision</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>No active exception.</td>
                            <td>Certificate evidence remains current.</td>
                            <td>CI Owner / Application Governance</td>
                            <td>Maintain periodic cadence.</td>
                            <td><span class="badge green">No Exception Required</span></td>
                            <td>Continue evidence refresh and monitoring.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td>Cutover Evidence Exception</td>
                            <td>Support group, MyAccess role, jump path, vendor handoff, rollback, and post-cutover evidence are still being finalized.</td>
                            <td>Infrastructure / Cutover Owner / Access Governance</td>
                            <td>All cutover evidence linked and recovery attestation completed.</td>
                            <td><span class="badge yellow">Approve Conditional Exception</span></td>
                            <td>Track daily until cutover evidence chain is complete.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Privileged Access Evidence Exception</td>
                            <td>Access route is controlled but admin/vendor procedure and access review evidence require refresh.</td>
                            <td>Infrastructure / Access Governance</td>
                            <td>Current procedure, access review proof, and post-access verification attached.</td>
                            <td><span class="badge orange">Escalate For Access Review</span></td>
                            <td>Attach current admin/vendor procedure and reviewer acceptance.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Support / Lifecycle Exception</td>
                            <td>Support group, LCM, access path, evidence location, and operational classification remain partially reconciled.</td>
                            <td>Operational Owner / CMDB Governance</td>
                            <td>Support, lifecycle, access, evidence, and classification lineage confirmed.</td>
                            <td><span class="badge yellow">Conditional With Owner Action</span></td>
                            <td>Assign owner action and closure date.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>Access Confirmation Exception</td>
                            <td>Evidence is strong except final MyAccess approver group and role mapping confirmation.</td>
                            <td>Application Governance / MyAccess Governance</td>
                            <td>Approver group and role evidence confirmed.</td>
                            <td><span class="badge blue">Accept Short-Term Exception</span></td>
                            <td>Close after MyAccess confirmation.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>Lifecycle Closure Exception</td>
                            <td>OOS closure evidence, access removal proof, closure owner, and lifecycle decision are missing.</td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td>Closure evidence and access deactivation proof attached.</td>
                            <td><span class="badge red">Reject Exception / Keep Suspended</span></td>
                            <td>Return to recovery until closure evidence is defensible.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>No Exception Allowed</td>
                            <td>No governed candidate, evidence pack, owner, support group, LCM, access route, cadence, or verification model exists.</td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td>Governed candidate created and minimum evidence model established.</td>
                            <td><span class="badge red">Reject Exception</span></td>
                            <td>Create governed candidate before any certificate exception can be considered.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Exception Decision Logic</h2>
                <p>
                    Exceptions must preserve trust discipline rather than weaken it.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Exception Can Be Accepted</h3>
                        <ul>
                            <li>Risk is specific and documented.</li>
                            <li>Exception owner is named.</li>
                            <li>Evidence gap is limited and understood.</li>
                            <li>Closure condition is clear.</li>
                            <li>Expiry or review date is defined.</li>
                            <li>Certificate remains visibly conditional.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Exception Must Be Rejected</h3>
                        <ul>
                            <li>No accountable owner exists.</li>
                            <li>Evidence gap is broad or undefined.</li>
                            <li>Access removal or access route cannot be defended.</li>
                            <li>Lifecycle state is unsupported.</li>
                            <li>Hidden dependency has no governed candidate record.</li>
                            <li>Exception would conceal certificate failure.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Exception Closure Queue</h2>
                <p>
                    These actions close certificate exceptions before they become certificate suspension triggers.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Exception Issue</th>
                            <th>Why It Matters</th>
                            <th>Closure Evidence Required</th>
                            <th>Expected Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation exception rejected.</td>
                            <td>No exception is defensible without governed CI identity.</td>
                            <td>Candidate record, owner, support group, LCM, access path, backup evidence, cadence, escalation, verification.</td>
                            <td>Rejected → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS lifecycle exception rejected.</td>
                            <td>Missing closure and access-removal evidence should suspend certificate assurance.</td>
                            <td>Closure evidence, access deactivation proof, closure owner, lifecycle decision, decision ledger update.</td>
                            <td>Suspended → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Privileged access exception requires escalation.</td>
                            <td>Admin/vendor access exceptions must be time-bound and evidence-backed.</td>
                            <td>Admin/vendor procedure, access review proof, escalation owner, post-access verification.</td>
                            <td>Escalated → Conditional Closed</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>BMS cutover exception approved conditionally.</td>
                            <td>Cutover-sensitive exception must close before certificate can become active.</td>
                            <td>Support group, MyAccess role, jump path, vendor handoff, rollback readiness, post-cutover verification.</td>
                            <td>Conditional Exception → Certificate Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This certificate exception review board is a governance assurance overlay for exception approval, conditional certificates, risk acceptance, residual-risk control, exception expiry, closure evidence, reviewer accountability, decision-ledger integrity, continuous trust monitoring, audit defense, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_CERTIFICATE_EXCEPTION_REVIEW_BOARD_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Certificate Exception Review Board installed.")
