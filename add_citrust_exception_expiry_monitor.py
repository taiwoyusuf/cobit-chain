from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_EXCEPTION_EXPIRY_MONITOR_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/exception-expiry-monitor")'
ROUTE_ALIAS = '@app.route("/citrust/certificate-exception-expiry")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Exception Expiry Monitor already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_EXCEPTION_EXPIRY_MONITOR_V1_ACTIVE
# ============================================================

@app.route("/citrust/exception-expiry-monitor")
@app.route("/citrust/certificate-exception-expiry")
def citrust_exception_expiry_monitor():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Exception Expiry Monitor</title>
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
                    radial-gradient(circle at top right, rgba(255,92,112,0.14), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(92,200,255,0.10), transparent 30%),
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
                <h1>CITrust™ Exception Expiry Monitor</h1>

                <div class="subtitle">
                    Monitors certificate exceptions that are approaching expiry, overdue, repeatedly extended, missing closure evidence, or no longer defensible under CITrust™ certificate governance.
                </div>

                <div class="positioning">
                    <strong>Expiry boundary:</strong>
                    CITrust™ does not approve risk, update ServiceNow, extend access, or close exceptions automatically in this demo. This monitor identifies when a certificate exception must be closed, renewed, escalated, suspended, or returned to recovery before the exception becomes hidden governance debt.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/certificate-exception-review-board">Exception Review Board</a>
                    <a href="/citrust/certificate-lifecycle-command-center">Certificate Command Center</a>
                    <a href="/citrust/certificate-suspension-center">Suspension Center</a>
                    <a href="/citrust/trust-recovery-board">Trust Recovery</a>
                    <a href="/citrust/continuous-trust-monitor">Continuous Trust</a>
                    <a href="/citrust/evidence-drift-monitor">Evidence Drift</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Tracked Exceptions</div>
                    <div class="value">13</div>
                    <div class="note">Certificate exceptions being monitored for expiry and closure.</div>
                </div>

                <div class="metric">
                    <div class="label">Expiring Soon</div>
                    <div class="value" style="color: var(--yellow);">5</div>
                    <div class="note">Exceptions approaching expiry and requiring closure or renewal decision.</div>
                </div>

                <div class="metric">
                    <div class="label">Overdue</div>
                    <div class="value" style="color: var(--red);">3</div>
                    <div class="note">Exceptions past expiry date with no defensible closure action.</div>
                </div>

                <div class="metric">
                    <div class="label">Closure Ready</div>
                    <div class="value" style="color: var(--green);">4</div>
                    <div class="note">Exceptions ready to close after evidence attachment or reviewer sign-off.</div>
                </div>

                <div class="metric">
                    <div class="label">Escalate</div>
                    <div class="value" style="color: var(--orange);">4</div>
                    <div class="note">Exceptions requiring owner, access, lifecycle, or executive escalation.</div>
                </div>

                <div class="metric">
                    <div class="label">Suspend Risk</div>
                    <div class="value" style="color: var(--blue);">3</div>
                    <div class="note">Exceptions likely to force certificate suspension if not closed.</div>
                </div>
            </section>

            <section class="section">
                <h2>Exception Expiry Answer</h2>
                <p>
                    This monitor answers whether a certificate exception is still legitimate or has become unresolved governance debt.
                </p>

                <div class="answer">
                    <strong>Current expiry interpretation:</strong>
                    A certificate exception should never remain open indefinitely. CITrust™ should treat expired exceptions as trust-decay signals. If the exception has no closure evidence, no owner action, no renewed risk acceptance, or no updated decision ledger entry, the certificate should be downgraded, suspended, or returned to recovery.
                </div>
            </section>

            <section class="section">
                <h2>Exception Expiry Domains</h2>
                <p>
                    CITrust™ separates exception expiry risk into domains that determine whether conditional trust can continue.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Expiry Control</h3>
                        <p>Tracks expiry date, review date, extension history, aging status, and whether the exception remains time-bound.</p>
                    </div>

                    <div class="card">
                        <h3>Closure Evidence</h3>
                        <p>Confirms whether the evidence required to close the exception has been attached, reviewed, and accepted.</p>
                    </div>

                    <div class="card">
                        <h3>Risk Acceptance</h3>
                        <p>Validates whether the exception still has an accountable owner and current residual-risk acceptance.</p>
                    </div>

                    <div class="card">
                        <h3>Suspension Trigger</h3>
                        <p>Determines whether expired or unsupported exceptions require certificate downgrade, suspension, or recovery action.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Exception Expiry Matrix</h2>
                <p>
                    This matrix shows which exceptions are current, expiring, overdue, closure-ready, or suspension-triggering.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Exception</th>
                            <th>Expiry Status</th>
                            <th>Owner Action</th>
                            <th>Closure Evidence</th>
                            <th>Expiry Decision</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>No active exception.</td>
                            <td><span class="badge soft-green">Not Applicable</span></td>
                            <td>Periodic review only.</td>
                            <td>Evidence remains current.</td>
                            <td><span class="badge green">No Expiry Risk</span></td>
                            <td>Maintain cadence and evidence refresh.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td>Cutover evidence exception.</td>
                            <td><span class="badge soft-yellow">Expiring Soon</span></td>
                            <td>Cutover owner and access governance must close evidence chain.</td>
                            <td>Support group, MyAccess role, jump path, vendor handoff, rollback, and post-cutover checks still partial.</td>
                            <td><span class="badge yellow">Renew Only If Justified</span></td>
                            <td>Close evidence chain or renew exception with explicit residual-risk acceptance.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Privileged access procedure evidence exception.</td>
                            <td><span class="badge soft-orange">Overdue Review</span></td>
                            <td>Infrastructure and access governance must refresh procedure evidence.</td>
                            <td>Admin/vendor procedure and access review proof are incomplete.</td>
                            <td><span class="badge orange">Escalate</span></td>
                            <td>Attach current procedure, access review proof, and reviewer acceptance.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Support and lifecycle reconciliation exception.</td>
                            <td><span class="badge soft-yellow">Aging</span></td>
                            <td>Operational owner must confirm support group, LCM, access path, and evidence location.</td>
                            <td>Partial evidence exists but classification and support lineage are not closed.</td>
                            <td><span class="badge yellow">Keep Conditional With Closure Date</span></td>
                            <td>Assign closure date and owner action in decision ledger.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>MyAccess approver confirmation exception.</td>
                            <td><span class="badge soft-green">Closure Ready</span></td>
                            <td>MyAccess governance must confirm approver group and role mapping.</td>
                            <td>Core evidence is strong; access confirmation remains final gap.</td>
                            <td><span class="badge green">Close After Confirmation</span></td>
                            <td>Attach approver group evidence and close exception.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>OOS lifecycle closure exception.</td>
                            <td><span class="badge soft-red">Overdue</span></td>
                            <td>Lifecycle and access governance must close OOS evidence gap.</td>
                            <td>Closure evidence, access removal proof, closure owner, and lifecycle decision are missing.</td>
                            <td><span class="badge red">Do Not Extend / Keep Suspended</span></td>
                            <td>Return to recovery until closure evidence and access deactivation proof are attached.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>No exception allowed.</td>
                            <td><span class="badge soft-red">Invalid</span></td>
                            <td>CMDB governance must create a governed candidate first.</td>
                            <td>No evidence model exists.</td>
                            <td><span class="badge red">Reject Exception</span></td>
                            <td>Create governed candidate before any exception can be monitored.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Exception Expiry Decision Logic</h2>
                <p>
                    Expired exceptions should trigger governance action, not quiet continuation.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Exception Can Continue</h3>
                        <ul>
                            <li>Exception owner remains accountable.</li>
                            <li>Expiry date is active and time-bound.</li>
                            <li>Residual risk is documented.</li>
                            <li>Closure evidence is in progress and specific.</li>
                            <li>Certificate remains visibly conditional.</li>
                            <li>Decision ledger includes the current exception rationale.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Exception Must Expire</h3>
                        <ul>
                            <li>Exception has passed expiry without closure.</li>
                            <li>No owner action is visible.</li>
                            <li>Closure evidence is missing or undefined.</li>
                            <li>Access, lifecycle, or ownership risk remains unresolved.</li>
                            <li>Exception has been repeatedly extended without progress.</li>
                            <li>Exception is hiding certificate failure.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Exception Expiry Action Queue</h2>
                <p>
                    These actions prevent open exceptions from becoming unmanaged certificate risk.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Expiry Issue</th>
                            <th>Why It Matters</th>
                            <th>Closure / Escalation Required</th>
                            <th>Expected Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>OOS lifecycle exception is overdue.</td>
                            <td>OOS closure and access-removal risk cannot remain under exception indefinitely.</td>
                            <td>Attach closure evidence, access deactivation proof, closure owner, and lifecycle decision.</td>
                            <td>Overdue Exception → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Hidden backup review workstation exception is invalid.</td>
                            <td>No exception is defensible where no governed candidate exists.</td>
                            <td>Create governed candidate and build owner, support, access, evidence, cadence, and verification model.</td>
                            <td>Invalid Exception → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Jump server access exception review is overdue.</td>
                            <td>Privileged access evidence must not remain stale under exception.</td>
                            <td>Attach admin/vendor procedure, access review proof, escalation owner, and post-access verification.</td>
                            <td>Overdue Review → Exception Closed</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>BMS cutover exception is expiring soon.</td>
                            <td>Cutover exception must close or be explicitly renewed with residual-risk acceptance.</td>
                            <td>Complete support group, MyAccess role, jump path, vendor handoff, rollback, and post-cutover evidence.</td>
                            <td>Expiring Soon → Certificate Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This exception expiry monitor is a governance assurance overlay for exception aging, expiry tracking, overdue exception escalation, conditional certificate expiry, risk acceptance renewal, closure evidence tracking, certificate suspension triggers, decision-ledger integrity, continuous trust monitoring, audit defense, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_EXCEPTION_EXPIRY_MONITOR_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Exception Expiry Monitor installed.")
