from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_EXCEPTION_CLOSURE_ATTESTATION_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/exception-closure-attestation")'
ROUTE_ALIAS = '@app.route("/citrust/certificate-exception-closure")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Exception Closure Attestation already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_EXCEPTION_CLOSURE_ATTESTATION_V1_ACTIVE
# ============================================================

@app.route("/citrust/exception-closure-attestation")
@app.route("/citrust/certificate-exception-closure")
def citrust_exception_closure_attestation():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Exception Closure Attestation</title>
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
                    radial-gradient(circle at top left, rgba(49,208,125,0.16), transparent 30%),
                    radial-gradient(circle at top right, rgba(92,200,255,0.15), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(255,184,107,0.10), transparent 30%),
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
                border: 1px solid rgba(49,208,125,0.36);
                background: rgba(49,208,125,0.10);
                color: #dfffea;
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
                <h1>CITrust™ Exception Closure Attestation</h1>

                <div class="subtitle">
                    Confirms whether certificate exceptions have been properly closed with evidence, reviewer acceptance, residual-risk resolution, decision-ledger update, and restored certificate trust state.
                </div>

                <div class="positioning">
                    <strong>Closure boundary:</strong>
                    CITrust™ does not close ServiceNow tasks, approve access, update CMDB records, or replace human governance in this demo. This console validates whether an exception can be closed from the CITrust™ certificate layer and whether the CI can move from conditional, expired, or suspended back to trusted, renewed, or passport-eligible status.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/exception-expiry-monitor">Exception Expiry</a>
                    <a href="/citrust/certificate-exception-review-board">Exception Review Board</a>
                    <a href="/citrust/certificate-suspension-center">Suspension Center</a>
                    <a href="/citrust/certificate-renewal-workbench">Renewal Workbench</a>
                    <a href="/citrust/trust-recovery-board">Trust Recovery</a>
                    <a href="/citrust/recovery-attestation">Recovery Attestation</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Closure Reviews</div>
                    <div class="value">12</div>
                    <div class="note">Exceptions awaiting closure, extension, escalation, or return-to-recovery decision.</div>
                </div>

                <div class="metric">
                    <div class="label">Closure Ready</div>
                    <div class="value" style="color: var(--green);">5</div>
                    <div class="note">Exceptions with enough evidence and reviewer acceptance to close.</div>
                </div>

                <div class="metric">
                    <div class="label">Close With Conditions</div>
                    <div class="value" style="color: var(--yellow);">3</div>
                    <div class="note">Exceptions that can close only with residual-risk statement or monitoring action.</div>
                </div>

                <div class="metric">
                    <div class="label">Escalate Closure</div>
                    <div class="value" style="color: var(--orange);">2</div>
                    <div class="note">Exceptions requiring access, lifecycle, support, or governance reviewer escalation.</div>
                </div>

                <div class="metric">
                    <div class="label">Closure Blocked</div>
                    <div class="value" style="color: var(--red);">2</div>
                    <div class="note">Exceptions missing required evidence, owner acceptance, or trust restoration proof.</div>
                </div>

                <div class="metric">
                    <div class="label">Certificate Restored</div>
                    <div class="value" style="color: var(--blue);">4</div>
                    <div class="note">Certificates that can move back to valid, renewed, or passport-eligible status.</div>
                </div>
            </section>

            <section class="section">
                <h2>Exception Closure Answer</h2>
                <p>
                    This console answers whether an exception can be formally closed without weakening trust discipline.
                </p>

                <div class="answer">
                    <strong>Current closure interpretation:</strong>
                    An exception should close only when the original exception cause has been resolved or controlled, closure evidence is attached, the accountable reviewer accepts the closure, residual risk is documented, and the decision ledger reflects the restored or conditional certificate state. Closing an exception without proof converts visible risk into hidden governance debt.
                </div>
            </section>

            <section class="section">
                <h2>Exception Closure Domains</h2>
                <p>
                    CITrust™ separates exception closure into evidence, accountability, trust-state, and monitoring controls.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Closure Evidence</h3>
                        <p>Confirms the required owner, support, access, lifecycle, evidence, rollback, or post-change proof has been attached.</p>
                    </div>

                    <div class="card">
                        <h3>Reviewer Acceptance</h3>
                        <p>Confirms the appropriate owner, support, LCM, access, governance, or executive reviewer accepts closure.</p>
                    </div>

                    <div class="card">
                        <h3>Trust-State Update</h3>
                        <p>Determines whether the certificate becomes active, renewed, conditional, suspended, or passport-eligible.</p>
                    </div>

                    <div class="card">
                        <h3>Post-Closure Monitoring</h3>
                        <p>Ensures cadence, evidence drift, continuous trust, and trust-decay forecast remain active after closure.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Exception Closure Attestation Matrix</h2>
                <p>
                    This matrix shows whether each exception can be closed, conditionally closed, escalated, or blocked.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Exception Being Closed</th>
                            <th>Closure Evidence</th>
                            <th>Reviewer Acceptance</th>
                            <th>Residual Risk</th>
                            <th>Closure Decision</th>
                            <th>Certificate Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>No active exception.</td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-green">Accepted</span></td>
                            <td>Low if cadence remains current.</td>
                            <td><span class="badge green">No Closure Needed</span></td>
                            <td>Certificate remains active.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td>Cutover evidence exception.</td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Cutover / Access Review Needed</span></td>
                            <td>Support, MyAccess, jump path, vendor handoff, rollback, and post-cutover evidence remain residual risks.</td>
                            <td><span class="badge yellow">Close With Conditions</span></td>
                            <td>Conditional certificate until cutover evidence chain closes.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Privileged access procedure evidence exception.</td>
                            <td><span class="badge soft-yellow">Evidence Refresh Needed</span></td>
                            <td><span class="badge soft-yellow">Access Reviewer Needed</span></td>
                            <td>Admin/vendor procedure and access review evidence remain partial.</td>
                            <td><span class="badge orange">Escalate Closure</span></td>
                            <td>Renewal remains blocked until access evidence is refreshed.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Support and lifecycle reconciliation exception.</td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Owner Action Needed</span></td>
                            <td>Support group, LCM, access route, evidence path, and classification need final confirmation.</td>
                            <td><span class="badge yellow">Conditionally Close After Owner Action</span></td>
                            <td>Pending certificate can move to conditional certificate.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>MyAccess approver confirmation exception.</td>
                            <td><span class="badge soft-green">Near Complete</span></td>
                            <td><span class="badge soft-green">Access Check Pending</span></td>
                            <td>Low once MyAccess approver group and role evidence are confirmed.</td>
                            <td><span class="badge green">Closure Ready After Final Check</span></td>
                            <td>Passport-eligible certificate.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>OOS lifecycle closure exception.</td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Accepted</span></td>
                            <td>OOS closure, access removal, closure owner, and lifecycle decision are not defensible.</td>
                            <td><span class="badge red">Closure Blocked</span></td>
                            <td>Certificate remains suspended.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>Invalid hidden-dependency exception.</td>
                            <td><span class="badge soft-red">No Evidence Model</span></td>
                            <td><span class="badge soft-red">No Reviewer</span></td>
                            <td>Dependency has no governed candidate, owner, support, LCM, access, cadence, or verification model.</td>
                            <td><span class="badge red">Cannot Close / Create Candidate First</span></td>
                            <td>No certificate allowed.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Exception Closure Decision Logic</h2>
                <p>
                    Exception closure must restore trust, not erase the visible risk trail.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Exception Can Close</h3>
                        <ul>
                            <li>Original exception cause is known and addressed.</li>
                            <li>Closure evidence is attached and reviewable.</li>
                            <li>Accountable reviewer accepts closure.</li>
                            <li>Residual risk is closed or explicitly controlled.</li>
                            <li>Certificate state is updated correctly.</li>
                            <li>Decision ledger records closure rationale.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Closure Must Be Blocked</h3>
                        <ul>
                            <li>Closure evidence is missing or stale.</li>
                            <li>No reviewer accepts the closure.</li>
                            <li>Access removal, access route, or lifecycle state remains unsupported.</li>
                            <li>Hidden dependency has no governed candidate record.</li>
                            <li>Exception is being closed only to clear a dashboard item.</li>
                            <li>Residual risk is undocumented or uncontrolled.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Exception Closure Action Queue</h2>
                <p>
                    These actions must close before exception closure can be attested.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Closure Gap</th>
                            <th>Why It Matters</th>
                            <th>Closure Evidence Required</th>
                            <th>Expected Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>OOS lifecycle exception cannot close.</td>
                            <td>Closure without access-removal and lifecycle proof would create false assurance.</td>
                            <td>Closure evidence, access deactivation proof, closure owner, lifecycle decision, decision ledger update.</td>
                            <td>Closure Blocked → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Hidden backup review workstation has no valid exception closure path.</td>
                            <td>No exception can be closed when no governed candidate exists.</td>
                            <td>Candidate record, owner, support group, LCM, access path, backup evidence, cadence, escalation, verification.</td>
                            <td>No Certificate Allowed → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Jump server access exception needs reviewer escalation.</td>
                            <td>Privileged access exception closure requires current procedure and review evidence.</td>
                            <td>Admin/vendor procedure, access review proof, escalation owner, post-access verification.</td>
                            <td>Escalate Closure → Renewed Certificate</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>BMS cutover exception can close only with conditions.</td>
                            <td>Cutover-sensitive closure must preserve visibility until all support, access, vendor, rollback, and verification evidence is complete.</td>
                            <td>Support group, MyAccess role, jump path, vendor handoff, rollback readiness, post-cutover verification.</td>
                            <td>Close With Conditions → Certificate Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This exception closure attestation console is a governance assurance overlay for exception closure, closure evidence validation, reviewer acceptance, residual-risk resolution, certificate restoration, certificate renewal, suspension prevention, decision-ledger integrity, continuous trust monitoring, audit defense, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_EXCEPTION_CLOSURE_ATTESTATION_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Exception Closure Attestation installed.")
