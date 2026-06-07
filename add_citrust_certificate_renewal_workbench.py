from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CERTIFICATE_RENEWAL_WORKBENCH_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/certificate-renewal-workbench")'
ROUTE_ALIAS = '@app.route("/citrust/certificate-renewal")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Certificate Renewal Workbench already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CERTIFICATE_RENEWAL_WORKBENCH_V1_ACTIVE
# ============================================================

@app.route("/citrust/certificate-renewal-workbench")
@app.route("/citrust/certificate-renewal")
def citrust_certificate_renewal_workbench():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Certificate Renewal Workbench</title>
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
                    radial-gradient(circle at top right, rgba(247,201,72,0.14), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(49,208,125,0.10), transparent 30%),
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
                <h1>CITrust™ Certificate Renewal Workbench</h1>

                <div class="subtitle">
                    Reviews issued and conditional CITrust™ certificates to determine whether each certificate should be renewed, renewed with conditions, suspended, revoked, or returned to recovery based on evidence freshness, cadence status, trust lineage, reviewer acceptance, and continuous trust signals.
                </div>

                <div class="positioning">
                    <strong>Renewal boundary:</strong>
                    CITrust™ does not update ServiceNow, issue legal certifications, approve access, or replace human governance. This workbench validates whether certificate-style assurance remains defensible and whether renewal can be supported by current evidence.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/trust-certificate-registry">Certificate Registry</a>
                    <a href="/citrust/trust-certificate-board">Certificate Board</a>
                    <a href="/citrust/continuous-trust-monitor">Continuous Trust</a>
                    <a href="/citrust/evidence-drift-monitor">Evidence Drift</a>
                    <a href="/citrust/recovery-attestation">Recovery Attestation</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Renewal Reviews</div>
                    <div class="value">14</div>
                    <div class="note">Certificates approaching renewal, cadence review, or evidence refresh.</div>
                </div>

                <div class="metric">
                    <div class="label">Renew Now</div>
                    <div class="value" style="color: var(--green);">4</div>
                    <div class="note">Certificates that can be renewed with current evidence and reviewer acceptance.</div>
                </div>

                <div class="metric">
                    <div class="label">Renew With Conditions</div>
                    <div class="value" style="color: var(--yellow);">5</div>
                    <div class="note">Certificates that need evidence closure or residual-risk statement.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Refresh Needed</div>
                    <div class="value" style="color: var(--orange);">6</div>
                    <div class="note">Certificates blocked from clean renewal until proof is refreshed.</div>
                </div>

                <div class="metric">
                    <div class="label">Suspend / Return</div>
                    <div class="value" style="color: var(--red);">3</div>
                    <div class="note">Certificates that must return to recovery or be suspended.</div>
                </div>

                <div class="metric">
                    <div class="label">Passport Renewal Ready</div>
                    <div class="value" style="color: var(--blue);">3</div>
                    <div class="note">Records ready for passport-linked renewal once reviewer sign-off is complete.</div>
                </div>
            </section>

            <section class="section">
                <h2>Certificate Renewal Answer</h2>
                <p>
                    This workbench answers whether a certificate-style trust statement can remain active.
                </p>

                <div class="answer">
                    <strong>Current renewal interpretation:</strong>
                    Certificate renewal should not be automatic. A certificate must be renewed only when evidence remains current, trust lineage is intact, continuous trust monitoring shows no material decay, reviewer accountability remains valid, and any residual risk is documented. If ownership, support, access, lifecycle, evidence, or cadence has drifted, the certificate should become conditional, suspended, or returned to recovery.
                </div>
            </section>

            <section class="section">
                <h2>Certificate Renewal Domains</h2>
                <p>
                    CITrust™ separates renewal into the proof areas needed to keep certificate-style assurance defensible.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Evidence Renewal</h3>
                        <p>Confirms evidence pack, access proof, lifecycle proof, support proof, rollback proof, and post-change evidence remain current.</p>
                    </div>

                    <div class="card">
                        <h3>Reviewer Renewal</h3>
                        <p>Confirms CI owner, support owner, LCM, access reviewer, or governance reviewer still accepts the certificate claim.</p>
                    </div>

                    <div class="card">
                        <h3>Continuity Renewal</h3>
                        <p>Confirms continuous trust, evidence drift, trust decay, and post-change verification controls support renewal.</p>
                    </div>

                    <div class="card">
                        <h3>Risk Renewal</h3>
                        <p>Confirms residual risks are controlled, exceptions are still valid, and no certificate should be suspended or returned to recovery.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Certificate Renewal Matrix</h2>
                <p>
                    This matrix shows renewal status for certificate-tracked CIs.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Current Certificate</th>
                            <th>Renewal Trigger</th>
                            <th>Evidence Freshness</th>
                            <th>Reviewer Status</th>
                            <th>Continuity Signal</th>
                            <th>Renewal Decision</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge green">Active</span></td>
                            <td>Periodic governance review.</td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-green">Accepted</span></td>
                            <td><span class="badge soft-green">Trust Maintained</span></td>
                            <td><span class="badge green">Renew Cleanly</span></td>
                            <td>Record renewal decision and maintain cadence.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Cutover evidence closure and post-cutover verification.</td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Reviewer Needed</span></td>
                            <td><span class="badge soft-yellow">Conditional Trust</span></td>
                            <td><span class="badge yellow">Renew With Conditions</span></td>
                            <td>Complete support group, MyAccess role, jump path, vendor handoff, rollback, and post-cutover evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge orange">Renewal Due</span></td>
                            <td>Privileged access review and procedure refresh.</td>
                            <td><span class="badge soft-yellow">Procedure Refresh Needed</span></td>
                            <td><span class="badge soft-yellow">Access Reviewer Needed</span></td>
                            <td><span class="badge soft-yellow">Access Drift Watch</span></td>
                            <td><span class="badge orange">Renewal Blocked Until Evidence Refresh</span></td>
                            <td>Attach current admin/vendor procedure, access review proof, and post-access verification evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge yellow">Pending</span></td>
                            <td>Support and lifecycle reconciliation.</td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Owner Action Needed</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td><span class="badge yellow">Not Ready For Renewal</span></td>
                            <td>Confirm support group, LCM, access path, evidence location, and operational classification.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge blue">Passport Eligible</span></td>
                            <td>Access approver confirmation.</td>
                            <td><span class="badge soft-green">Near Complete</span></td>
                            <td><span class="badge soft-yellow">Access Check Needed</span></td>
                            <td><span class="badge soft-green">Stable</span></td>
                            <td><span class="badge blue">Renew After Access Check</span></td>
                            <td>Confirm MyAccess approver group and role mapping evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge red">Suspended</span></td>
                            <td>Closure evidence and access deactivation proof.</td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Trust Decayed</span></td>
                            <td><span class="badge red">Do Not Renew</span></td>
                            <td>Return to recovery: attach closure evidence, confirm access removal, assign closure owner, and update decision ledger.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge red">Not Certifiable</span></td>
                            <td>Candidate creation and evidence pack build.</td>
                            <td><span class="badge soft-red">No Evidence</span></td>
                            <td><span class="badge soft-red">No Reviewer</span></td>
                            <td><span class="badge soft-red">No Trust Model</span></td>
                            <td><span class="badge red">No Renewal Possible</span></td>
                            <td>Create governed candidate and build owner, support, access, evidence, cadence, and verification model.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Renewal Decision Logic</h2>
                <p>
                    A certificate should renew only if the evidence still proves the trust claim.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Renew Certificate</h3>
                        <ul>
                            <li>Evidence pack is current.</li>
                            <li>Reviewer acceptance is current.</li>
                            <li>Trust lineage remains complete.</li>
                            <li>Continuous trust monitor shows no material decay.</li>
                            <li>Cadence review is current or completed.</li>
                            <li>Decision ledger captures renewal rationale.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Suspend Or Return To Recovery</h3>
                        <ul>
                            <li>Evidence is missing, stale, or conflicts with reality.</li>
                            <li>Reviewer accountability is unclear.</li>
                            <li>Access, support, owner, or lifecycle state has changed without attestation.</li>
                            <li>Trust lineage is broken.</li>
                            <li>Post-change verification failed or is missing.</li>
                            <li>Certificate would hide unresolved governance debt.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Certificate Renewal Action Queue</h2>
                <p>
                    These actions must close before certificate renewal can be defended.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Renewal Issue</th>
                            <th>Why It Matters</th>
                            <th>Renewal Evidence Required</th>
                            <th>Expected Renewal Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no certificate basis.</td>
                            <td>No renewal path exists because no governed certificate exists.</td>
                            <td>Candidate record, owner, support group, LCM, access path, backup evidence, cadence, escalation, verification.</td>
                            <td>No Renewal Possible → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS certificate must remain suspended.</td>
                            <td>Suspended certificate cannot be renewed without lifecycle closure and access-removal proof.</td>
                            <td>Closure evidence, access deactivation proof, closure owner, lifecycle decision, decision ledger update.</td>
                            <td>Do Not Renew → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Jump server certificate renewal blocked by stale access evidence.</td>
                            <td>Privileged access assurance requires current procedure and access review proof.</td>
                            <td>Admin/vendor procedure, access review proof, escalation owner, post-access verification.</td>
                            <td>Renewal Blocked → Renew Cleanly</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>BMS certificate renewal remains conditional.</td>
                            <td>Cutover-sensitive renewal requires support, access, vendor, rollback, and verification closure.</td>
                            <td>Support group, MyAccess role, jump path, vendor handoff, rollback readiness, post-cutover verification.</td>
                            <td>Renew With Conditions → Renew Cleanly</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, MyAccess, CITrust™ Passport, CMDB governance, audit systems, change control, validation systems, evidence repositories, or human governance. This certificate renewal workbench is a governance assurance overlay for certificate renewal, evidence refresh, reviewer renewal, renewal conditions, renewal suspension, renewal revocation, decision-ledger integrity, continuous trust monitoring, audit defense, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_CERTIFICATE_RENEWAL_WORKBENCH_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Certificate Renewal Workbench installed.")
