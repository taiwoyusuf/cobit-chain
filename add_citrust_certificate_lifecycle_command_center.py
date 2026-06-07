from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CERTIFICATE_LIFECYCLE_COMMAND_CENTER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/certificate-lifecycle-command-center")'
ROUTE_ALIAS = '@app.route("/citrust/certificate-command-center")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Certificate Lifecycle Command Center already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CERTIFICATE_LIFECYCLE_COMMAND_CENTER_V1_ACTIVE
# ============================================================

@app.route("/citrust/certificate-lifecycle-command-center")
@app.route("/citrust/certificate-command-center")
def citrust_certificate_lifecycle_command_center():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Certificate Lifecycle Command Center</title>
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
                    radial-gradient(circle at top right, rgba(49,208,125,0.15), transparent 28%),
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
                border: 1px solid rgba(92,200,255,0.38);
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
                min-height: 150px;
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

            .flow {
                display: grid;
                grid-template-columns: repeat(7, 1fr);
                gap: 12px;
                margin-top: 16px;
            }

            .flow-step {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 15px;
                min-height: 145px;
            }

            .flow-step h3 {
                margin: 0 0 8px 0;
                font-size: 15px;
            }

            .flow-step p {
                margin: 0;
                color: var(--muted);
                font-size: 13px;
                line-height: 1.5;
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
                .kpis, .cards, .flow, .two-col {
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
                <h1>CITrust™ Certificate Lifecycle Command Center</h1>

                <div class="subtitle">
                    Executive command layer for the full CITrust™ certificate lifecycle: certificate eligibility, issuance, registry status, renewal, suspension, restoration, attestation, passport linkage, and continuous trust monitoring.
                </div>

                <div class="positioning">
                    <strong>Lifecycle boundary:</strong>
                    CITrust™ does not replace ServiceNow, create CIs, approve access, issue legal certifications, or update CMDB records in this demo. This command center governs whether certificate-style CI trust statements are evidence-backed, current, renewable, suspendable, restorable, and defensible.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/trust-certificate-board">Certificate Board</a>
                    <a href="/citrust/trust-certificate-registry">Certificate Registry</a>
                    <a href="/citrust/certificate-renewal-workbench">Renewal Workbench</a>
                    <a href="/citrust/certificate-suspension-center">Suspension Center</a>
                    <a href="/citrust/recovery-attestation">Recovery Attestation</a>
                    <a href="/citrust/continuous-trust-monitor">Continuous Trust</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Certificate Population</div>
                    <div class="value">18</div>
                    <div class="note">CIs currently tracked for certificate-style governance.</div>
                </div>

                <div class="metric">
                    <div class="label">Active / Valid</div>
                    <div class="value" style="color: var(--green);">5</div>
                    <div class="note">Certificates valid, evidence-backed, and cadence-current.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional</div>
                    <div class="value" style="color: var(--yellow);">7</div>
                    <div class="note">Certificates with residual risk or pending evidence closure.</div>
                </div>

                <div class="metric">
                    <div class="label">Renewal / Refresh</div>
                    <div class="value" style="color: var(--orange);">6</div>
                    <div class="note">Certificates requiring evidence refresh or reviewer renewal.</div>
                </div>

                <div class="metric">
                    <div class="label">Suspended / Blocked</div>
                    <div class="value" style="color: var(--red);">4</div>
                    <div class="note">Certificates not defensible until recovery evidence is closed.</div>
                </div>

                <div class="metric">
                    <div class="label">Passport-Linked</div>
                    <div class="value" style="color: var(--blue);">5</div>
                    <div class="note">Records ready for or already aligned with passport-style assurance.</div>
                </div>
            </section>

            <section class="section">
                <h2>Certificate Lifecycle Answer</h2>
                <p>
                    This command center answers whether leadership can trust the certificate layer itself.
                </p>

                <div class="answer">
                    <strong>Current lifecycle interpretation:</strong>
                    A CI certificate is not a one-time badge. It must move through a governed lifecycle: eligibility, issuance, registry entry, renewal, suspension, recovery, attestation, and continuous monitoring. If evidence drifts, ownership changes, access becomes unclear, lifecycle state becomes unsupported, or review cadence expires, the certificate must be downgraded, suspended, or returned to recovery.
                </div>
            </section>

            <section class="section">
                <h2>Certificate Lifecycle Flow</h2>
                <p>
                    CITrust™ manages certificate-style assurance as a controlled lifecycle, not a static label.
                </p>

                <div class="flow">
                    <div class="flow-step">
                        <h3><span class="badge blue">1</span><br>Eligibility</h3>
                        <p>CI is checked for evidence pack, ownership, support, LCM, access, lifecycle, and lineage sufficiency.</p>
                    </div>

                    <div class="flow-step">
                        <h3><span class="badge green">2</span><br>Issuance</h3>
                        <p>Certificate claim is approved only when evidence and reviewer accountability support the trust statement.</p>
                    </div>

                    <div class="flow-step">
                        <h3><span class="badge purple">3</span><br>Registry</h3>
                        <p>Certificate is tracked as active, conditional, renewal due, suspended, revoked, or not certifiable.</p>
                    </div>

                    <div class="flow-step">
                        <h3><span class="badge yellow">4</span><br>Renewal</h3>
                        <p>Certificate is reviewed against current evidence, reviewer acceptance, cadence, and continuous trust status.</p>
                    </div>

                    <div class="flow-step">
                        <h3><span class="badge red">5</span><br>Suspension</h3>
                        <p>Certificate is downgraded or suspended when evidence no longer supports the trust claim.</p>
                    </div>

                    <div class="flow-step">
                        <h3><span class="badge orange">6</span><br>Recovery</h3>
                        <p>Trust is restored through evidence refresh, owner confirmation, access closure, lifecycle closure, or remediation.</p>
                    </div>

                    <div class="flow-step">
                        <h3><span class="badge blue">7</span><br>Monitoring</h3>
                        <p>Continuous trust checks prevent certificate drift, stale assurance, and false trust status.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Certificate Lifecycle Command Matrix</h2>
                <p>
                    This matrix gives leadership a single view of certificate lifecycle status and required action.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Lifecycle Stage</th>
                            <th>Certificate Status</th>
                            <th>Primary Issue</th>
                            <th>Required Governance Action</th>
                            <th>Command Decision</th>
                            <th>Target State</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>Registry / Monitoring</td>
                            <td><span class="badge green">Active</span></td>
                            <td>No material issue if cadence remains current.</td>
                            <td>Maintain evidence refresh and periodic review cadence.</td>
                            <td><span class="badge green">Keep Valid</span></td>
                            <td>Active Certificate</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td>Conditional / Recovery</td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Cutover support, MyAccess, jump path, vendor handoff, rollback, and post-cutover evidence remain partial.</td>
                            <td>Close cutover evidence chain and obtain reviewer attestation.</td>
                            <td><span class="badge yellow">Hold Conditional</span></td>
                            <td>Certificate Ready</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Renewal / Evidence Refresh</td>
                            <td><span class="badge orange">Renewal Due</span></td>
                            <td>Admin/vendor procedure and access review evidence require refresh.</td>
                            <td>Attach current access procedure, access review proof, and post-access verification.</td>
                            <td><span class="badge orange">Renewal Required</span></td>
                            <td>Renewed Certificate</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Recovery / Pending</td>
                            <td><span class="badge yellow">Pending</span></td>
                            <td>Support group, LCM, access path, evidence location, and operational classification are partial.</td>
                            <td>Confirm support, lifecycle, access, evidence, and classification lineage.</td>
                            <td><span class="badge yellow">Return To Recovery</span></td>
                            <td>Conditional Certificate</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>Passport Linkage</td>
                            <td><span class="badge blue">Passport Eligible</span></td>
                            <td>MyAccess approver group and role evidence need final confirmation.</td>
                            <td>Confirm MyAccess approver group and role mapping evidence.</td>
                            <td><span class="badge blue">Approve After Check</span></td>
                            <td>Passport-Linked Certificate</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>Suspension / Recovery</td>
                            <td><span class="badge red">Suspended</span></td>
                            <td>OOS closure evidence, access removal proof, closure owner, and lifecycle decision are missing.</td>
                            <td>Attach closure evidence, confirm access removal, assign closure owner, and update decision ledger.</td>
                            <td><span class="badge red">Keep Suspended</span></td>
                            <td>Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>Not Certifiable</td>
                            <td><span class="badge red">No Certificate</span></td>
                            <td>No governed candidate, evidence pack, owner, support, LCM, access route, cadence, or verification model exists.</td>
                            <td>Create governed candidate and build full trust model.</td>
                            <td><span class="badge red">No Certificate Allowed</span></td>
                            <td>Candidate Review</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Lifecycle Command Rules</h2>
                <p>
                    Certificate decisions must be governed by evidence, not confidence or assumptions.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Certificate Can Stay Active</h3>
                        <ul>
                            <li>Evidence pack remains complete and current.</li>
                            <li>Trust lineage is intact.</li>
                            <li>Reviewer accountability is valid.</li>
                            <li>Continuous trust shows no material decay.</li>
                            <li>Renewal cadence is current.</li>
                            <li>Decision ledger supports the active certificate state.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Certificate Must Move State</h3>
                        <ul>
                            <li>Evidence is stale, missing, or contradictory.</li>
                            <li>Owner, support, LCM, access, or lifecycle state changed without attestation.</li>
                            <li>Trust lineage breaks.</li>
                            <li>Post-change verification fails.</li>
                            <li>Certificate masks unresolved governance debt.</li>
                            <li>Hidden dependency has no governed CI candidate.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Certificate Action Queue</h2>
                <p>
                    These are the certificate lifecycle actions leadership should care about first.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Lifecycle Issue</th>
                            <th>Why It Matters</th>
                            <th>Required Executive Action</th>
                            <th>Expected Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no certificate basis.</td>
                            <td>Critical operational dependency remains outside governed certificate lifecycle.</td>
                            <td>Require governed candidate creation and evidence model assignment.</td>
                            <td>No Certificate → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS certificate remains suspended.</td>
                            <td>Lifecycle and access-removal risk cannot be trusted without closure proof.</td>
                            <td>Require closure evidence, access deactivation proof, closure owner, and decision ledger update.</td>
                            <td>Suspended → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Jump server renewal blocked by stale access evidence.</td>
                            <td>Privileged access certificate cannot remain trusted without current proof.</td>
                            <td>Require procedure refresh, access review evidence, and reviewer sign-off.</td>
                            <td>Renewal Due → Renewed Certificate</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>BMS certificate remains conditional during cutover.</td>
                            <td>Cutover-sensitive trust requires full support, access, vendor, rollback, and verification evidence.</td>
                            <td>Require closure of cutover evidence chain and recovery attestation.</td>
                            <td>Conditional → Certificate Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, audit systems, change control, validation systems, evidence repositories, or human governance. This certificate lifecycle command center is a governance assurance overlay for certificate eligibility, issuance, registry status, renewal, suspension, recovery, restoration, attestation, passport linkage, continuous trust monitoring, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_CERTIFICATE_LIFECYCLE_COMMAND_CENTER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Certificate Lifecycle Command Center installed.")
