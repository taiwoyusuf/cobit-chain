from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_TRUST_CERTIFICATE_REGISTRY_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/trust-certificate-registry")'
ROUTE_ALIAS = '@app.route("/citrust/certificate-registry")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Trust Certificate Registry already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_TRUST_CERTIFICATE_REGISTRY_V1_ACTIVE
# ============================================================

@app.route("/citrust/trust-certificate-registry")
@app.route("/citrust/certificate-registry")
def citrust_trust_certificate_registry():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Trust Certificate Registry</title>
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
                    radial-gradient(circle at bottom right, rgba(247,201,72,0.10), transparent 30%),
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
                <h1>CITrust™ Trust Certificate Registry</h1>

                <div class="subtitle">
                    Maintains the registry of issued, conditional, expired, revoked, renewal-due, and not-defensible CITrust™ certificates so leadership can see which Configuration Items remain formally trusted.
                </div>

                <div class="positioning">
                    <strong>Registry boundary:</strong>
                    CITrust™ does not replace ServiceNow, update CMDB records, issue legal certificates, or approve access in this demo. This registry is a governance assurance view showing whether certificate-style trust statements remain current, evidence-backed, reviewer-accepted, and continuously monitored.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/trust-certificate-board">Certificate Board</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                    <a href="/citrust/trust-lineage-console">Trust Lineage</a>
                    <a href="/citrust/recovery-attestation">Recovery Attestation</a>
                    <a href="/citrust/continuous-trust-monitor">Continuous Trust</a>
                    <a href="/citrust/evidence-drift-monitor">Evidence Drift</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Registry Entries</div>
                    <div class="value">18</div>
                    <div class="note">CIs evaluated for certificate-style assurance tracking.</div>
                </div>

                <div class="metric">
                    <div class="label">Active Certificates</div>
                    <div class="value" style="color: var(--green);">5</div>
                    <div class="note">Certificates currently trusted, evidence-backed, and within review cadence.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Certificates</div>
                    <div class="value" style="color: var(--yellow);">7</div>
                    <div class="note">Certificates with residual risk, pending evidence, or reviewer conditions.</div>
                </div>

                <div class="metric">
                    <div class="label">Renewal Due</div>
                    <div class="value" style="color: var(--orange);">4</div>
                    <div class="note">Certificates approaching evidence refresh or cadence review deadline.</div>
                </div>

                <div class="metric">
                    <div class="label">Suspended / Revoked</div>
                    <div class="value" style="color: var(--red);">2</div>
                    <div class="note">Certificates blocked by broken lineage, missing evidence, or trust decay.</div>
                </div>

                <div class="metric">
                    <div class="label">Passport Linked</div>
                    <div class="value" style="color: var(--blue);">5</div>
                    <div class="note">Certificates linked to CITrust™ Passport-style assurance view.</div>
                </div>
            </section>

            <section class="section">
                <h2>Trust Certificate Registry Answer</h2>
                <p>
                    This registry answers which certificate-style trust statements are still valid.
                </p>

                <div class="answer">
                    <strong>Current registry interpretation:</strong>
                    A certificate is only useful if it remains current. CITrust™ should track certificate status, evidence basis, reviewer acceptance, expiry or renewal date, residual risk, continuous-trust state, and revocation triggers. If evidence drifts, cadence expires, ownership changes, support routing breaks, or lifecycle state becomes unclear, the certificate must move from active to conditional, renewal due, suspended, or revoked.
                </div>
            </section>

            <section class="section">
                <h2>Certificate Registry Domains</h2>
                <p>
                    CITrust™ separates certificate tracking into the governance attributes needed for renewal and defensibility.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Certificate Status</h3>
                        <p>Tracks active, conditional, renewal due, suspended, revoked, expired, or not certifiable trust certificate status.</p>
                    </div>

                    <div class="card">
                        <h3>Certificate Evidence</h3>
                        <p>Links certificate status to evidence pack, lineage, attestation, reviewer acceptance, and decision ledger rationale.</p>
                    </div>

                    <div class="card">
                        <h3>Certificate Renewal</h3>
                        <p>Defines when the certificate must be reviewed again based on cadence, drift, post-change verification, or lifecycle change.</p>
                    </div>

                    <div class="card">
                        <h3>Certificate Suspension</h3>
                        <p>Identifies trust-decay triggers that should suspend or revoke certificate-style assurance until remediated.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Trust Certificate Registry</h2>
                <p>
                    This matrix shows certificate status, renewal status, and revocation triggers for key CI records.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Certificate Status</th>
                            <th>Certificate Basis</th>
                            <th>Reviewer / Owner</th>
                            <th>Renewal Trigger</th>
                            <th>Suspension Trigger</th>
                            <th>Registry Decision</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge green">Active</span></td>
                            <td>Evidence, lineage, reviewer acceptance, and cadence are current.</td>
                            <td>CI Owner / Application Governance</td>
                            <td>Next periodic governance review.</td>
                            <td>Evidence drift, ownership change, or overdue cadence.</td>
                            <td><span class="badge green">Certificate Valid</span></td>
                            <td>Maintain cadence and evidence refresh.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Cutover context exists, but support, MyAccess, jump path, vendor, rollback, and post-cutover evidence remain partial.</td>
                            <td>Infrastructure / Cutover Owner / Access Governance</td>
                            <td>Cutover evidence closure or post-change verification.</td>
                            <td>Failed cutover evidence, unresolved access route, or missing support group.</td>
                            <td><span class="badge yellow">Conditional Certificate</span></td>
                            <td>Complete support group, MyAccess role, jump path, vendor handoff, rollback, and post-cutover evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge yellow">Renewal Due</span></td>
                            <td>Access control path known, but procedure and access review evidence require refresh.</td>
                            <td>Infrastructure / Access Governance</td>
                            <td>Privileged access review or procedure update.</td>
                            <td>Missing admin/vendor procedure or stale access review evidence.</td>
                            <td><span class="badge orange">Renewal Required</span></td>
                            <td>Attach admin/vendor procedure, access review proof, and post-access verification evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge yellow">Pending</span></td>
                            <td>Operational state known, but support, LCM, access, evidence path, and classification remain incomplete.</td>
                            <td>Operational Owner / CMDB Governance</td>
                            <td>Support and lifecycle reconciliation.</td>
                            <td>Unresolved support group, missing LCM, or incomplete evidence path.</td>
                            <td><span class="badge yellow">Not Yet Active</span></td>
                            <td>Confirm support group, LCM, access path, evidence location, and operational classification.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge blue">Passport Eligible</span></td>
                            <td>Strong evidence and lineage; MyAccess approver confirmation remains final condition.</td>
                            <td>Application Governance / MyAccess Governance</td>
                            <td>Access review or approver group change.</td>
                            <td>Unconfirmed approver group or access-role drift.</td>
                            <td><span class="badge blue">Eligible After Check</span></td>
                            <td>Confirm MyAccess approver group and role mapping evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge red">Suspended</span></td>
                            <td>Certificate cannot be maintained because lifecycle closure and access-removal evidence are missing.</td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td>Closure evidence and access deactivation confirmation.</td>
                            <td>Missing closure proof, unclear owner, or access-removal gap.</td>
                            <td><span class="badge red">Certificate Suspended</span></td>
                            <td>Attach closure evidence, confirm access removal, assign closure owner, and update decision ledger.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge red">Not Certifiable</span></td>
                            <td>No governed candidate, evidence pack, owner, support group, LCM, access model, or verification model exists.</td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td>Candidate creation and evidence pack build.</td>
                            <td>Hidden dependency remains unmanaged.</td>
                            <td><span class="badge red">No Registry Eligibility</span></td>
                            <td>Create governed candidate and build full owner, support, access, evidence, cadence, and verification model.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Registry Decision Logic</h2>
                <p>
                    Certificate registry status must change when trust evidence changes.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Certificate Remains Active</h3>
                        <ul>
                            <li>Evidence pack remains current.</li>
                            <li>Trust lineage remains complete.</li>
                            <li>Reviewer acceptance remains valid.</li>
                            <li>Continuous trust monitor shows no material decay.</li>
                            <li>Cadence review is current.</li>
                            <li>Decision ledger supports the certificate rationale.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Certificate Must Be Suspended</h3>
                        <ul>
                            <li>Evidence is stale, missing, or conflicting.</li>
                            <li>Owner, support group, LCM, or access route changes without attestation.</li>
                            <li>Lifecycle closure or access removal cannot be defended.</li>
                            <li>Trust lineage breaks.</li>
                            <li>Post-change verification fails.</li>
                            <li>Hidden dependency has no governed candidate record.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Registry Renewal Queue</h2>
                <p>
                    These actions keep issued certificates from becoming stale or indefensible.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Registry Issue</th>
                            <th>Why It Matters</th>
                            <th>Renewal / Restoration Action</th>
                            <th>Expected Registry Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation is not certifiable.</td>
                            <td>No certificate registry entry can be valid without governed identity and evidence lineage.</td>
                            <td>Create governed candidate and build owner, support, LCM, access, backup evidence, cadence, and verification model.</td>
                            <td>Not Certifiable → Candidate Registry Entry</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment certificate is suspended.</td>
                            <td>Suspended certificate cannot be restored without closure and access-removal evidence.</td>
                            <td>Attach closure evidence, confirm access removal, assign closure owner, and update decision ledger.</td>
                            <td>Suspended → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Jump server certificate renewal is due.</td>
                            <td>Privileged access trust decays if admin/vendor procedure and access review evidence are stale.</td>
                            <td>Attach current admin/vendor procedure, access review proof, and post-access verification evidence.</td>
                            <td>Renewal Due → Certificate Valid</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>BMS certificate remains conditional.</td>
                            <td>Cutover-sensitive certificate cannot become active without support, access, vendor, rollback, and verification evidence.</td>
                            <td>Complete support group, MyAccess role, jump path, vendor handoff, rollback, and post-cutover evidence.</td>
                            <td>Conditional → Certificate Valid</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, audit systems, change control, validation systems, evidence repositories, or human governance. This trust certificate registry is a governance assurance overlay for issued certificate tracking, conditional certificate tracking, certificate renewal, certificate suspension, certificate revocation, evidence freshness, reviewer accountability, continuous trust monitoring, decision-ledger integrity, audit defense, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_TRUST_CERTIFICATE_REGISTRY_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Trust Certificate Registry installed.")
