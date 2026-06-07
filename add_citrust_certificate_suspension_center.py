from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CERTIFICATE_SUSPENSION_CENTER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/certificate-suspension-center")'
ROUTE_ALIAS = '@app.route("/citrust/certificate-revocation")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Certificate Suspension Center already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CERTIFICATE_SUSPENSION_CENTER_V1_ACTIVE
# ============================================================

@app.route("/citrust/certificate-suspension-center")
@app.route("/citrust/certificate-revocation")
def citrust_certificate_suspension_center():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Certificate Suspension Center</title>
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
                    radial-gradient(circle at top left, rgba(255,92,112,0.16), transparent 30%),
                    radial-gradient(circle at top right, rgba(92,200,255,0.14), transparent 28%),
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
                <h1>CITrust™ Certificate Suspension Center</h1>

                <div class="subtitle">
                    Determines when a CITrust™ certificate-style assurance statement must be suspended, revoked, downgraded to conditional, or returned to recovery because the CI is no longer operationally defensible.
                </div>

                <div class="positioning">
                    <strong>Suspension boundary:</strong>
                    CITrust™ does not revoke legal certifications, update ServiceNow, approve access, or replace human governance. This center governs the internal certificate-style trust state and explains why assurance must be paused until evidence, ownership, access, lifecycle, support, or lineage gaps are remediated.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/trust-certificate-registry">Certificate Registry</a>
                    <a href="/citrust/certificate-renewal-workbench">Renewal Workbench</a>
                    <a href="/citrust/trust-recovery-board">Trust Recovery</a>
                    <a href="/citrust/recovery-attestation">Recovery Attestation</a>
                    <a href="/citrust/trust-lineage-console">Trust Lineage</a>
                    <a href="/citrust/evidence-drift-monitor">Evidence Drift</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Suspension Reviews</div>
                    <div class="value">11</div>
                    <div class="note">Certificates requiring suspension, downgrade, revocation, or recovery review.</div>
                </div>

                <div class="metric">
                    <div class="label">Suspend Now</div>
                    <div class="value" style="color: var(--red);">3</div>
                    <div class="note">Certificates no longer defensible because critical evidence or lifecycle proof is missing.</div>
                </div>

                <div class="metric">
                    <div class="label">Downgrade Conditional</div>
                    <div class="value" style="color: var(--yellow);">4</div>
                    <div class="note">Certificates that can remain visible only with residual-risk conditions.</div>
                </div>

                <div class="metric">
                    <div class="label">Return To Recovery</div>
                    <div class="value" style="color: var(--orange);">5</div>
                    <div class="note">Certificates needing recovery work before renewal or restoration.</div>
                </div>

                <div class="metric">
                    <div class="label">Restore Eligible</div>
                    <div class="value" style="color: var(--green);">2</div>
                    <div class="note">Suspended certificates that can be restored after final evidence closure.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Visibility</div>
                    <div class="value" style="color: var(--blue);">4</div>
                    <div class="note">Suspensions with operational, access, audit, or cutover leadership impact.</div>
                </div>
            </section>

            <section class="section">
                <h2>Certificate Suspension Answer</h2>
                <p>
                    This center answers when a certificate-style trust statement is no longer defensible.
                </p>

                <div class="answer">
                    <strong>Current suspension interpretation:</strong>
                    A certificate must be suspended when the evidence no longer supports the trust claim. If owner, support group, LCM, MyAccess route, lifecycle closure, access removal, evidence pack, trust lineage, or post-change verification becomes incomplete or contradictory, CITrust™ should downgrade, suspend, or return the certificate to recovery rather than allowing leadership to rely on a false trust statement.
                </div>
            </section>

            <section class="section">
                <h2>Suspension Trigger Domains</h2>
                <p>
                    CITrust™ separates suspension triggers by the type of trust failure.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Evidence Failure</h3>
                        <p>Evidence is missing, stale, contradictory, or no longer proves the current CI state.</p>
                    </div>

                    <div class="card">
                        <h3>Accountability Failure</h3>
                        <p>Owner, support group, LCM, backup owner, reviewer, or escalation path is missing or disputed.</p>
                    </div>

                    <div class="card">
                        <h3>Access Failure</h3>
                        <p>MyAccess route, approver group, admin path, vendor path, jump route, or access-removal proof is not defensible.</p>
                    </div>

                    <div class="card">
                        <h3>Lifecycle Failure</h3>
                        <p>Active, cutover, OOS, retired, closed, rollback, or post-change lifecycle state cannot be proven.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Certificate Suspension Matrix</h2>
                <p>
                    This matrix shows which certificates should remain active, be downgraded, suspended, or returned to recovery.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Current Certificate State</th>
                            <th>Suspension Trigger</th>
                            <th>Evidence Problem</th>
                            <th>Risk If Left Active</th>
                            <th>Suspension Decision</th>
                            <th>Restoration Requirement</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge green">Active</span></td>
                            <td>No material trigger.</td>
                            <td>Evidence remains current and cadence-backed.</td>
                            <td>Low if periodic review remains current.</td>
                            <td><span class="badge green">Keep Active</span></td>
                            <td>Maintain cadence and evidence refresh.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Cutover evidence, support group, MyAccess role, jump path, vendor handoff, rollback, and post-change evidence are partial.</td>
                            <td>Cutover trust claim cannot yet be fully defended.</td>
                            <td>Leadership may over-trust a cutover-sensitive CI before support and access closure.</td>
                            <td><span class="badge yellow">Keep Conditional</span></td>
                            <td>Complete cutover evidence chain and reviewer attestation.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge orange">Renewal Due</span></td>
                            <td>Admin/vendor procedure and access review evidence are incomplete.</td>
                            <td>Privileged access assurance is not fully current.</td>
                            <td>Access certificate could misrepresent audit-readiness.</td>
                            <td><span class="badge orange">Downgrade Until Renewed</span></td>
                            <td>Attach current admin/vendor procedure, access review proof, and post-access verification.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge yellow">Pending</span></td>
                            <td>Support group, LCM, access path, evidence location, and classification are partial.</td>
                            <td>Operational trust cannot yet support certificate activation.</td>
                            <td>Support-routing or lifecycle ambiguity may be hidden under a pending certificate state.</td>
                            <td><span class="badge yellow">Return To Recovery</span></td>
                            <td>Confirm support group, LCM, access path, evidence location, and operational classification.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge blue">Passport Eligible</span></td>
                            <td>MyAccess approver group and role evidence need final confirmation.</td>
                            <td>Access evidence is near complete but not final.</td>
                            <td>Certificate could be issued before final access route confirmation.</td>
                            <td><span class="badge blue">Hold For Final Check</span></td>
                            <td>Confirm MyAccess approver group and role mapping evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge red">Suspended</span></td>
                            <td>OOS closure evidence, access removal proof, closure owner, and lifecycle decision are missing.</td>
                            <td>Lifecycle trust is not defensible.</td>
                            <td>Certificate would mask an OOS lifecycle and access-removal risk.</td>
                            <td><span class="badge red">Keep Suspended</span></td>
                            <td>Attach closure evidence, confirm access removal, assign closure owner, and update decision ledger.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge red">Not Certifiable</span></td>
                            <td>No governed candidate, evidence pack, owner, support group, LCM, access route, cadence, or verification model exists.</td>
                            <td>No trust basis exists.</td>
                            <td>Hidden dependency may remain operationally critical but invisible to governance.</td>
                            <td><span class="badge red">No Certificate Allowed</span></td>
                            <td>Create governed candidate and build owner, support, access, evidence, cadence, and verification model.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Suspension Decision Logic</h2>
                <p>
                    A certificate should be suspended when continuing it would misrepresent operational trust.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Keep Certificate Active</h3>
                        <ul>
                            <li>Evidence remains current and reviewable.</li>
                            <li>Trust lineage remains complete.</li>
                            <li>Reviewer accountability remains valid.</li>
                            <li>Access, support, lifecycle, and owner data remain accurate.</li>
                            <li>Continuous trust monitor shows no material decay.</li>
                            <li>Decision ledger supports continued certificate validity.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Suspend Or Revoke Certificate</h3>
                        <ul>
                            <li>Evidence is missing, stale, or contradictory.</li>
                            <li>Lifecycle closure or access removal cannot be defended.</li>
                            <li>Owner, support group, LCM, reviewer, or escalation path is missing.</li>
                            <li>Post-change verification failed or was never completed.</li>
                            <li>Hidden dependency has no governed CI candidate.</li>
                            <li>Certificate would conceal unresolved governance debt.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Certificate Restoration Queue</h2>
                <p>
                    These actions are required before suspended or downgraded certificates can be restored.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Suspension Issue</th>
                            <th>Why It Matters</th>
                            <th>Restoration Evidence Required</th>
                            <th>Expected Restoration Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no certificate basis.</td>
                            <td>No certificate can be issued, suspended, or restored without governed CI identity.</td>
                            <td>Candidate record, owner, support group, LCM, access path, backup evidence, cadence, escalation, verification.</td>
                            <td>No Certificate Allowed → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment certificate remains suspended.</td>
                            <td>Lifecycle trust cannot be restored until closure and access removal are proven.</td>
                            <td>Closure evidence, access deactivation proof, closure owner, lifecycle decision, decision ledger update.</td>
                            <td>Suspended → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Jump server certificate downgraded due to stale access evidence.</td>
                            <td>Privileged access assurance requires current procedure and access review evidence.</td>
                            <td>Admin/vendor procedure, access review proof, access escalation owner, post-access verification.</td>
                            <td>Downgraded → Certificate Valid</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>BMS certificate remains conditional during cutover.</td>
                            <td>Cutover-sensitive assurance must not become active until support, access, vendor, rollback, and verification evidence close.</td>
                            <td>Support group, MyAccess role, jump path, vendor handoff, rollback readiness, post-cutover verification.</td>
                            <td>Conditional → Certificate Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, audit systems, change control, validation systems, evidence repositories, or human governance. This certificate suspension center is a governance assurance overlay for certificate suspension, certificate revocation, certificate downgrade, certificate restoration, evidence defensibility, trust lineage integrity, reviewer accountability, continuous trust monitoring, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_CERTIFICATE_SUSPENSION_CENTER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Certificate Suspension Center installed.")
