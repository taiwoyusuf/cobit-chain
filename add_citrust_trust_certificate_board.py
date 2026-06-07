from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_TRUST_CERTIFICATE_BOARD_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/trust-certificate-board")'
ROUTE_ALIAS = '@app.route("/citrust/ci-trust-certificate")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Trust Certificate Board already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_TRUST_CERTIFICATE_BOARD_V1_ACTIVE
# ============================================================

@app.route("/citrust/trust-certificate-board")
@app.route("/citrust/ci-trust-certificate")
def citrust_trust_certificate_board():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Trust Certificate Board</title>
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
                    radial-gradient(circle at top right, rgba(49,208,125,0.16), transparent 28%),
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
                <h1>CITrust™ Trust Certificate Board</h1>

                <div class="subtitle">
                    Determines whether a Configuration Item is ready for a formal trust certificate after candidate review, evidence pack completion, remediation, trust recovery, recovery attestation, trust lineage, and continuous trust monitoring.
                </div>

                <div class="positioning">
                    <strong>Certificate boundary:</strong>
                    CITrust™ does not create ServiceNow CIs, update CMDB records, approve access, or replace the existing CITrust™ Passport. This board decides whether the CI has enough governed evidence to support a certificate-style assurance statement that leadership can defend.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                    <a href="/citrust/trust-lineage-console">Trust Lineage</a>
                    <a href="/citrust/evidence-pack-builder">Evidence Pack</a>
                    <a href="/citrust/recovery-attestation">Recovery Attestation</a>
                    <a href="/citrust/continuous-trust-monitor">Continuous Trust</a>
                    <a href="/citrust/audit-question-bank">Audit Question Bank</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Certificate Candidates</div>
                    <div class="value">18</div>
                    <div class="note">CIs strong enough to be evaluated for certificate-style assurance.</div>
                </div>

                <div class="metric">
                    <div class="label">Certificate Ready</div>
                    <div class="value" style="color: var(--green);">5</div>
                    <div class="note">CIs with complete evidence, lineage, attestation, and continuous trust posture.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Certificate</div>
                    <div class="value" style="color: var(--yellow);">7</div>
                    <div class="note">CIs eligible only with residual-risk statement or pending evidence closure.</div>
                </div>

                <div class="metric">
                    <div class="label">Not Certifiable</div>
                    <div class="value" style="color: var(--red);">6</div>
                    <div class="note">CIs with broken lineage, missing evidence, blocked recovery, or unmanaged trust basis.</div>
                </div>

                <div class="metric">
                    <div class="label">Reviewer Required</div>
                    <div class="value" style="color: var(--orange);">9</div>
                    <div class="note">Records requiring owner, support, access, lifecycle, or governance reviewer sign-off.</div>
                </div>

                <div class="metric">
                    <div class="label">Passport Eligible</div>
                    <div class="value" style="color: var(--blue);">5</div>
                    <div class="note">Records ready to move into CITrust™ Passport-style assurance view.</div>
                </div>
            </section>

            <section class="section">
                <h2>Trust Certificate Answer</h2>
                <p>
                    This board answers whether a CI can receive a defensible trust certificate.
                </p>

                <div class="answer">
                    <strong>Current certificate interpretation:</strong>
                    A CI should receive certificate-style assurance only when its trust claim is supported by complete lineage, current evidence, accountable reviewers, closed or controlled remediation, recovery attestation where needed, audit-ready answers, and continuous trust monitoring. A certificate is not a decorative badge; it is a governed statement that the CI can be operationally trusted.
                </div>
            </section>

            <section class="section">
                <h2>Certificate Issuance Domains</h2>
                <p>
                    CITrust™ separates certificate readiness into the domains needed for a defensible assurance statement.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Evidence Sufficiency</h3>
                        <p>Identity, owner, support, LCM, MyAccess, lifecycle, relationship, rollback, and post-change evidence are complete.</p>
                    </div>

                    <div class="card">
                        <h3>Lineage Sufficiency</h3>
                        <p>The CI journey from candidate discovery to review, remediation, recovery, attestation, and monitoring is traceable.</p>
                    </div>

                    <div class="card">
                        <h3>Reviewer Sufficiency</h3>
                        <p>Owner, support, lifecycle, access, governance, or executive reviewer has accepted the trust statement.</p>
                    </div>

                    <div class="card">
                        <h3>Continuity Sufficiency</h3>
                        <p>Cadence, evidence drift, post-change verification, trust-decay forecast, and recovery controls remain active.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Trust Certificate Matrix</h2>
                <p>
                    This matrix shows which CIs are certificate-ready, conditional, or not certifiable.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Certificate Claim</th>
                            <th>Evidence Status</th>
                            <th>Lineage Status</th>
                            <th>Reviewer Status</th>
                            <th>Continuity Status</th>
                            <th>Certificate Decision</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>CI is operationally trusted and certificate-ready.</td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td><span class="badge soft-green">Accepted</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge green">Certificate Ready</span></td>
                            <td>Maintain periodic cadence and evidence refresh.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td>CI can become certificate-ready after cutover evidence closes.</td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Reviewer Needed</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td><span class="badge yellow">Conditional Certificate</span></td>
                            <td>Complete support group, MyAccess role, jump path, vendor handoff, rollback, and post-cutover evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Access trust can be certified after procedure evidence closes.</td>
                            <td><span class="badge soft-yellow">Procedure Needed</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Access Reviewer Needed</span></td>
                            <td><span class="badge soft-yellow">Review Due</span></td>
                            <td><span class="badge yellow">Conditional Certificate</span></td>
                            <td>Attach admin/vendor procedure, access review proof, post-access verification, and escalation owner.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Operational CI can be certified after support and lifecycle reconciliation.</td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Owner Action Needed</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td><span class="badge yellow">Not Yet Certificate-Ready</span></td>
                            <td>Confirm support group, LCM, access path, evidence location, and operational classification.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>CI is near certificate-ready after MyAccess approver confirmation.</td>
                            <td><span class="badge soft-green">Near Complete</span></td>
                            <td><span class="badge soft-blue">Strong</span></td>
                            <td><span class="badge soft-yellow">Access Check Needed</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge blue">Passport Eligible After Check</span></td>
                            <td>Confirm MyAccess approver group and role mapping evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>CI cannot be certified until OOS closure is defensible.</td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Broken</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Decayed</span></td>
                            <td><span class="badge red">Not Certifiable</span></td>
                            <td>Attach closure evidence, confirm access removal, assign closure owner, and update decision ledger.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>No certificate possible until a governed candidate exists.</td>
                            <td><span class="badge soft-red">No Evidence</span></td>
                            <td><span class="badge soft-red">No Lineage</span></td>
                            <td><span class="badge soft-red">No Reviewer</span></td>
                            <td><span class="badge soft-red">No Model</span></td>
                            <td><span class="badge red">Not Certifiable</span></td>
                            <td>Create governed candidate and build full owner, support, access, evidence, cadence, and verification model.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Certificate Decision Logic</h2>
                <p>
                    A certificate must represent defensible governance, not optimistic readiness.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Certificate Can Be Issued</h3>
                        <ul>
                            <li>Evidence pack is complete and current.</li>
                            <li>Trust lineage is complete from origin to current state.</li>
                            <li>Owner, support, LCM, access, or governance reviewer accepts the trust claim.</li>
                            <li>Open risks are closed or documented as controlled residual risk.</li>
                            <li>Continuous trust monitoring is active.</li>
                            <li>Decision ledger records the certificate rationale.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Certificate Must Be Blocked</h3>
                        <ul>
                            <li>Evidence is missing, stale, or disconnected from current reality.</li>
                            <li>Trust lineage is broken or undocumented.</li>
                            <li>No reviewer can accept accountability for the trust claim.</li>
                            <li>Lifecycle closure or access removal cannot be defended.</li>
                            <li>Hidden dependency has no governed candidate record.</li>
                            <li>Certificate would mask unresolved governance debt.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Certificate Readiness Closure Queue</h2>
                <p>
                    These actions must close before a CI can receive certificate-style assurance.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Certificate Gap</th>
                            <th>Why It Matters</th>
                            <th>Closure Evidence</th>
                            <th>Expected Certificate Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no certificate basis.</td>
                            <td>No certificate can exist without governed identity, ownership, evidence, and lineage.</td>
                            <td>Candidate record, owner, support group, LCM, access path, backup evidence, cadence, escalation, verification.</td>
                            <td>Not Certifiable → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment lifecycle certificate is blocked.</td>
                            <td>OOS trust cannot be certified without closure and access-removal evidence.</td>
                            <td>Closure evidence, access deactivation proof, closure owner, lifecycle decision, decision ledger update.</td>
                            <td>Not Certifiable → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover certificate is conditional.</td>
                            <td>Cutover-sensitive CI requires complete support, access, vendor, rollback, and post-cutover evidence.</td>
                            <td>Support group, MyAccess role, jump path, vendor handoff, rollback readiness, post-cutover verification.</td>
                            <td>Conditional Certificate → Certificate Ready</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access certificate requires procedure evidence.</td>
                            <td>Privileged access trust cannot be certified without current procedure and review proof.</td>
                            <td>Admin/vendor procedure, access review proof, escalation owner, post-access verification.</td>
                            <td>Conditional Certificate → Passport Eligible</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, audit systems, change control, validation systems, evidence repositories, or human governance. This trust certificate board is a governance assurance overlay for certificate-style CI trust statements, evidence-backed issuance, lineage sufficiency, reviewer accountability, residual-risk control, passport eligibility, decision-ledger integrity, continuous trust monitoring, audit defense, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_TRUST_CERTIFICATE_BOARD_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Trust Certificate Board installed.")
