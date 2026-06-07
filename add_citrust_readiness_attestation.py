from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_READINESS_ATTESTATION_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/readiness-attestation")'
ROUTE_ALIAS = '@app.route("/citrust/attestation-center")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Readiness Attestation Center already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_READINESS_ATTESTATION_V1_ACTIVE
# ============================================================

@app.route("/citrust/readiness-attestation")
@app.route("/citrust/attestation-center")
def citrust_readiness_attestation():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Readiness Attestation Center</title>
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
                    radial-gradient(circle at top right, rgba(49,208,125,0.14), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(180,156,255,0.08), transparent 30%),
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
                <h1>CITrust™ Readiness Attestation Center</h1>

                <div class="subtitle">
                    Captures whether CI owners, support groups, lifecycle managers, MyAccess approvers, infrastructure teams, and governance reviewers are willing to attest that a Configuration Item can be operationally trusted with available evidence.
                </div>

                <div class="positioning">
                    <strong>Attestation boundary:</strong>
                    CITrust™ attestation is a governance assurance statement, not an automatic ServiceNow update, not a CI creation action, and not a replacement for formal approval. It records whether the evidence is strong enough for accountable stakeholders to defend the CI.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/executive-reasoning-panel">Executive Reasoning</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                    <a href="/citrust/exception-register">Exception Register</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                    <a href="/citrust/submission-board">Submission Board</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Attestation Candidates</div>
                    <div class="value">42</div>
                    <div class="note">CIs eligible for owner, support, access, lifecycle, or governance attestation review.</div>
                </div>

                <div class="metric">
                    <div class="label">Fully Attested</div>
                    <div class="value" style="color: var(--green);">14</div>
                    <div class="note">Records with defensible stakeholder attestation.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Attestation</div>
                    <div class="value" style="color: var(--yellow);">16</div>
                    <div class="note">Attestation allowed only with documented remediation or exception.</div>
                </div>

                <div class="metric">
                    <div class="label">Rejected / Blocked</div>
                    <div class="value" style="color: var(--red);">8</div>
                    <div class="note">Stakeholders should not attest until critical gaps are closed.</div>
                </div>

                <div class="metric">
                    <div class="label">Pending Evidence</div>
                    <div class="value" style="color: var(--orange);">13</div>
                    <div class="note">Evidence still needed before readiness can be defended.</div>
                </div>

                <div class="metric">
                    <div class="label">Ready for Passport</div>
                    <div class="value" style="color: var(--blue);">9</div>
                    <div class="note">Records ready to move into CITrust™ Passport or submission-pack review.</div>
                </div>
            </section>

            <section class="section">
                <h2>Attestation Answer</h2>
                <p>
                    This center answers who can defend the CI and what evidence supports that defense.
                </p>

                <div class="answer">
                    <strong>Current attestation interpretation:</strong>
                    CITrust™ should only allow full readiness attestation when owner, support group, LCM, access routing, lifecycle state, dependency lineage, evidence lineage, and data quality are defensible. Conditional attestation is acceptable only when the risk is visible, time-bound, owned, and tied to a remediation plan.
                </div>
            </section>

            <section class="section">
                <h2>Attestation Register</h2>
                <p>
                    Each attestation records who is willing to defend the CI, which evidence supports the statement, and what condition remains open.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Attestation Status</th>
                            <th>Attesting Role</th>
                            <th>Evidence Basis</th>
                            <th>Open Condition</th>
                            <th>Trust Impact</th>
                            <th>Next Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge green">Fully Attested</span></td>
                            <td>Application Owner / CMDB Governance</td>
                            <td>Owner, support group, lifecycle, access, and evidence are available.</td>
                            <td>No material open condition.</td>
                            <td>Can support trusted CI Passport.</td>
                            <td>Maintain periodic review.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge yellow">Conditional Attestation</span></td>
                            <td>Infrastructure / Access Governance</td>
                            <td>Access path and support context are known.</td>
                            <td>Admin-access procedure evidence should be linked.</td>
                            <td>Conditional audit defensibility.</td>
                            <td>Attach admin or vendor access procedure evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge yellow">Conditional Attestation</span></td>
                            <td>Infrastructure / MyAccess Governance</td>
                            <td>Owner and lifecycle context exist; cutover path is known.</td>
                            <td>Support group, MyAccess role, jump path, and cutover evidence remain partial.</td>
                            <td>Controlled watchlist only.</td>
                            <td>Finalize support routing, access role, jump path, and cutover evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge yellow">Conditional Attestation</span></td>
                            <td>Operational Owner / CMDB Governance</td>
                            <td>Operational state is known.</td>
                            <td>Support group and evidence path need reconciliation.</td>
                            <td>Not fully ServiceNow-ready until reconciled.</td>
                            <td>Reconcile owner, support group, lifecycle, and evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge red">Do Not Attest</span></td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td>Evidence is insufficient for full defense.</td>
                            <td>OOS closure, access deactivation, and lifecycle ownership are not defensible.</td>
                            <td>Blocked from trust attestation.</td>
                            <td>Attach closure evidence and confirm access removal.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge red">Do Not Attest</span></td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td>Evidence and ownership are missing.</td>
                            <td>No owner, support group, LCM, access route, classification, or evidence lineage.</td>
                            <td>Blocked from trust and submission.</td>
                            <td>Create governed CI candidate with full accountability model.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge yellow">Conditional Attestation</span></td>
                            <td>Application Governance / MyAccess Governance</td>
                            <td>Core record is strong and operationally known.</td>
                            <td>Approver group and role mapping evidence should be confirmed.</td>
                            <td>Near access-ready.</td>
                            <td>Confirm approver group and access role evidence.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Attestation Evidence Domains</h2>
                <p>
                    CITrust™ separates attestation into evidence-backed domains so no stakeholder signs off blindly.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Owner Attestation</h3>
                        <p>Confirms the CI owner is willing to defend accountability, operational purpose, and readiness state.</p>
                    </div>

                    <div class="card">
                        <h3>Support Attestation</h3>
                        <p>Confirms the support group is willing to own routing, escalation, incident response, and support accountability.</p>
                    </div>

                    <div class="card">
                        <h3>Access Attestation</h3>
                        <p>Confirms MyAccess roles, approver groups, admin paths, and vendor access routes can be defended.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Attestation</h3>
                        <p>Confirms SOP, backup, audit trail, validation, closure, lifecycle, and cutover evidence can support audit questions.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Attestation Decision Logic</h2>
                <p>
                    Attestation should reflect what leadership can operationally defend.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Full Attestation Allowed</h3>
                        <ul>
                            <li>Owner, support group, and LCM are confirmed.</li>
                            <li>MyAccess roles and approver groups are mapped.</li>
                            <li>Lifecycle state is clear and evidence-backed.</li>
                            <li>Evidence lineage is reviewable.</li>
                            <li>Dependency chain is known.</li>
                            <li>Stakeholders can explain why the CI is operationally trusted.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Attestation Must Be Withheld</h3>
                        <ul>
                            <li>No accountable owner exists.</li>
                            <li>Support group or escalation path is missing.</li>
                            <li>Access approval route cannot be defended.</li>
                            <li>OOS or retired record lacks closure evidence.</li>
                            <li>Evidence is missing or disconnected from the CI.</li>
                            <li>Hidden dependency supports operational work without governance.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Attestation Closure Queue</h2>
                <p>
                    These actions convert conditional or blocked records into defensible attestation candidates.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Attestation Gap</th>
                            <th>Required Evidence</th>
                            <th>Responsible Workstream</th>
                            <th>Expected Upgrade</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation cannot be attested.</td>
                            <td>Owner, support group, LCM, access path, classification, and backup review evidence.</td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td>Blocked → Conditional Attestation</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment lacks closure and access deactivation evidence.</td>
                            <td>Closure evidence, access removal proof, lifecycle owner confirmation.</td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td>Blocked → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover record has partial support and access evidence.</td>
                            <td>Support group confirmation, role mapping, jump path evidence, cutover evidence.</td>
                            <td>Infrastructure / MyAccess Governance</td>
                            <td>Conditional → Full Attestation</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Lab application access route needs approver confirmation.</td>
                            <td>MyAccess approver group and role evidence.</td>
                            <td>Application Governance / MyAccess Governance</td>
                            <td>Conditional → Access-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, update CMDB records, approve access, or substitute for human governance. This readiness attestation center is a governance assurance overlay for stakeholder attestation, evidence-backed CI trust, owner accountability, support accountability, MyAccess readiness, lifecycle defensibility, audit readiness, ServiceNow-readiness, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_READINESS_ATTESTATION_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Readiness Attestation Center installed.")
