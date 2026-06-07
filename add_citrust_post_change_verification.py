from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_POST_CHANGE_VERIFICATION_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/post-change-verification")'
ROUTE_ALIAS = '@app.route("/citrust/post-cutover-verification")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Post-Change Verification Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_POST_CHANGE_VERIFICATION_V1_ACTIVE
# ============================================================

@app.route("/citrust/post-change-verification")
@app.route("/citrust/post-cutover-verification")
def citrust_post_change_verification():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Post-Change Verification Console</title>
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
                <h1>CITrust™ Post-Change Verification Console</h1>

                <div class="subtitle">
                    Validates whether a Configuration Item remains operationally trusted after change activity, cutover, support reassignment, access update, lifecycle correction, vendor work, rollback, evidence refresh, or ServiceNow-style readiness remediation.
                </div>

                <div class="positioning">
                    <strong>Post-change boundary:</strong>
                    CITrust™ does not approve changes, execute testing, update ServiceNow records, or replace change control. It validates whether post-change ownership, support, access, lifecycle, evidence, dependency, rollback, and audit-readiness checks were completed and are defensible.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/change-impact-readiness">Change Impact</a>
                    <a href="/citrust/rollback-readiness">Rollback Readiness</a>
                    <a href="/citrust/pre-deviation-readiness">Pre-Deviation</a>
                    <a href="/citrust/evidence-pack-builder">Evidence Pack</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Post-Change Checks</div>
                    <div class="value">38</div>
                    <div class="note">Checks across support, access, lifecycle, evidence, relationships, rollback, and audit readiness.</div>
                </div>

                <div class="metric">
                    <div class="label">Verified</div>
                    <div class="value" style="color: var(--green);">17</div>
                    <div class="note">CIs with completed post-change evidence and trust confirmation.</div>
                </div>

                <div class="metric">
                    <div class="label">Pending Verification</div>
                    <div class="value" style="color: var(--yellow);">13</div>
                    <div class="note">CIs with checks not fully closed or evidence not yet linked.</div>
                </div>

                <div class="metric">
                    <div class="label">Failed Verification</div>
                    <div class="value" style="color: var(--red);">8</div>
                    <div class="note">CIs with unresolved gaps after change activity.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Refresh Needed</div>
                    <div class="value" style="color: var(--orange);">12</div>
                    <div class="note">Records requiring updated proof after change, cutover, or remediation.</div>
                </div>

                <div class="metric">
                    <div class="label">Trust Reconfirmed</div>
                    <div class="value" style="color: var(--blue);">11</div>
                    <div class="note">CIs whose trusted or conditional state has been revalidated post-change.</div>
                </div>
            </section>

            <section class="section">
                <h2>Post-Change Verification Answer</h2>
                <p>
                    This console answers whether a CI remains trusted after something has changed.
                </p>

                <div class="answer">
                    <strong>Current post-change interpretation:</strong>
                    A CI should not automatically remain trusted after cutover, access update, support reassignment, vendor activity, lifecycle correction, or rollback. CITrust™ requires post-change verification of owner, support group, LCM, MyAccess route, access closure, dependency state, evidence pack, rollback readiness, audit question readiness, and decision ledger update.
                </div>
            </section>

            <section class="section">
                <h2>Post-Change Verification Domains</h2>
                <p>
                    CITrust™ separates post-change verification into the controls needed to reconfirm trust.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Operational Verification</h3>
                        <p>Confirms CI owner, support group, resolver path, escalation chain, and LCM remain accurate after change.</p>
                    </div>

                    <div class="card">
                        <h3>Access Verification</h3>
                        <p>Confirms MyAccess roles, approver group, admin access, vendor access, and access removal are current and defensible.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Verification</h3>
                        <p>Confirms evidence pack, SOP linkage, backup review, audit trail review, cutover evidence, and closure proof are refreshed.</p>
                    </div>

                    <div class="card">
                        <h3>Trust Reconfirmation</h3>
                        <p>Confirms trust score, threshold status, decision ledger, assurance case, and audit-defense answer remain valid.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Post-Change Verification Matrix</h2>
                <p>
                    This matrix shows whether each CI passed post-change or post-cutover verification.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Change Scenario</th>
                            <th>Support Verified</th>
                            <th>Access Verified</th>
                            <th>Lifecycle Verified</th>
                            <th>Evidence Verified</th>
                            <th>Verification Decision</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>Routine record or support review.</td>
                            <td><span class="badge soft-green">Verified</span></td>
                            <td><span class="badge soft-green">Verified</span></td>
                            <td><span class="badge soft-green">Verified</span></td>
                            <td><span class="badge soft-green">Verified</span></td>
                            <td><span class="badge green">Trust Reconfirmed</span></td>
                            <td>Maintain periodic review cadence.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td>Cutover, vendor support, jump path, access route update.</td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Cutover Active</span></td>
                            <td><span class="badge soft-yellow">Cutover Evidence Needed</span></td>
                            <td><span class="badge yellow">Verification Pending</span></td>
                            <td>Complete support, MyAccess, jump path, vendor handoff, rollback, and post-cutover evidence checks.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Admin route, vendor route, privileged access update.</td>
                            <td><span class="badge soft-green">Verified</span></td>
                            <td><span class="badge soft-yellow">Procedure Evidence Needed</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-yellow">Access Evidence Partial</span></td>
                            <td><span class="badge yellow">Conditional Verification</span></td>
                            <td>Attach admin/vendor procedure, access review evidence, and post-change access confirmation.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Support reassignment, lifecycle check, access model correction.</td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-green">Operational</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge yellow">Conditional Verification</span></td>
                            <td>Reconfirm support group, LCM, access route, evidence path, and operational classification.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>Access role or support-routing update.</td>
                            <td><span class="badge soft-green">Verified</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Verified</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge yellow">Near Verified</span></td>
                            <td>Confirm MyAccess approver group and post-access verification evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>OOS closure, retirement, access deactivation.</td>
                            <td><span class="badge soft-red">Not Verified</span></td>
                            <td><span class="badge soft-red">Removal Not Confirmed</span></td>
                            <td><span class="badge soft-red">Closure Missing</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge red">Verification Failed</span></td>
                            <td>Attach closure evidence, confirm access removal, assign closure owner, and update lifecycle decision.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>Backup review process, workstation support, access or evidence model.</td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Unmanaged</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge red">No Verification Model</span></td>
                            <td>Create governed candidate and define post-change verification controls.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Post-Change Verification Decision Logic</h2>
                <p>
                    Post-change verification must prove that trust survived the change.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Verification Passed</h3>
                        <ul>
                            <li>Owner, support group, LCM, and escalation remain accurate.</li>
                            <li>MyAccess, admin, vendor, or jump path remains approved and evidence-backed.</li>
                            <li>Lifecycle state is current after change.</li>
                            <li>Relationships and dependency impact are still valid.</li>
                            <li>Evidence pack and audit answers are refreshed.</li>
                            <li>Decision ledger records post-change trust status.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Verification Failed</h3>
                        <ul>
                            <li>Support group or owner changed without confirmation.</li>
                            <li>Access route, access removal, or approver evidence is missing.</li>
                            <li>Lifecycle state remains unsupported.</li>
                            <li>Rollback evidence or post-change evidence is missing.</li>
                            <li>Hidden dependency still has no governed record.</li>
                            <li>Trust score improved without actual evidence closure.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Post-Change Verification Queue</h2>
                <p>
                    These actions must close before the CI can be treated as trusted after change.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Verification Gap</th>
                            <th>Why It Matters</th>
                            <th>Required Action</th>
                            <th>Expected Trust Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no post-change verification model.</td>
                            <td>Recurring backup review may be affected without any governed verification trail.</td>
                            <td>Create governed candidate and define support, access, evidence, lifecycle, and post-change verification controls.</td>
                            <td>No Verification Model → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS closure verification failed.</td>
                            <td>Closure cannot be trusted without access removal and lifecycle evidence.</td>
                            <td>Attach closure evidence, confirm access deactivation, and update decision ledger.</td>
                            <td>Verification Failed → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover verification is pending.</td>
                            <td>Cutover-sensitive systems need post-cutover support, access, vendor, rollback, and evidence checks.</td>
                            <td>Complete post-cutover evidence, support confirmation, MyAccess check, jump path check, and rollback confirmation.</td>
                            <td>Verification Pending → Trust Reconfirmed</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access-path verification evidence is partial.</td>
                            <td>Privileged access changes must be proven after implementation.</td>
                            <td>Attach admin/vendor procedure, access review proof, and post-access verification evidence.</td>
                            <td>Conditional Verification → Audit-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow change management, MyAccess approvals, rollback execution, validation testing, audit systems, or human governance. This post-change verification console is a governance assurance overlay for confirming post-change owner accuracy, support routing, access readiness, lifecycle state, dependency integrity, evidence refresh, rollback closure, decision ledger update, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_POST_CHANGE_VERIFICATION_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Post-Change Verification Console installed.")
