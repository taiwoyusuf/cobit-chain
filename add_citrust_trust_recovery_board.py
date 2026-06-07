from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_TRUST_RECOVERY_BOARD_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/trust-recovery-board")'
ROUTE_ALIAS = '@app.route("/citrust/trust-recovery")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Trust Recovery Board already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_TRUST_RECOVERY_BOARD_V1_ACTIVE
# ============================================================

@app.route("/citrust/trust-recovery-board")
@app.route("/citrust/trust-recovery")
def citrust_trust_recovery_board():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Trust Recovery Board</title>
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
                    radial-gradient(circle at bottom right, rgba(255,92,112,0.10), transparent 30%),
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
                <h1>CITrust™ Trust Recovery Board</h1>

                <div class="subtitle">
                    Converts trust-decay findings into governed recovery actions so conditional, decayed, blocked, or unmanaged Configuration Items can return to evidence-backed operational trust.
                </div>

                <div class="positioning">
                    <strong>Recovery boundary:</strong>
                    CITrust™ does not update ServiceNow, approve access, execute remediation, close quality events, or replace human governance. It defines the recovery path, evidence required, accountable owner, and readiness decision needed to restore CI trust.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/trust-decay-forecast">Trust Decay Forecast</a>
                    <a href="/citrust/continuous-trust-monitor">Continuous Trust</a>
                    <a href="/citrust/evidence-drift-monitor">Evidence Drift</a>
                    <a href="/citrust/post-change-verification">Post-Change Verification</a>
                    <a href="/citrust/governance-debt-register">Governance Debt</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Recovery Candidates</div>
                    <div class="value">28</div>
                    <div class="note">CIs needing recovery from conditional, decayed, blocked, or unmanaged trust status.</div>
                </div>

                <div class="metric">
                    <div class="label">Recoverable Now</div>
                    <div class="value" style="color: var(--green);">9</div>
                    <div class="note">Records that can be restored with targeted evidence refresh or confirmation.</div>
                </div>

                <div class="metric">
                    <div class="label">Needs Owner Action</div>
                    <div class="value" style="color: var(--yellow);">11</div>
                    <div class="note">Records requiring CI owner, support group, LCM, or MyAccess confirmation.</div>
                </div>

                <div class="metric">
                    <div class="label">Escalation Required</div>
                    <div class="value" style="color: var(--orange);">5</div>
                    <div class="note">Records requiring governance, access, lifecycle, or executive escalation.</div>
                </div>

                <div class="metric">
                    <div class="label">Blocked Recovery</div>
                    <div class="value" style="color: var(--red);">3</div>
                    <div class="note">Records with no recovery path until critical ownership or evidence gaps close.</div>
                </div>

                <div class="metric">
                    <div class="label">Trust Restored</div>
                    <div class="value" style="color: var(--blue);">7</div>
                    <div class="note">Records where trust can be reconfirmed after recovery evidence is attached.</div>
                </div>
            </section>

            <section class="section">
                <h2>Trust Recovery Answer</h2>
                <p>
                    This board answers what must happen to restore trust after decay, drift, or failed verification.
                </p>

                <div class="answer">
                    <strong>Current recovery interpretation:</strong>
                    Trust recovery requires more than changing a dashboard color. The recovery action must close the reason trust decayed: stale evidence, missing owner, unresolved support group, incomplete MyAccess mapping, lifecycle ambiguity, failed post-change verification, missing rollback proof, vendor-handoff weakness, or hidden dependency governance.
                </div>
            </section>

            <section class="section">
                <h2>Trust Recovery Domains</h2>
                <p>
                    CITrust™ separates recovery work into domains so each trust gap has an accountable closure path.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Evidence Recovery</h3>
                        <p>Refreshes stale or missing proof for owner, support, access, lifecycle, evidence pack, rollback, and post-change verification.</p>
                    </div>

                    <div class="card">
                        <h3>Accountability Recovery</h3>
                        <p>Restores CI owner, support group, LCM, backup owner, governance reviewer, and escalation accountability.</p>
                    </div>

                    <div class="card">
                        <h3>Access Recovery</h3>
                        <p>Closes MyAccess role, approver group, admin path, vendor route, access removal, and privileged access evidence gaps.</p>
                    </div>

                    <div class="card">
                        <h3>Lifecycle Recovery</h3>
                        <p>Restores defensibility for active, cutover, OOS, retired, closed, rollback, or post-change lifecycle states.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Trust Recovery Matrix</h2>
                <p>
                    This matrix shows the recovery path for decayed or conditional CI records.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Trust Problem</th>
                            <th>Recovery Type</th>
                            <th>Accountable Owner</th>
                            <th>Required Evidence</th>
                            <th>Recovery Decision</th>
                            <th>Expected Trust State</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>No material trust decay.</td>
                            <td><span class="badge soft-green">Maintain</span></td>
                            <td>Application Governance / CI Owner</td>
                            <td>Periodic review and evidence refresh.</td>
                            <td><span class="badge green">No Recovery Needed</span></td>
                            <td><span class="badge green">Trusted</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td>Cutover trust remains conditional due to support, MyAccess, jump path, vendor, rollback, and post-change evidence gaps.</td>
                            <td><span class="badge orange">Cutover Recovery</span></td>
                            <td>Infrastructure / Cutover Owner / Access Governance</td>
                            <td>Support group, MyAccess role, jump path evidence, vendor handoff, rollback plan, post-cutover checks.</td>
                            <td><span class="badge yellow">Recoverable With Evidence</span></td>
                            <td><span class="badge blue">Trust Reconfirmed</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Access trust is conditional because admin/vendor procedure and access review evidence are partial.</td>
                            <td><span class="badge yellow">Access Recovery</span></td>
                            <td>Infrastructure / Access Governance</td>
                            <td>Admin/vendor procedure, access review proof, escalation owner, post-access verification evidence.</td>
                            <td><span class="badge yellow">Recoverable Now</span></td>
                            <td><span class="badge green">Audit-Ready</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Support, LCM, access route, evidence path, and operational classification are partial.</td>
                            <td><span class="badge yellow">Support Recovery</span></td>
                            <td>Operational Owner / CMDB Governance</td>
                            <td>Support group confirmation, LCM evidence, access route, evidence location, classification reconciliation.</td>
                            <td><span class="badge yellow">Owner Action Needed</span></td>
                            <td><span class="badge blue">Conditional To Trusted</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>Near trusted; MyAccess approver group and role evidence need final confirmation.</td>
                            <td><span class="badge yellow">Access Confirmation</span></td>
                            <td>Application Governance / MyAccess Governance</td>
                            <td>Approver group evidence, role mapping, access escalation, access review evidence.</td>
                            <td><span class="badge green">Recoverable Now</span></td>
                            <td><span class="badge green">Trusted</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>Trust decayed because OOS closure, access deactivation, closure owner, and lifecycle evidence are missing.</td>
                            <td><span class="badge red">Lifecycle Recovery</span></td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td>Closure evidence, access removal proof, closure owner, lifecycle decision, decision ledger update.</td>
                            <td><span class="badge red">Recovery Blocked Until Evidence Attached</span></td>
                            <td><span class="badge blue">Closed / Defensible</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>No trust basis because the CI-like dependency has no governed candidate, owner, support, access, evidence, cadence, or verification model.</td>
                            <td><span class="badge red">Governance Recovery</span></td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td>Candidate record, owner, support group, LCM, access route, backup review evidence, cadence, escalation path.</td>
                            <td><span class="badge red">Create Candidate First</span></td>
                            <td><span class="badge yellow">Candidate Review</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Trust Recovery Decision Logic</h2>
                <p>
                    Recovery must close the cause of trust decay, not mask it.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Trust Can Be Recovered</h3>
                        <ul>
                            <li>Recovery owner is assigned.</li>
                            <li>Cause of decay is known.</li>
                            <li>Required evidence is specific and obtainable.</li>
                            <li>Support, access, lifecycle, or evidence gap has a closure action.</li>
                            <li>Post-recovery verification is defined.</li>
                            <li>Decision ledger will update after closure.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Recovery Must Be Blocked</h3>
                        <ul>
                            <li>No owner exists for the recovery action.</li>
                            <li>Required evidence cannot be identified.</li>
                            <li>OOS or retired state lacks closure proof.</li>
                            <li>Hidden dependency has no governed candidate record.</li>
                            <li>Access removal or access route cannot be defended.</li>
                            <li>Recovery would only change status without evidence closure.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Trust Recovery Action Queue</h2>
                <p>
                    These actions restore trust where decay, drift, or failed verification exists.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Recovery Action</th>
                            <th>Why It Matters</th>
                            <th>Evidence Required</th>
                            <th>Expected Recovery Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Create governed candidate for hidden backup review workstation.</td>
                            <td>No trust can be recovered until the dependency has a governed CI candidate model.</td>
                            <td>Candidate record, owner, support group, LCM, access path, backup evidence, cadence, escalation.</td>
                            <td>No Trust Basis → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Close OOS lifecycle recovery gap.</td>
                            <td>OOS record remains blocked until closure and access removal are defensible.</td>
                            <td>Closure evidence, access deactivation proof, closure owner, lifecycle decision, decision ledger update.</td>
                            <td>Trust Decayed → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Recover BMS cutover trust.</td>
                            <td>Cutover-sensitive CI requires support, access, vendor, rollback, and post-change evidence.</td>
                            <td>Support group, MyAccess role, jump path, vendor handoff, rollback readiness, post-cutover verification.</td>
                            <td>Conditional → Trust Reconfirmed</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Recover privileged access trust.</td>
                            <td>Admin and vendor access must be defensible with current procedure and review evidence.</td>
                            <td>Admin/vendor procedure, access review proof, access escalation owner, post-access verification.</td>
                            <td>Conditional → Audit-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, MyAccess, change control, audit systems, validation systems, remediation ownership, or human governance. This trust recovery board is a governance assurance overlay for restoring decayed CI trust, refreshing evidence, closing ownership gaps, resolving support gaps, confirming access, closing lifecycle ambiguity, recovering rollback readiness, confirming post-change verification, updating the decision ledger, and preventing future trust decay.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_TRUST_RECOVERY_BOARD_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Trust Recovery Board installed.")
