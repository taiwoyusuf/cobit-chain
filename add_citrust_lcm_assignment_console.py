from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_LCM_ASSIGNMENT_CONSOLE_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/lcm-assignment-console")'
ROUTE_ALIAS = '@app.route("/citrust/lcm-readiness")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust LCM Assignment Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_LCM_ASSIGNMENT_CONSOLE_V1_ACTIVE
# ============================================================

@app.route("/citrust/lcm-assignment-console")
@app.route("/citrust/lcm-readiness")
def citrust_lcm_assignment_console():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ LCM Assignment Console</title>
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
                    radial-gradient(circle at top right, rgba(180,156,255,0.16), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(49,208,125,0.08), transparent 30%),
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
                border: 1px solid rgba(92,200,255,0.36);
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
                <h1>CITrust™ LCM Assignment Console</h1>

                <div class="subtitle">
                    Validates whether each Configuration Item has a defensible Lifecycle Manager, backup accountability, lifecycle state, training readiness, escalation path, evidence basis, and review cadence before the CI can be operationally trusted or prepared for ServiceNow-style submission.
                </div>

                <div class="positioning">
                    <strong>LCM boundary:</strong>
                    CITrust™ does not assign ServiceNow roles, create ServiceNow CIs, or update CMDB ownership fields in this demo. It validates whether lifecycle accountability is complete enough for CI trust, audit readiness, operational support, and governance defensibility.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/ownership-readiness">Ownership Readiness</a>
                    <a href="/citrust/lifecycle-readiness">Lifecycle Readiness</a>
                    <a href="/citrust/mandatory-fields-checklist">Mandatory Fields</a>
                    <a href="/citrust/readiness-attestation">Attestation Center</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">LCM-Relevant CIs</div>
                    <div class="value">42</div>
                    <div class="note">Records requiring lifecycle accountability before trust can be defended.</div>
                </div>

                <div class="metric">
                    <div class="label">LCM Assigned</div>
                    <div class="value" style="color: var(--green);">24</div>
                    <div class="note">CIs with named lifecycle accountability.</div>
                </div>

                <div class="metric">
                    <div class="label">LCM Pending</div>
                    <div class="value" style="color: var(--yellow);">11</div>
                    <div class="note">CIs with likely LCM but incomplete confirmation or evidence.</div>
                </div>

                <div class="metric">
                    <div class="label">LCM Missing</div>
                    <div class="value" style="color: var(--red);">7</div>
                    <div class="note">Records blocked from lifecycle trust or submission readiness.</div>
                </div>

                <div class="metric">
                    <div class="label">Backup LCM Missing</div>
                    <div class="value" style="color: var(--orange);">13</div>
                    <div class="note">Records with single-person lifecycle dependency risk.</div>
                </div>

                <div class="metric">
                    <div class="label">Attestation Ready</div>
                    <div class="value" style="color: var(--blue);">16</div>
                    <div class="note">Records ready for owner or lifecycle attestation review.</div>
                </div>
            </section>

            <section class="section">
                <h2>LCM Assignment Answer</h2>
                <p>
                    This console answers whether lifecycle accountability is strong enough for CI trust.
                </p>

                <div class="answer">
                    <strong>Current LCM interpretation:</strong>
                    CITrust™ should not treat a CI as operationally trusted unless lifecycle accountability is clear. A record may have an owner and support group, but still remain conditional if the Lifecycle Manager, backup owner, lifecycle state, evidence, training status, and escalation path are incomplete or not defensible.
                </div>
            </section>

            <section class="section">
                <h2>LCM Governance Domains</h2>
                <p>
                    CITrust™ separates lifecycle accountability into the controls needed for defensible CI governance.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Primary LCM</h3>
                        <p>The accountable lifecycle manager responsible for active, cutover, OOS, retirement, closure, and transition-state governance.</p>
                    </div>

                    <div class="card">
                        <h3>Backup LCM</h3>
                        <p>Secondary lifecycle accountability to prevent single-person dependency and continuity failure.</p>
                    </div>

                    <div class="card">
                        <h3>Lifecycle Evidence</h3>
                        <p>Proof supporting active state, OOS state, closure, retirement, access removal, cutover, or transition readiness.</p>
                    </div>

                    <div class="card">
                        <h3>LCM Readiness</h3>
                        <p>Training, role access, escalation path, decision authority, and review cadence needed for accountable lifecycle governance.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>LCM Assignment Matrix</h2>
                <p>
                    This matrix shows whether each CI has defensible lifecycle accountability.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Primary LCM</th>
                            <th>Backup LCM</th>
                            <th>Lifecycle State</th>
                            <th>Training / Role Readiness</th>
                            <th>Evidence Basis</th>
                            <th>LCM Decision</th>
                            <th>Next Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-green">Ready</span></td>
                            <td>Owner, support, lifecycle, and evidence references are available.</td>
                            <td><span class="badge green">LCM-Ready</span></td>
                            <td>Maintain periodic lifecycle review.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">Cutover-sensitive BMS dependency</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-yellow">Cutover Active</span></td>
                            <td><span class="badge soft-yellow">Role Confirmation Needed</span></td>
                            <td>Cutover context exists, but support, jump path, and access evidence remain partial.</td>
                            <td><span class="badge yellow">Conditional LCM</span></td>
                            <td>Confirm backup LCM, role readiness, cutover evidence, and escalation path.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Recommended</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-green">Ready</span></td>
                            <td>Access path is known, but procedure evidence should be linked.</td>
                            <td><span class="badge yellow">LCM Conditional</span></td>
                            <td>Attach admin/vendor access procedure and identify backup lifecycle owner.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-yellow">Likely Assigned</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-green">Operational</span></td>
                            <td><span class="badge soft-yellow">Needs Confirmation</span></td>
                            <td>Operational context exists, but support and lifecycle evidence need reconciliation.</td>
                            <td><span class="badge yellow">Conditional LCM</span></td>
                            <td>Confirm LCM, backup LCM, support group, and lifecycle evidence path.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-yellow">Access Role Check</span></td>
                            <td>Core lifecycle evidence is strong; access approver evidence needs confirmation.</td>
                            <td><span class="badge yellow">Near LCM-Ready</span></td>
                            <td>Confirm MyAccess approver group and role evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">OOS Closure Needed</span></td>
                            <td><span class="badge soft-red">Not Defensible</span></td>
                            <td>Closure evidence and access deactivation proof are missing.</td>
                            <td><span class="badge red">LCM Blocked</span></td>
                            <td>Assign lifecycle owner, attach closure evidence, and confirm access removal.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Discovered</span></td>
                            <td><span class="badge soft-red">Not Ready</span></td>
                            <td>No governed candidate, owner, support, access, evidence, or cadence exists.</td>
                            <td><span class="badge red">LCM Missing</span></td>
                            <td>Create governed candidate and assign lifecycle accountability.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>LCM Readiness Decision Logic</h2>
                <p>
                    Lifecycle accountability must be evidence-backed, not assumed.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>LCM-Ready CI</h3>
                        <ul>
                            <li>Primary Lifecycle Manager is assigned and current.</li>
                            <li>Backup lifecycle accountability is defined where needed.</li>
                            <li>Lifecycle state is evidence-backed.</li>
                            <li>LCM has role readiness or access to perform governance duties.</li>
                            <li>Escalation path is known.</li>
                            <li>Review cadence is defined and current.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>LCM-Blocked CI</h3>
                        <ul>
                            <li>No lifecycle owner exists.</li>
                            <li>OOS or retired record lacks closure evidence.</li>
                            <li>Access removal cannot be confirmed.</li>
                            <li>Lifecycle state conflicts across sources.</li>
                            <li>Cutover state is active but owner, evidence, or escalation is unclear.</li>
                            <li>Hidden dependency has no governed candidate record.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>LCM Remediation Queue</h2>
                <p>
                    These actions close lifecycle accountability gaps before CITrust™ trust, attestation, or submission-readiness can be defended.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>LCM Gap</th>
                            <th>Why It Matters</th>
                            <th>Required Action</th>
                            <th>Expected Readiness Upgrade</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no lifecycle owner.</td>
                            <td>Recurring operational dependency cannot be governed without lifecycle accountability.</td>
                            <td>Create governed candidate and assign primary LCM, backup LCM, support group, and evidence path.</td>
                            <td>LCM Missing → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment lacks lifecycle closure evidence.</td>
                            <td>OOS state cannot be defended without closure and access deactivation proof.</td>
                            <td>Assign lifecycle owner, attach closure evidence, and confirm access removal.</td>
                            <td>LCM Blocked → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover record has partial lifecycle accountability.</td>
                            <td>Cutover-sensitive CIs need clear lifecycle owner, backup owner, escalation, and evidence.</td>
                            <td>Confirm backup LCM, support path, MyAccess role, jump path, and cutover evidence.</td>
                            <td>Conditional LCM → LCM-Ready</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Backup LCM missing for active access path.</td>
                            <td>Single-person lifecycle dependency can weaken operational continuity.</td>
                            <td>Identify backup lifecycle owner and attach access procedure evidence.</td>
                            <td>LCM Conditional → Continuity-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, update CMDB lifecycle fields, assign LCM roles, or approve lifecycle changes in this demo. This LCM assignment console is a governance assurance overlay for lifecycle accountability, primary LCM readiness, backup LCM readiness, lifecycle evidence, OOS closure, access deactivation, cutover accountability, audit defensibility, ServiceNow-readiness, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_LCM_ASSIGNMENT_CONSOLE_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust LCM Assignment Console installed.")
