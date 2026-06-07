from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_REMEDIATION_BOARD_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/remediation-board")'
ROUTE_ALIAS = '@app.route("/citrust/remediation-command")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Remediation Board already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_REMEDIATION_BOARD_V1_ACTIVE
# ============================================================

@app.route("/citrust/remediation-board")
@app.route("/citrust/remediation-command")
def citrust_remediation_board():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Remediation Board</title>
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
                    radial-gradient(circle at top left, rgba(49,208,125,0.14), transparent 30%),
                    radial-gradient(circle at top right, rgba(92,200,255,0.16), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(255,92,112,0.09), transparent 30%),
                    var(--bg);
                color: var(--text);
            }

            .page {
                max-width: 1400px;
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
                font-size: 39px;
                line-height: 1.1;
            }

            .subtitle {
                color: var(--muted);
                font-size: 16px;
                line-height: 1.6;
                max-width: 1080px;
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

            .flow {
                display: grid;
                grid-template-columns: repeat(5, 1fr);
                gap: 12px;
                margin-top: 16px;
            }

            .flow-step {
                border: 1px solid rgba(49,208,125,0.28);
                background: rgba(49,208,125,0.07);
                border-radius: 18px;
                padding: 16px;
            }

            .flow-step h3 {
                margin: 0 0 8px 0;
                font-size: 15px;
            }

            .flow-step p {
                margin: 0;
                font-size: 13px;
                color: var(--muted);
                line-height: 1.5;
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
                .kpis, .flow, .cards, .two-col {
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
                <h1>CITrust™ Remediation Board</h1>

                <div class="subtitle">
                    Converts CITrust™ findings into governed remediation actions across ownership, support group, LCM, MyAccess, evidence lineage, dependency lineage, lifecycle state, data quality, classification, audit readiness, and ServiceNow-readiness.
                </div>

                <div class="positioning">
                    <strong>Remediation boundary:</strong>
                    CITrust™ does not create ServiceNow tasks, does not update CMDB records, and does not bypass human governance in this demo. This board identifies what must be remediated before a CI can become operationally trusted, ServiceNow-ready, MyAccess-ready, audit-ready, or submission-ready.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/executive-reasoning-panel">Executive Reasoning</a>
                    <a href="/citrust/bottleneck-analysis">Bottleneck Analysis</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                    <a href="/citrust/trust-score-model">Trust Score Model</a>
                    <a href="/citrust/submission-board">Submission Board</a>
                    <a href="/citrust/pre-deviation-readiness">Pre-Deviation Readiness</a>
                    <a href="/citrust/orphans">Orphan CI Intelligence</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Open Remediation Items</div>
                    <div class="value">24</div>
                    <div class="note">Actions needed before CI records can be fully trusted.</div>
                </div>

                <div class="metric">
                    <div class="label">Critical Actions</div>
                    <div class="value" style="color: var(--red);">6</div>
                    <div class="note">Blocking issues that prevent ServiceNow-readiness or audit-readiness.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Actions</div>
                    <div class="value" style="color: var(--yellow);">11</div>
                    <div class="note">Items needed to move records from conditional to trusted.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Actions</div>
                    <div class="value" style="color: var(--orange);">9</div>
                    <div class="note">SOP, backup, audit trail, closure, validation, or access evidence actions.</div>
                </div>

                <div class="metric">
                    <div class="label">Ownership Actions</div>
                    <div class="value" style="color: var(--blue);">7</div>
                    <div class="note">Owner, support group, LCM, or escalation-path actions.</div>
                </div>

                <div class="metric">
                    <div class="label">Unlock Candidates</div>
                    <div class="value" style="color: var(--green);">13</div>
                    <div class="note">Records likely to move forward after remediation is complete.</div>
                </div>
            </section>

            <section class="section">
                <h2>Remediation Board Answer</h2>
                <p>
                    This board answers what must be fixed, who should fix it, and which readiness state will be unlocked.
                </p>

                <div class="answer">
                    <strong>Current remediation interpretation:</strong>
                    The fastest path to improving CITrust™ readiness is to close evidence gaps, assign owners for hidden dependencies, confirm support groups, finalize MyAccess mappings, reconcile OOS lifecycle records, and attach closure or cutover evidence. These actions will move multiple records from blocked or conditional state toward trusted, submission-ready, and audit-defensible status.
                </div>
            </section>

            <section class="section">
                <h2>Remediation Flow</h2>
                <p>
                    CITrust™ separates remediation into governed stages so records are not pushed forward before the blockers are resolved.
                </p>

                <div class="flow">
                    <div class="flow-step">
                        <h3>1. Identify Gap</h3>
                        <p>Finding comes from risk heatmap, bottleneck analysis, orphan intelligence, audit readiness, or trust scoring.</p>
                    </div>

                    <div class="flow-step">
                        <h3>2. Assign Workstream</h3>
                        <p>Route to CMDB governance, infrastructure, MyAccess, lifecycle, evidence, or application governance.</p>
                    </div>

                    <div class="flow-step">
                        <h3>3. Attach Evidence</h3>
                        <p>Link owner proof, support confirmation, access mapping, SOP, backup, closure, or cutover evidence.</p>
                    </div>

                    <div class="flow-step">
                        <h3>4. Re-score CI</h3>
                        <p>Update readiness interpretation from blocked to conditional, or conditional to trusted.</p>
                    </div>

                    <div class="flow-step">
                        <h3>5. Move Forward</h3>
                        <p>Proceed to passport, submission pack, audit readiness, or executive trust reporting only after remediation.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Remediation Action Board</h2>
                <p>
                    This matrix shows the concrete remediation action needed for each weak CI record.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Current State</th>
                            <th>Remediation Action</th>
                            <th>Responsible Workstream</th>
                            <th>Evidence Required</th>
                            <th>Unlocks</th>
                            <th>Priority</th>
                            <th>Target Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge red">Blocked</span></td>
                            <td>Create governed CI candidate; assign owner, support group, LCM, access path, classification, and evidence link.</td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td>Backup review evidence, owner confirmation, support group, LCM, access path.</td>
                            <td>Candidate Review / Evidence Lineage / Audit Readiness</td>
                            <td><span class="badge red">Critical</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge red">Blocked</span></td>
                            <td>Confirm OOS closure, attach closure evidence, verify access deactivation, and reconcile lifecycle owner.</td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td>Closure evidence, access removal proof, lifecycle decision, owner confirmation.</td>
                            <td>Lifecycle Readiness / Audit Defense / Orphan Reduction</td>
                            <td><span class="badge red">Critical</span></td>
                            <td><span class="badge green">Closed / Defensible</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Finalize support group, MyAccess role mapping, jump path dependency, and cutover evidence reference.</td>
                            <td>Infrastructure / MyAccess Governance</td>
                            <td>Support group confirmation, access role evidence, jump path evidence, cutover evidence.</td>
                            <td>Change Impact / Access Readiness / Trust Score Increase</td>
                            <td><span class="badge orange">High</span></td>
                            <td><span class="badge green">Trusted</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Reconcile support group, owner, lifecycle state, evidence path, and operational classification.</td>
                            <td>Operational Owner / CMDB Governance</td>
                            <td>Support group confirmation, owner evidence, lifecycle state, operational evidence.</td>
                            <td>Support Readiness / Data Quality / Submission Board</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge green">ServiceNow-Ready</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Attach admin-access procedure, vendor-access governance artifact, and support routing context.</td>
                            <td>Infrastructure / Access Governance</td>
                            <td>Admin access procedure, vendor access evidence, support routing model.</td>
                            <td>Audit Readiness / Access Readiness / Evidence Lineage</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge green">Trusted</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Confirm MyAccess approver group, requestable roles, and access evidence.</td>
                            <td>Application Governance / MyAccess Governance</td>
                            <td>Approver group confirmation, role mapping evidence, access pathway.</td>
                            <td>MyAccess Readiness / Audit Readiness / Trust Score Increase</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge green">Access-Ready</span></td>
                        </tr>

                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge green">Trusted</span></td>
                            <td>Maintain periodic governance review and confirm owner/support/access evidence remains current.</td>
                            <td>Application Governance / CMDB Governance</td>
                            <td>Periodic review evidence, owner confirmation, support/access review.</td>
                            <td>Continued Trust / Audit Defense</td>
                            <td><span class="badge green">Low</span></td>
                            <td><span class="badge green">Maintain Trusted</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Remediation Workstreams</h2>
                <p>
                    CITrust™ groups remediation by accountable governance domain.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>CMDB Governance</h3>
                        <p>Resolve missing CI fields, candidate records, duplicate risk, classification, owner, support group, and submission readiness.</p>
                    </div>

                    <div class="card">
                        <h3>MyAccess Governance</h3>
                        <p>Confirm approver groups, access roles, requestability, privileged access, vendor access, and access evidence.</p>
                    </div>

                    <div class="card">
                        <h3>Lifecycle Governance</h3>
                        <p>Resolve active, OOS, retired, cutover, closure, access deactivation, and lifecycle accountability issues.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Governance</h3>
                        <p>Attach SOP, backup, audit trail, validation, closure, cutover, access, and submission evidence to the CI record.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Remediation Decision Logic</h2>
                <p>
                    Remediation should unlock a defined readiness state.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Remediation Complete</h3>
                        <ul>
                            <li>Required owner, support group, and LCM are assigned.</li>
                            <li>MyAccess routing and access roles are mapped.</li>
                            <li>Evidence is linked and reviewable.</li>
                            <li>Lifecycle state is reconciled.</li>
                            <li>Dependency and classification are clear.</li>
                            <li>Readiness status can be upgraded with defensible reasoning.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Remediation Incomplete</h3>
                        <ul>
                            <li>Owner, support group, LCM, or escalation path remains unclear.</li>
                            <li>Access route is still not defensible.</li>
                            <li>Evidence is missing or disconnected.</li>
                            <li>OOS, retired, or cutover state is unresolved.</li>
                            <li>Hidden dependency remains ungoverned.</li>
                            <li>Submission would create weak or orphaned CMDB data.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Remediation Priorities</h2>
                <p>
                    These are the highest-value remediation priorities for leadership visibility.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Remediation Theme</th>
                            <th>Why It Matters</th>
                            <th>Immediate Action</th>
                            <th>Expected Business Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden Operational Dependencies</td>
                            <td>Undocumented workstations or review dependencies create audit and operational blind spots.</td>
                            <td>Create governed CI candidates and assign accountability.</td>
                            <td>Reduces orphan CI and audit exposure.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS / Retired Closure</td>
                            <td>Unclosed records can create lifecycle, access, and audit ambiguity.</td>
                            <td>Attach closure evidence and confirm access deactivation.</td>
                            <td>Improves lifecycle defensibility.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Cutover-Sensitive Records</td>
                            <td>Cutover records require support, access, dependency, and evidence readiness before reliance.</td>
                            <td>Finalize support routing, jump path, MyAccess mapping, and cutover evidence.</td>
                            <td>Improves transition readiness.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access Routing Confirmation</td>
                            <td>Weak approver group or role mapping can create unsupported access approvals.</td>
                            <td>Confirm MyAccess routing and role evidence.</td>
                            <td>Improves access governance defensibility.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow tasks, create ServiceNow CIs, update CMDB data, or write remediation actions directly into ServiceNow in this demo. This remediation board is a governance assurance overlay for converting CITrust™ findings into evidence-backed remediation actions across ownership, support group, LCM, MyAccess, evidence lineage, dependency lineage, lifecycle readiness, data quality, classification, audit readiness, and ServiceNow-readiness.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_REMEDIATION_BOARD_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Remediation Board installed.")
