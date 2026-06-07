from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_FIELD_CONFLICT_RESOLUTION_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/field-conflict-resolution")'
ROUTE_ALIAS = '@app.route("/citrust/conflict-resolution")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Field Conflict Resolution Board already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_FIELD_CONFLICT_RESOLUTION_V1_ACTIVE
# ============================================================

@app.route("/citrust/field-conflict-resolution")
@app.route("/citrust/conflict-resolution")
def citrust_field_conflict_resolution():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Field Conflict Resolution Board</title>
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
                    radial-gradient(circle at top left, rgba(255,92,112,0.14), transparent 30%),
                    radial-gradient(circle at top right, rgba(92,200,255,0.16), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(247,201,72,0.08), transparent 30%),
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
                <h1>CITrust™ Field Conflict Resolution Board</h1>

                <div class="subtitle">
                    Resolves conflicts between ServiceNow-style records, MyAccess, Blue Mountain, master lists, CI candidate intake, evidence repositories, support routing sources, lifecycle artifacts, and operational discovery before a Configuration Item is trusted or submitted.
                </div>

                <div class="positioning">
                    <strong>Conflict resolution boundary:</strong>
                    CITrust™ does not overwrite ServiceNow, MyAccess, Blue Mountain, or other source systems in this demo. It identifies field conflicts, recommends the authoritative source, documents the governance rationale, and prevents weak or contradictory CI data from becoming trusted.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/source-of-truth-map">Source-of-Truth Map</a>
                    <a href="/citrust/reconciliation">CMDB Reconciliation</a>
                    <a href="/citrust/data-quality-readiness">Data Quality</a>
                    <a href="/citrust/mandatory-fields-checklist">Mandatory Fields</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                    <a href="/citrust/executive-reasoning-panel">Executive Reasoning</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Field Conflicts Found</div>
                    <div class="value">22</div>
                    <div class="note">Conflicts across owner, support group, CI class, lifecycle, access, evidence, and relationships.</div>
                </div>

                <div class="metric">
                    <div class="label">Resolved Conflicts</div>
                    <div class="value" style="color: var(--green);">9</div>
                    <div class="note">Conflicts with clear authoritative source and documented decision.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Conflicts</div>
                    <div class="value" style="color: var(--yellow);">8</div>
                    <div class="note">Conflicts with known path but pending confirmation or evidence.</div>
                </div>

                <div class="metric">
                    <div class="label">Blocking Conflicts</div>
                    <div class="value" style="color: var(--red);">5</div>
                    <div class="note">Conflicts that should block trust, attestation, or submission.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Overrides</div>
                    <div class="value" style="color: var(--orange);">6</div>
                    <div class="note">Evidence needed to override stale or conflicting source data.</div>
                </div>

                <div class="metric">
                    <div class="label">Escalations Needed</div>
                    <div class="value" style="color: var(--blue);">4</div>
                    <div class="note">Conflicts requiring owner, support, access, or lifecycle governance decision.</div>
                </div>
            </section>

            <section class="section">
                <h2>Conflict Resolution Answer</h2>
                <p>
                    This board answers which field value should be trusted when sources disagree.
                </p>

                <div class="answer">
                    <strong>Current conflict interpretation:</strong>
                    Several CI fields should remain conditional or blocked because source systems do not fully agree. The highest-risk conflicts involve OOS lifecycle state, support group ownership, MyAccess approver routing, hidden dependency identity, and evidence location. CITrust™ should not allow those records to become ServiceNow-ready until the conflict is resolved or formally documented.
                </div>
            </section>

            <section class="section">
                <h2>Field Conflict Resolution Matrix</h2>
                <p>
                    This matrix shows the conflicting field, competing sources, recommended authority, and governance decision.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>CI / Record</th>
                            <th>Conflicting Field</th>
                            <th>Source A</th>
                            <th>Source B</th>
                            <th>Recommended Authority</th>
                            <th>Decision</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">Cutover-sensitive BMS dependency</span></td>
                            <td>Support Group / Access Route</td>
                            <td>Candidate intake shows cutover-dependent support.</td>
                            <td>Operational discussion indicates jump-path dependency.</td>
                            <td><span class="badge blue">Infrastructure + MyAccess Governance</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Confirm support group, MyAccess role, jump path, and cutover evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>Lifecycle State</td>
                            <td>Legacy inventory may still show equipment record.</td>
                            <td>Operational state indicates OOS / closure needed.</td>
                            <td><span class="badge orange">Lifecycle Evidence</span></td>
                            <td><span class="badge red">Blocked</span></td>
                            <td>Attach OOS closure evidence and confirm access deactivation.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Support Group</td>
                            <td>Candidate record shows pending support mapping.</td>
                            <td>Operational ownership is known but not fully reconciled.</td>
                            <td><span class="badge blue">CMDB Governance + Operational Owner</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Reconcile support group against owner, LCM, and evidence path.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>CI Identity / Dependency Status</td>
                            <td>Operational discovery indicates workstation dependency.</td>
                            <td>No governed CI candidate exists.</td>
                            <td><span class="badge red">Candidate Review Board</span></td>
                            <td><span class="badge red">Blocked</span></td>
                            <td>Create governed candidate and define identity, owner, support, LCM, access, and evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Admin and vendor access route</span></td>
                            <td>Evidence Link</td>
                            <td>Access model is understood operationally.</td>
                            <td>Formal admin-access procedure evidence is not linked.</td>
                            <td><span class="badge purple">Access Governance Evidence</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Attach admin or vendor access procedure evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>Approver Group</td>
                            <td>Application record appears strong.</td>
                            <td>MyAccess approver route needs confirmation.</td>
                            <td><span class="badge blue">MyAccess Authority</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Confirm approver group and access role evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>No material conflict</td>
                            <td>Application and governance data align.</td>
                            <td>Evidence supports operational state.</td>
                            <td><span class="badge green">Current Source Authority</span></td>
                            <td><span class="badge green">Resolved</span></td>
                            <td>Maintain periodic review.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Conflict Types</h2>
                <p>
                    CITrust™ classifies conflicts so remediation is precise.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Ownership Conflict</h3>
                        <p>Different sources disagree on who owns, supports, or governs the CI lifecycle.</p>
                    </div>

                    <div class="card">
                        <h3>Access Conflict</h3>
                        <p>MyAccess roles, approver groups, admin paths, vendor access routes, or requestability do not align.</p>
                    </div>

                    <div class="card">
                        <h3>Lifecycle Conflict</h3>
                        <p>Active, cutover, OOS, retired, or closed state is inconsistent across records and evidence.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Conflict</h3>
                        <p>Field values exist, but evidence either contradicts them or does not support them.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Conflict Resolution Rules</h2>
                <p>
                    These rules prevent weak source data from becoming trusted CI data.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Resolve and Move Forward</h3>
                        <ul>
                            <li>Authoritative source is identified.</li>
                            <li>Conflicting field is corrected or documented.</li>
                            <li>Evidence supports the selected value.</li>
                            <li>Owner, support group, LCM, access, or lifecycle authority is confirmed.</li>
                            <li>Decision is visible in executive reasoning and remediation board.</li>
                            <li>Record can proceed to passport or submission-pack preparation.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Hold or Block</h3>
                        <ul>
                            <li>No authoritative source can be identified.</li>
                            <li>Source conflict affects owner, support group, LCM, access, lifecycle, or evidence.</li>
                            <li>OOS or retired state lacks closure evidence.</li>
                            <li>MyAccess route cannot be defended.</li>
                            <li>Hidden dependency exists without candidate record.</li>
                            <li>Submission would create weak, duplicate, or orphaned CMDB data.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Conflict Remediation Queue</h2>
                <p>
                    These are the highest-priority conflict resolution actions.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Conflict</th>
                            <th>Why It Matters</th>
                            <th>Resolution Owner</th>
                            <th>Expected Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no governed identity.</td>
                            <td>Cannot determine CI identity, owner, support, access, or evidence source.</td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td>Governed candidate created.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment lifecycle state is not evidence-backed.</td>
                            <td>Could create false active record or unresolved lifecycle exposure.</td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td>Closed or defensible OOS state.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover support/access authority is partial.</td>
                            <td>Post-cutover routing may not be defendable.</td>
                            <td>Infrastructure / MyAccess Governance</td>
                            <td>Authority-ready cutover CI.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Support group pending for operational equipment.</td>
                            <td>Operational support routing may be delayed or unclear.</td>
                            <td>Operational Owner / CMDB Governance</td>
                            <td>Support-ready CI candidate.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, MyAccess, Blue Mountain, master lists, evidence repositories, or human governance. This field conflict resolution board is a governance assurance overlay for cross-source conflict detection, source authority decisions, evidence override logic, data quality remediation, ServiceNow-readiness, MyAccess-readiness, audit readiness, relationship readiness, executive reasoning, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_FIELD_CONFLICT_RESOLUTION_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Field Conflict Resolution Board installed.")
