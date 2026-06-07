from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_MANDATORY_FIELDS_CHECKLIST_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/mandatory-fields-checklist")'
ROUTE_ALIAS = '@app.route("/citrust/ci-field-checklist")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Mandatory Fields Checklist already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_MANDATORY_FIELDS_CHECKLIST_V1_ACTIVE
# ============================================================

@app.route("/citrust/mandatory-fields-checklist")
@app.route("/citrust/ci-field-checklist")
def citrust_mandatory_fields_checklist():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Mandatory Fields Checklist</title>
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
                    radial-gradient(circle at top right, rgba(247,201,72,0.14), transparent 28%),
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
                border: 1px solid rgba(247,201,72,0.38);
                background: rgba(247,201,72,0.10);
                color: #fff4cc;
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
                <h1>CITrust™ Mandatory Fields Checklist</h1>

                <div class="subtitle">
                    Validates whether each Configuration Item has the mandatory ServiceNow-style fields, governance fields, evidence fields, access fields, lifecycle fields, and operational context needed before the CI can be considered CMDB-ready, MyAccess-ready, audit-ready, or submission-ready.
                </div>

                <div class="positioning">
                    <strong>Checklist boundary:</strong>
                    ServiceNow stores the CI. CITrust™ validates whether the required CI fields are complete, current, evidence-backed, and operationally usable. This checklist does not create ServiceNow CIs, does not write to ServiceNow, and does not replace the formal CMDB submission process.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/submission-board">Submission Board</a>
                    <a href="/ci-submission-pack">Submission Pack</a>
                    <a href="/citrust/data-quality-readiness">Data Quality</a>
                    <a href="/citrust/classification-readiness">Classification</a>
                    <a href="/citrust/ownership-readiness">Ownership</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Mandatory Fields</div>
                    <div class="value">24</div>
                    <div class="note">Core ServiceNow-style, governance, access, lifecycle, and evidence fields.</div>
                </div>

                <div class="metric">
                    <div class="label">Complete Records</div>
                    <div class="value" style="color: var(--green);">14</div>
                    <div class="note">Records with required fields complete and defensible.</div>
                </div>

                <div class="metric">
                    <div class="label">Partial Records</div>
                    <div class="value" style="color: var(--yellow);">17</div>
                    <div class="note">Records with fields present but requiring confirmation or evidence.</div>
                </div>

                <div class="metric">
                    <div class="label">Blocked Records</div>
                    <div class="value" style="color: var(--red);">11</div>
                    <div class="note">Records missing critical fields required for trust or submission.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Missing</div>
                    <div class="value" style="color: var(--orange);">13</div>
                    <div class="note">Records missing evidence links for field defensibility.</div>
                </div>

                <div class="metric">
                    <div class="label">Ready for Pack</div>
                    <div class="value" style="color: var(--blue);">5</div>
                    <div class="note">Records ready for submission-pack preparation.</div>
                </div>
            </section>

            <section class="section">
                <h2>Mandatory Fields Answer</h2>
                <p>
                    This checklist answers whether a CI has enough complete field data to move forward.
                </p>

                <div class="answer">
                    <strong>Current field-readiness interpretation:</strong>
                    The CI population is not uniformly submission-ready. Several records have enough field coverage for controlled review, but records with missing owner, support group, LCM, CI class, lifecycle state, MyAccess mapping, evidence reference, or dependency context should remain blocked until the mandatory fields are completed and evidence-backed.
                </div>
            </section>

            <section class="section">
                <h2>Mandatory Field Library</h2>
                <p>
                    CITrust™ separates required fields into operationally meaningful groups.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Field Group</th>
                            <th>Mandatory Field</th>
                            <th>Why It Matters</th>
                            <th>Pass Condition</th>
                            <th>Failure Impact</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Identity</strong></td>
                            <td>CI Name / Asset Name</td>
                            <td>Identifies the record consistently across systems.</td>
                            <td><span class="badge soft-green">Unique and reconciled</span></td>
                            <td>Duplicate or ambiguous CI risk.</td>
                        </tr>

                        <tr>
                            <td><strong>Classification</strong></td>
                            <td>CI Class / Type</td>
                            <td>Defines whether the record is application, server, workstation, equipment, or dependency.</td>
                            <td><span class="badge soft-green">Correct class selected</span></td>
                            <td>Wrong support, lifecycle, or submission path.</td>
                        </tr>

                        <tr>
                            <td><strong>Ownership</strong></td>
                            <td>CI Owner</td>
                            <td>Defines accountable owner for governance questions.</td>
                            <td><span class="badge soft-green">Owner confirmed</span></td>
                            <td>Ownerless CI / audit exposure.</td>
                        </tr>

                        <tr>
                            <td><strong>Support</strong></td>
                            <td>Support Group</td>
                            <td>Determines routing for incidents, requests, and operational support.</td>
                            <td><span class="badge soft-green">Routable support group</span></td>
                            <td>Support and escalation failure.</td>
                        </tr>

                        <tr>
                            <td><strong>Lifecycle</strong></td>
                            <td>LCM / Lifecycle Owner</td>
                            <td>Defines accountability for active, cutover, OOS, retired, or closed state.</td>
                            <td><span class="badge soft-green">LCM assigned</span></td>
                            <td>Lifecycle ambiguity and closure risk.</td>
                        </tr>

                        <tr>
                            <td><strong>Access</strong></td>
                            <td>MyAccess Role / Approver Group</td>
                            <td>Supports access request routing and approval defensibility.</td>
                            <td><span class="badge soft-green">Role and approver mapped</span></td>
                            <td>Access routing cannot be defended.</td>
                        </tr>

                        <tr>
                            <td><strong>Evidence</strong></td>
                            <td>Evidence Location / Link</td>
                            <td>Shows where owner, access, SOP, backup, audit trail, validation, or closure evidence lives.</td>
                            <td><span class="badge soft-green">Reviewable evidence link</span></td>
                            <td>Audit-readiness failure.</td>
                        </tr>

                        <tr>
                            <td><strong>Dependency</strong></td>
                            <td>Upstream / Downstream Dependencies</td>
                            <td>Supports change impact and operational dependency analysis.</td>
                            <td><span class="badge soft-green">Dependencies known</span></td>
                            <td>Hidden dependency and change risk.</td>
                        </tr>

                        <tr>
                            <td><strong>Operational Context</strong></td>
                            <td>Business Function / GMP Impact</td>
                            <td>Explains why the CI matters operationally and whether it supports regulated work.</td>
                            <td><span class="badge soft-green">Impact classified</span></td>
                            <td>Weak criticality and audit reasoning.</td>
                        </tr>

                        <tr>
                            <td><strong>Readiness</strong></td>
                            <td>Submission Decision</td>
                            <td>Shows whether the candidate is ready, conditional, or blocked.</td>
                            <td><span class="badge soft-green">Decision evidence-backed</span></td>
                            <td>Premature ServiceNow-style submission.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>CI Field Completion Matrix</h2>
                <p>
                    This matrix shows whether each CI has the required fields for governed submission readiness.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Identity / Class</th>
                            <th>Owner</th>
                            <th>Support Group</th>
                            <th>LCM</th>
                            <th>MyAccess</th>
                            <th>Evidence Link</th>
                            <th>Dependency</th>
                            <th>Checklist Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge green">Field-Ready</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Needs Confirmation</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Cutover Evidence</span></td>
                            <td><span class="badge soft-yellow">Jump Path Pending</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-yellow">Procedure Needed</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Local Dependency</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-yellow">OOS Partial</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-red">Not Confirmed</span></td>
                            <td><span class="badge soft-yellow">Closure Needed</span></td>
                            <td><span class="badge soft-red">Unknown</span></td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Hidden</span></td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Checklist Control Domains</h2>
                <p>
                    These domains determine whether a CI candidate can move forward.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Field Completeness</h3>
                        <p>Mandatory fields must exist before a CI can be considered ServiceNow-style submission-ready.</p>
                    </div>

                    <div class="card">
                        <h3>Field Defensibility</h3>
                        <p>Fields must be backed by evidence, not just copied from spreadsheets or assumed from tribal knowledge.</p>
                    </div>

                    <div class="card">
                        <h3>Field Reconciliation</h3>
                        <p>Fields should align across ServiceNow-style records, MyAccess, Blue Mountain, master lists, and candidate intake.</p>
                    </div>

                    <div class="card">
                        <h3>Field Decision</h3>
                        <p>Checklist outcome determines whether the CI is field-ready, conditional, or blocked from submission.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Checklist Decision Logic</h2>
                <p>
                    Missing mandatory fields should stop weak records from becoming trusted records.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Field-Ready CI</h3>
                        <ul>
                            <li>CI name and class are clear.</li>
                            <li>Owner, support group, and LCM are confirmed.</li>
                            <li>MyAccess route and approver group are mapped where applicable.</li>
                            <li>Lifecycle state is current and evidence-backed.</li>
                            <li>Evidence location is linked and reviewable.</li>
                            <li>Dependency and operational context are known.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Blocked Field Checklist</h3>
                        <ul>
                            <li>Owner, support group, or LCM is missing.</li>
                            <li>CI class or operational role is unclear.</li>
                            <li>Access approval route is not defensible.</li>
                            <li>Evidence link is missing or disconnected.</li>
                            <li>OOS or retired record lacks closure evidence.</li>
                            <li>Dependency remains hidden or undocumented.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Field Completion Remediation Queue</h2>
                <p>
                    These actions complete mandatory fields and unlock submission readiness.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Record</th>
                            <th>Missing Field</th>
                            <th>Required Completion</th>
                            <th>Readiness Unlock</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Local Backup Review Workstation</td>
                            <td>CI class, owner, LCM, access route, evidence link, dependency mapping.</td>
                            <td>Create governed candidate and populate mandatory field set.</td>
                            <td>Blocked → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Speedy Glove 1802</td>
                            <td>OOS closure evidence, support group, access deactivation, lifecycle owner.</td>
                            <td>Attach closure evidence and reconcile lifecycle fields.</td>
                            <td>Blocked → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Niagara BMS Server</td>
                            <td>Support group confirmation, MyAccess role, jump path evidence, cutover evidence.</td>
                            <td>Complete cutover-sensitive field pack.</td>
                            <td>Conditional → Submission-Ready</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Speedy Glove 1803</td>
                            <td>Support group, evidence path, operational classification.</td>
                            <td>Reconcile fields against source systems and candidate intake.</td>
                            <td>Conditional → Field-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, update CMDB records, or bypass ServiceNow-style submission review in this demo. This mandatory fields checklist is a governance assurance overlay for CI intake completeness, ownership validation, support group mapping, LCM assignment, MyAccess readiness, evidence linkage, lifecycle classification, dependency mapping, data quality, audit readiness, and CMDB-readiness.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_MANDATORY_FIELDS_CHECKLIST_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Mandatory Fields Checklist installed.")
