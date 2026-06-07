from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AUDIT_READINESS_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/audit-readiness")'
ROUTE_ALIAS = '@app.route("/citrust/audit-defense")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Audit Readiness page already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AUDIT_READINESS_V1_ACTIVE
# ============================================================

@app.route("/citrust/audit-readiness")
@app.route("/citrust/audit-defense")
def citrust_audit_readiness():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Audit Readiness Console</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <style>
            :root {
                --bg: #050d19;
                --panel: #101d2f;
                --panel2: #142842;
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
                    radial-gradient(circle at bottom right, rgba(255,184,107,0.08), transparent 30%),
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

            .audit-answer {
                border: 1px solid rgba(49,208,125,0.36);
                background: rgba(49,208,125,0.10);
                color: #dfffea;
                border-radius: 18px;
                padding: 20px;
                margin-top: 16px;
                line-height: 1.65;
                font-size: 15px;
            }

            .question-grid {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 16px;
                margin-top: 16px;
            }

            .question-card {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 18px;
            }

            .question-card h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .question-card p {
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
                .kpis, .question-grid, .two-col {
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
                <h1>CITrust™ Audit Readiness Console</h1>

                <div class="subtitle">
                    Determines whether each Configuration Item can survive audit questions about owner, support group, LCM, MyAccess routing, SOP linkage, backup evidence, audit trail evidence, lifecycle state, and operational accountability.
                </div>

                <div class="positioning">
                    <strong>Audit-safe positioning:</strong>
                    ServiceNow remains the system of record. CITrust™ is the governance assurance overlay that tests whether ServiceNow-style records, CI candidates, and operational asset references are evidence-backed, explainable, and audit-defensible before leadership relies on them.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/servicenow-ci-readiness">ServiceNow CI Readiness</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                    <a href="/citrust/reconciliation">CMDB Reconciliation</a>
                    <a href="/citrust/submission-board">Submission Board</a>
                    <a href="/citrust/myaccess-readiness">MyAccess Readiness</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                    <a href="/citrust/orphans">Orphan CI Intelligence</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">CIs Reviewed</div>
                    <div class="value">42</div>
                    <div class="note">ServiceNow-style records, candidates, operational assets, and infrastructure dependencies.</div>
                </div>

                <div class="metric">
                    <div class="label">Audit-Defensible</div>
                    <div class="value" style="color: var(--green);">16</div>
                    <div class="note">Can answer key audit questions with evidence-backed governance lineage.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditionally Defensible</div>
                    <div class="value" style="color: var(--yellow);">15</div>
                    <div class="note">Needs remediation, clarification, or exception documentation.</div>
                </div>

                <div class="metric">
                    <div class="label">Audit Exposure</div>
                    <div class="value" style="color: var(--red);">8</div>
                    <div class="note">Missing evidence, unclear owner, weak routing, or lifecycle gaps.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Gaps</div>
                    <div class="value" style="color: var(--orange);">19</div>
                    <div class="note">SOP, backup, access, validation, closure, or audit trail evidence missing or partial.</div>
                </div>

                <div class="metric">
                    <div class="label">Pre-Deviation Saves</div>
                    <div class="value" style="color: var(--blue);">11</div>
                    <div class="note">Potential issues identified before becoming deviations, audit observations, or routing failures.</div>
                </div>
            </section>

            <section class="section">
                <h2>Audit Readiness Answer</h2>
                <p>
                    This view converts CI governance details into audit-response readiness.
                </p>

                <div class="audit-answer">
                    <strong>Current audit interpretation:</strong>
                    The CI estate is not uniformly audit-defensible. A controlled portion can answer audit questions with owner, support group, access, lifecycle, and evidence lineage. Conditional and exposed records require remediation before they should be presented as fully governed or ServiceNow-ready.
                </div>
            </section>

            <section class="section">
                <h2>Audit Question Coverage</h2>
                <p>
                    CITrust™ evaluates the questions an auditor, QA reviewer, IT governance lead, or infrastructure owner may ask when testing whether a CI is operationally trustworthy.
                </p>

                <div class="question-grid">
                    <div class="question-card">
                        <h3>Who owns this CI?</h3>
                        <p>Validates whether ownership is clear, accountable, reviewable, and not just a stale field in a record.</p>
                    </div>

                    <div class="question-card">
                        <h3>Who supports this CI?</h3>
                        <p>Confirms that incidents, access issues, operational questions, and escalation paths route to a defined support group.</p>
                    </div>

                    <div class="question-card">
                        <h3>Who approves access?</h3>
                        <p>Tests whether MyAccess routing, approver group, and role mapping can be defended without manual interpretation.</p>
                    </div>

                    <div class="question-card">
                        <h3>What SOP or procedure governs it?</h3>
                        <p>Checks whether SOP linkage or operational work instruction evidence exists where required.</p>
                    </div>

                    <div class="question-card">
                        <h3>What evidence proves control?</h3>
                        <p>Links the CI to backup reviews, audit trail reviews, validation evidence, closure records, or access review artifacts.</p>
                    </div>

                    <div class="question-card">
                        <h3>What is its lifecycle state?</h3>
                        <p>Confirms whether the CI is active, pending, retired, OOS, or under review, and whether that state is reconciled across sources.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Audit Readiness Matrix</h2>
                <p>
                    This matrix shows whether each CI can survive common audit questions without relying on tribal knowledge, disconnected spreadsheets, or unsupported assumptions.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Owner</th>
                            <th>Support Group</th>
                            <th>LCM</th>
                            <th>MyAccess</th>
                            <th>SOP / Procedure</th>
                            <th>Evidence</th>
                            <th>Lifecycle State</th>
                            <th>Audit Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset / calibration governance system</span></td>
                            <td><span class="badge soft-green">Defensible</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Linked</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge green">Audit-Defensible</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin / vendor access route</span></td>
                            <td><span class="badge soft-green">Defensible</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-yellow">Procedure Needed</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS server / facility support dependency</span></td>
                            <td><span class="badge soft-green">Defensible</span></td>
                            <td><span class="badge soft-yellow">Needs Confirmation</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-green">Cutover Active</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-green">Defensible</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Needs Link</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-green">Operational</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Closure Needed</span></td>
                            <td><span class="badge soft-red">OOS Not Closed</span></td>
                            <td><span class="badge red">Audit Exposure</span></td>
                        </tr>

                        <tr>
                            <td><strong>Chromeleon Workstation</strong><br><span style="color: var(--muted);">Lab workstation dependency</span></td>
                            <td><span class="badge soft-green">Defensible</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Role Check</span></td>
                            <td><span class="badge soft-green">Linked</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Discovered</span></td>
                            <td><span class="badge red">Audit Exposure</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Defensible</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Linked</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Audit Evidence Requirements</h2>
                <p>
                    CITrust™ does not only ask whether a CI field exists. It asks whether the field can be defended with governed evidence.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Audit Domain</th>
                            <th>Evidence Needed</th>
                            <th>Weakness Detected</th>
                            <th>CITrust™ Response</th>
                            <th>Audit Impact</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td>Ownership</td>
                            <td>Named CI owner or accountable ownership model</td>
                            <td>Owner missing, stale, or not aligned with operational reality</td>
                            <td>Flag as conditional or audit exposure</td>
                            <td>Cannot defend who is accountable</td>
                        </tr>

                        <tr>
                            <td>Support Routing</td>
                            <td>Mapped support group and escalation path</td>
                            <td>Support group missing, unclear, or inconsistent</td>
                            <td>Route to reconciliation queue</td>
                            <td>Incident and support accountability risk</td>
                        </tr>

                        <tr>
                            <td>Access Governance</td>
                            <td>MyAccess role, approver group, and request path</td>
                            <td>Access approval path cannot be explained</td>
                            <td>Hold from trusted routing</td>
                            <td>Access approval defensibility risk</td>
                        </tr>

                        <tr>
                            <td>Lifecycle</td>
                            <td>Active, retired, OOS, pending, or cutover state</td>
                            <td>Lifecycle state conflicts across records</td>
                            <td>Require closure or state reconciliation</td>
                            <td>Retired/OOS assets may remain operationally exposed</td>
                        </tr>

                        <tr>
                            <td>Operational Evidence</td>
                            <td>Backup review, audit trail review, SOP, validation, or closure evidence</td>
                            <td>Evidence not linked to CI</td>
                            <td>Create evidence remediation item</td>
                            <td>Cannot survive detailed audit questioning</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Pre-Deviation Audit Defense</h2>
                <p>
                    This page helps catch governance weaknesses before they become deviations, audit observations, or operational failures.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Audit-Defensible CI</h3>
                        <ul>
                            <li>Owner is clear and accountable.</li>
                            <li>Support group is mapped and operationally usable.</li>
                            <li>LCM is assigned or inherited through a governed model.</li>
                            <li>MyAccess roles and approver groups are explainable.</li>
                            <li>SOP, procedure, or work instruction linkage exists where required.</li>
                            <li>Evidence is available, current, and connected to the CI.</li>
                            <li>Lifecycle state is reconciled across sources.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Audit Exposure CI</h3>
                        <ul>
                            <li>Owner, support group, or LCM is missing.</li>
                            <li>Access approval route cannot be defended.</li>
                            <li>CI exists in one source but not in another critical source.</li>
                            <li>OOS or retired records lack closure evidence.</li>
                            <li>Evidence exists but is disconnected from the CI.</li>
                            <li>Operational reliance depends on tribal knowledge.</li>
                            <li>Candidate was pushed forward before governance review was complete.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Audit Remediation Queue</h2>
                <p>
                    These are the records that should be corrected before leadership describes the CI estate as audit-ready.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Record</th>
                            <th>Audit Weakness</th>
                            <th>Required Remediation</th>
                            <th>Target State</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Speedy Glove 1802</td>
                            <td>OOS lifecycle state lacks complete closure and access deactivation evidence.</td>
                            <td>Attach closure evidence, confirm access removal, and reconcile lifecycle state.</td>
                            <td>Closed / audit-defensible OOS record.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Local Backup Review Workstation</td>
                            <td>Missing owner, LCM, MyAccess mapping, SOP, and evidence lineage.</td>
                            <td>Create governed candidate and route through Candidate Review Board.</td>
                            <td>Governed CI candidate with assigned accountability.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Niagara BMS Server</td>
                            <td>Partial support routing and access role evidence.</td>
                            <td>Confirm support group, MyAccess role mapping, and cutover evidence link.</td>
                            <td>Conditionally defensible record moved toward trusted state.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Jump Server Access Path</td>
                            <td>Procedure or administrative access work instruction should be linked.</td>
                            <td>Attach procedure, admin-access model, or support evidence reference.</td>
                            <td>Audit-defensible infrastructure dependency.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, or write directly into ServiceNow in this demo. This audit readiness console is a governance assurance overlay for CI audit defensibility, evidence lineage, ownership accountability, support routing, MyAccess readiness, lifecycle reconciliation, and pre-deviation readiness.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AUDIT_READINESS_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Audit Readiness Console installed.")
