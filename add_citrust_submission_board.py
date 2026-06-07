from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_SUBMISSION_BOARD_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/submission-board")'
ROUTE_ALIAS = '@app.route("/citrust/submission-readiness")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Submission Board already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_SUBMISSION_BOARD_V1_ACTIVE
# ============================================================

@app.route("/citrust/submission-board")
@app.route("/citrust/submission-readiness")
def citrust_submission_board():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ ServiceNow Submission Board</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <style>
            :root {
                --bg: #06101d;
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
                    radial-gradient(circle at top left, rgba(92,200,255,0.17), transparent 30%),
                    radial-gradient(circle at top right, rgba(180,156,255,0.15), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(49,208,125,0.08), transparent 28%),
                    var(--bg);
                color: var(--text);
            }

            .page {
                max-width: 1380px;
                margin: 0 auto;
                padding: 28px;
            }

            .hero {
                border: 1px solid var(--line);
                background: linear-gradient(135deg, rgba(16,29,47,0.97), rgba(20,40,66,0.92));
                border-radius: 24px;
                padding: 28px;
                box-shadow: 0 22px 70px rgba(0,0,0,0.38);
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
                font-size: 38px;
                line-height: 1.1;
            }

            .subtitle {
                color: var(--muted);
                font-size: 16px;
                line-height: 1.6;
                max-width: 1060px;
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
                grid-template-columns: repeat(5, 1fr);
                gap: 16px;
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

            .green {
                color: #05140b;
                background: var(--green);
            }

            .yellow {
                color: #1d1600;
                background: var(--yellow);
            }

            .red {
                color: #fff;
                background: var(--red);
            }

            .blue {
                color: #06101d;
                background: var(--blue);
            }

            .purple {
                color: #120b24;
                background: var(--purple);
            }

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

            .stage-grid {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 16px;
                margin-top: 16px;
            }

            .stage-card {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 18px;
                position: relative;
                overflow: hidden;
            }

            .stage-card:before {
                content: "";
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 4px;
                background: linear-gradient(90deg, var(--blue), var(--purple));
            }

            .stage-card h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .stage-card p {
                margin: 0;
                color: var(--muted);
                font-size: 14px;
                line-height: 1.55;
            }

            .two-col {
                display: grid;
                grid-template-columns: 1.1fr 0.9fr;
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

            .callout {
                border: 1px solid rgba(247,201,72,0.35);
                background: rgba(247,201,72,0.10);
                color: #fff4cc;
                padding: 16px 18px;
                border-radius: 16px;
                margin-top: 16px;
                line-height: 1.55;
            }

            .footer {
                color: var(--muted);
                font-size: 12px;
                margin-top: 22px;
                line-height: 1.6;
            }

            @media (max-width: 1100px) {
                .kpis, .stage-grid, .two-col {
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
                <h1>CITrust™ ServiceNow Submission Board</h1>

                <div class="subtitle">
                    Separates CI candidates that are ready for ServiceNow-style submission from candidates that must remain in governance review due to missing ownership, support group, LCM, MyAccess mapping, evidence lineage, or operational readiness gaps.
                </div>

                <div class="positioning">
                    <strong>Important boundary:</strong>
                    This board does not create ServiceNow CIs, does not write directly to ServiceNow, and does not bypass the existing CI Candidate Review Board. It provides a governance decision layer showing whether a CI candidate is ServiceNow-ready, conditionally ready, or must remain in review before submission.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/ci-candidate-factory">CI Candidate Factory</a>
                    <a href="/ci-candidate-review">Candidate Review Board</a>
                    <a href="/ci-submission-pack">Existing Submission Pack</a>
                    <a href="/citrust/reconciliation">CMDB Reconciliation</a>
                    <a href="/citrust/myaccess-readiness">MyAccess Readiness</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                    <a href="/citrust/orphans">Orphan CI Intelligence</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Total Candidates</div>
                    <div class="value">16</div>
                    <div class="note">Candidates from Planner, Excel, Blue Mountain, master list, and operational discovery.</div>
                </div>

                <div class="metric">
                    <div class="label">ServiceNow-Ready</div>
                    <div class="value" style="color: var(--green);">5</div>
                    <div class="note">Governance minimums met for submission pack preparation.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional</div>
                    <div class="value" style="color: var(--yellow);">6</div>
                    <div class="note">Can proceed only after named gaps are resolved or documented.</div>
                </div>

                <div class="metric">
                    <div class="label">Remain in Review</div>
                    <div class="value" style="color: var(--red);">4</div>
                    <div class="note">Not ready for ServiceNow-style submission or operational reliance.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Escalation</div>
                    <div class="value" style="color: var(--blue);">1</div>
                    <div class="note">Requires decision on ownership or lifecycle accountability.</div>
                </div>
            </section>

            <section class="section">
                <h2>Submission Readiness Stages</h2>
                <p>
                    CITrust™ keeps candidate intake, candidate review, and ServiceNow-readiness separate. This prevents immature records from being treated as trusted Configuration Items too early.
                </p>

                <div class="stage-grid">
                    <div class="stage-card">
                        <h3>1. Candidate Intake</h3>
                        <p>
                            Raw CI candidates are discovered from Planner, Excel, Blue Mountain, master lists, operational walkthroughs, or known infrastructure dependencies.
                        </p>
                    </div>

                    <div class="stage-card">
                        <h3>2. Governance Review</h3>
                        <p>
                            Candidate Review Board validates ownership, support group, lifecycle owner, access mapping, SOP linkage, and evidence readiness.
                        </p>
                    </div>

                    <div class="stage-card">
                        <h3>3. Submission Pack</h3>
                        <p>
                            ServiceNow-ready candidates are packaged with required fields, evidence references, risk notes, and governance explanation.
                        </p>
                    </div>

                    <div class="stage-card">
                        <h3>4. CMDB-Readiness</h3>
                        <p>
                            Candidate is considered ready for ServiceNow-style submission, future API integration, or controlled handoff to CMDB governance teams.
                        </p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>ServiceNow Submission Board</h2>
                <p>
                    This board answers the core governance question: should this CI candidate be prepared for ServiceNow submission, remain in review, or be blocked until governance gaps are fixed?
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>CI Candidate</th>
                            <th>Candidate Source</th>
                            <th>Owner</th>
                            <th>Support Group</th>
                            <th>LCM</th>
                            <th>MyAccess</th>
                            <th>Evidence</th>
                            <th>Submission Decision</th>
                            <th>Reason</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">GMP application / asset governance</span></td>
                            <td><span class="badge soft-blue">Master List</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge green">ServiceNow-Ready</span></td>
                            <td>Minimum governance requirements are satisfied.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin / vendor access route</span></td>
                            <td><span class="badge soft-blue">Infrastructure Discovery</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge green">ServiceNow-Ready</span></td>
                            <td>Dependency and access path are ready for controlled submission packaging.</td>
                        </tr>

                        <tr>
                            <td><strong>Chromeleon Workstation</strong><br><span style="color: var(--muted);">Lab workstation dependency</span></td>
                            <td><span class="badge soft-blue">Lab Inventory</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Role Check</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Role mapping should be confirmed before final submission package.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS server / facility support dependency</span></td>
                            <td><span class="badge soft-blue">Cutover Tracker</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Needs Final Confirmation</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Support routing and access role evidence must be finalized.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-blue">Blue Mountain / Field Discovery</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Support group and MyAccess routing need reconciliation.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-blue">Legacy Asset List</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-yellow">Closure Evidence Needed</span></td>
                            <td><span class="badge red">Remain in Review</span></td>
                            <td>Lifecycle closure and access deactivation evidence required.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-blue">Operational Discovery</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge red">Remain in Review</span></td>
                            <td>No defensible owner, LCM, access routing, or evidence lineage.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-blue">Master System List</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Approver group confirmation required before submission pack completion.</td>
                        </tr>
                    </tbody>
                </table>

                <div class="callout">
                    <strong>Board rule:</strong>
                    A candidate can be moved toward the existing submission pack only when the board can defend owner, support group, LCM, access routing, lifecycle state, evidence lineage, and operational dependency context.
                </div>
            </section>

            <section class="section">
                <h2>Submission Gate Logic</h2>
                <p>
                    This logic prevents the team from pushing incomplete records forward simply because they exist in a spreadsheet, asset export, or partial ServiceNow-style record.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Move to Submission Pack</h3>
                        <ul>
                            <li>CI name, class, and operational purpose are clear.</li>
                            <li>CI owner is accountable and reviewable.</li>
                            <li>Support group is mapped for incidents and operational support.</li>
                            <li>LCM is assigned or clearly inherited.</li>
                            <li>MyAccess approver path and roles are mapped or justified.</li>
                            <li>Evidence lineage exists for SOP, validation, backup, audit trail, or lifecycle support where applicable.</li>
                            <li>Candidate Review Board has no blocking questions.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Keep in Governance Review</h3>
                        <ul>
                            <li>Owner, support group, or LCM is missing or disputed.</li>
                            <li>MyAccess routing cannot be defended.</li>
                            <li>Lifecycle state conflicts across sources.</li>
                            <li>OOS, retired, or legacy equipment lacks closure evidence.</li>
                            <li>Operational dependency is unclear.</li>
                            <li>Evidence cannot be located or connected to the CI candidate.</li>
                            <li>Submission would create a weak or orphaned CMDB record.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Board Actions</h2>
                <p>
                    These are the controlled actions the board can take without claiming direct ServiceNow creation or automated CMDB writing.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Action</th>
                            <th>Meaning</th>
                            <th>Permitted Outcome</th>
                            <th>Not Permitted</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge green">Approve for Submission Pack</span></td>
                            <td>Candidate has enough governance evidence to prepare a ServiceNow-style submission package.</td>
                            <td>Move to `/ci-submission-pack` preparation.</td>
                            <td>Do not claim ServiceNow CI was created.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Conditional Approval</span></td>
                            <td>Candidate is close, but one or more fields require confirmation.</td>
                            <td>Assign remediation owner and keep under board visibility.</td>
                            <td>Do not treat as fully operationally trusted.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">Hold in Review</span></td>
                            <td>Candidate lacks defensible ownership, support, lifecycle, access, or evidence lineage.</td>
                            <td>Return to candidate review or orphan intelligence queue.</td>
                            <td>Do not submit as trusted CMDB-ready record.</td>
                        </tr>

                        <tr>
                            <td><span class="badge blue">Escalate</span></td>
                            <td>Governance question requires leadership or cross-functional decision.</td>
                            <td>Escalate owner/support/LCM conflict for decision.</td>
                            <td>Do not resolve by assumption or tribal knowledge.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, or write directly into ServiceNow in this demo. This page is a governance assurance overlay for candidate submission readiness, controlled review, evidence-backed decisioning, and future ServiceNow API integration after governance validation.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_SUBMISSION_BOARD_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Submission Board installed.")
