from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_OWNERSHIP_READINESS_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/ownership-readiness")'
ROUTE_ALIAS = '@app.route("/citrust/ownership-command")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Ownership Readiness page already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_OWNERSHIP_READINESS_V1_ACTIVE
# ============================================================

@app.route("/citrust/ownership-readiness")
@app.route("/citrust/ownership-command")
def citrust_ownership_readiness():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Ownership Readiness Command Center</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <style>
            :root {
                --bg: #050d19;
                --panel: #101d2f;
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
                    radial-gradient(circle at bottom left, rgba(49,208,125,0.08), transparent 30%),
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
                <h1>CITrust™ Ownership Readiness Command Center</h1>

                <div class="subtitle">
                    Determines whether CI ownership, support group assignment, LCM accountability, escalation routing, and operational responsibility are trustworthy before a Configuration Item is treated as ServiceNow-ready, access-ready, audit-ready, or operationally reliable.
                </div>

                <div class="positioning">
                    <strong>Governance boundary:</strong>
                    ServiceNow stores CI ownership fields. CITrust™ validates whether those fields are complete, current, accountable, supportable, and evidence-backed. This page does not create ServiceNow CIs, does not write to ServiceNow, and does not replace CMDB governance.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/servicenow-ci-readiness">ServiceNow CI Readiness</a>
                    <a href="/citrust/myaccess-readiness">MyAccess Readiness</a>
                    <a href="/citrust/reconciliation">CMDB Reconciliation</a>
                    <a href="/citrust/submission-board">Submission Board</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                    <a href="/citrust/orphans">Orphan CI Intelligence</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">CIs Assessed</div>
                    <div class="value">42</div>
                    <div class="note">Records reviewed for ownership, support, LCM, and escalation readiness.</div>
                </div>

                <div class="metric">
                    <div class="label">Owner Confirmed</div>
                    <div class="value" style="color: var(--green);">31</div>
                    <div class="note">Owner exists and can be used for accountability and approval questions.</div>
                </div>

                <div class="metric">
                    <div class="label">Support Group Mapped</div>
                    <div class="value" style="color: var(--blue);">26</div>
                    <div class="note">Operational routing can be directed to a defined support group.</div>
                </div>

                <div class="metric">
                    <div class="label">LCM Assigned</div>
                    <div class="value" style="color: var(--purple);">24</div>
                    <div class="note">Lifecycle accountability exists or is inherited through a governed model.</div>
                </div>

                <div class="metric">
                    <div class="label">Ownership Exceptions</div>
                    <div class="value" style="color: var(--yellow);">9</div>
                    <div class="note">Records with partial, disputed, or stale accountability.</div>
                </div>

                <div class="metric">
                    <div class="label">Ownerless / Blocked</div>
                    <div class="value" style="color: var(--red);">5</div>
                    <div class="note">Records cannot be trusted until ownership or support accountability is resolved.</div>
                </div>
            </section>

            <section class="section">
                <h2>Ownership Readiness Answer</h2>
                <p>
                    This console answers whether a CI has accountable human and operational ownership behind the record.
                </p>

                <div class="answer">
                    <strong>Current ownership interpretation:</strong>
                    The CI estate is partially ownership-ready. Most high-value records have an identifiable owner, but several operational assets, legacy equipment, and discovered infrastructure dependencies still require confirmed support group mapping, LCM assignment, or escalation ownership before they can be considered operationally trusted.
                </div>
            </section>

            <section class="section">
                <h2>Ownership Control Domains</h2>
                <p>
                    CITrust™ separates ownership into operationally meaningful controls instead of treating ownership as a single CMDB field.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>CI Owner</h3>
                        <p>Confirms who is accountable for the CI as a governed record and who can answer ownership questions.</p>
                    </div>

                    <div class="card">
                        <h3>Support Group</h3>
                        <p>Validates who receives incidents, service requests, troubleshooting items, and operational routing.</p>
                    </div>

                    <div class="card">
                        <h3>LCM</h3>
                        <p>Confirms lifecycle accountability for change impact, retirement, revalidation triggers, and governance continuity.</p>
                    </div>

                    <div class="card">
                        <h3>Escalation Path</h3>
                        <p>Tests whether unresolved ownership, support, access, or lifecycle questions have a clear escalation owner.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Ownership Readiness Matrix</h2>
                <p>
                    This matrix shows whether each CI has defensible ownership, support routing, lifecycle responsibility, and escalation coverage.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>CI Owner</th>
                            <th>Support Group</th>
                            <th>LCM</th>
                            <th>Escalation Path</th>
                            <th>Ownership Evidence</th>
                            <th>Primary Gap</th>
                            <th>Readiness Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">GMP application / asset governance system</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Defined</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td>No major ownership gap</td>
                            <td><span class="badge green">Ownership-Ready</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS server / facility support dependency</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Needs Final Confirmation</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td>Support group and escalation model need final confirmation</td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin / vendor access route</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Defined</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td>No major ownership gap</td>
                            <td><span class="badge green">Ownership-Ready</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td>Support group and escalation responsibility need reconciliation</td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Closure Needed</span></td>
                            <td>OOS ownership and closure accountability not defendable</td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Chromeleon Workstation</strong><br><span style="color: var(--muted);">Lab workstation dependency</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Defined</span></td>
                            <td><span class="badge soft-yellow">Needs Reference</span></td>
                            <td>Ownership evidence reference should be linked</td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td>No defensible owner, LCM, or escalation path</td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Defined</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td>No major ownership gap</td>
                            <td><span class="badge green">Ownership-Ready</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Ownership Decision Logic</h2>
                <p>
                    CITrust™ prevents weak or ownerless records from being treated as trusted simply because they exist in a CMDB, spreadsheet, asset export, or master list.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Ownership-Ready CI</h3>
                        <ul>
                            <li>CI owner is confirmed and accountable.</li>
                            <li>Support group is mapped and operationally usable.</li>
                            <li>LCM is assigned or clearly inherited.</li>
                            <li>Escalation path is defined for unresolved issues.</li>
                            <li>Ownership evidence can be located and reviewed.</li>
                            <li>Ownership supports access routing, audit response, incident routing, and lifecycle decisions.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Blocked Ownership CI</h3>
                        <ul>
                            <li>CI owner is missing, stale, or disputed.</li>
                            <li>Support group cannot be confirmed.</li>
                            <li>LCM accountability is missing.</li>
                            <li>Escalation path is undefined.</li>
                            <li>Ownership evidence is absent or disconnected.</li>
                            <li>Record would create orphan CI, orphan access, or audit defensibility risk.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Ownership Remediation Queue</h2>
                <p>
                    These are the ownership gaps that should be resolved before records are treated as ServiceNow-ready, MyAccess-ready, or audit-ready.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Record</th>
                            <th>Ownership Gap</th>
                            <th>Required Action</th>
                            <th>Target State</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Local Backup Review Workstation</td>
                            <td>Missing owner, LCM, escalation path, and ownership evidence.</td>
                            <td>Create governed CI candidate and assign accountable owner before further reliance.</td>
                            <td>Governed candidate with owner, support group, and LCM.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Speedy Glove 1802</td>
                            <td>OOS ownership and closure accountability are not defendable.</td>
                            <td>Confirm closure owner, lifecycle state, support responsibility, and evidence reference.</td>
                            <td>Closed or governed OOS record with defensible accountability.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Niagara BMS Server</td>
                            <td>Support group and escalation model need final confirmation.</td>
                            <td>Confirm operational support group and escalation path after cutover access model is finalized.</td>
                            <td>Ownership-ready infrastructure/application dependency.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Speedy Glove 1803</td>
                            <td>Support routing and escalation ownership remain partial.</td>
                            <td>Reconcile support group against operational owner and candidate review record.</td>
                            <td>Conditionally trusted record moved to ownership-ready state.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, or write directly into ServiceNow in this demo. This ownership readiness command center is a governance assurance overlay for CI owner validation, support group mapping, LCM accountability, escalation readiness, orphan prevention, MyAccess routing support, CMDB-readiness, and audit defensibility.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_OWNERSHIP_READINESS_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Ownership Readiness Command Center installed.")
