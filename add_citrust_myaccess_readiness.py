from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_MYACCESS_READINESS_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/myaccess-readiness")'
ROUTE_ALIAS = '@app.route("/citrust/access-readiness")'

# If the page was already installed earlier without the alias,
# safely add only the alias route and stop.
if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    if ROUTE_PRIMARY in text and ROUTE_ALIAS not in text:
        text = text.replace(
            ROUTE_PRIMARY,
            ROUTE_PRIMARY + "\n" + ROUTE_ALIAS,
            1
        )
        APP.write_text(text, encoding="utf-8")
        print("CITrust MyAccess Readiness page already existed. Alias route /citrust/access-readiness added.")
        raise SystemExit()

    print("CITrust MyAccess Readiness page already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_MYACCESS_READINESS_V1_ACTIVE
# ============================================================

@app.route("/citrust/myaccess-readiness")
@app.route("/citrust/access-readiness")
def citrust_myaccess_readiness():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ MyAccess Readiness Console</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <style>
            :root {
                --bg: #07111f;
                --panel: #101d2f;
                --panel2: #13263d;
                --line: rgba(255,255,255,0.12);
                --text: #eef5ff;
                --muted: #a9bdd6;
                --green: #31d07d;
                --yellow: #f7c948;
                --red: #ff5c70;
                --blue: #5cc8ff;
                --purple: #b49cff;
            }

            body {
                margin: 0;
                font-family: Arial, Helvetica, sans-serif;
                background:
                    radial-gradient(circle at top left, rgba(92,200,255,0.18), transparent 30%),
                    radial-gradient(circle at top right, rgba(180,156,255,0.14), transparent 28%),
                    var(--bg);
                color: var(--text);
            }

            .page {
                max-width: 1320px;
                margin: 0 auto;
                padding: 28px;
            }

            .hero {
                border: 1px solid var(--line);
                background: linear-gradient(135deg, rgba(16,29,47,0.96), rgba(19,38,61,0.9));
                border-radius: 24px;
                padding: 28px;
                box-shadow: 0 22px 60px rgba(0,0,0,0.35);
            }

            .eyebrow {
                color: var(--blue);
                font-size: 13px;
                text-transform: uppercase;
                letter-spacing: 1.8px;
                font-weight: 700;
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
                max-width: 980px;
                margin-top: 14px;
            }

            .positioning {
                margin-top: 18px;
                padding: 16px 18px;
                border: 1px solid rgba(92,200,255,0.28);
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

            .grid {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 16px;
                margin-top: 20px;
            }

            .metric {
                border: 1px solid var(--line);
                background: rgba(16,29,47,0.88);
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
                font-weight: 800;
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
                background: rgba(16,29,47,0.88);
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
                font-weight: 700;
                white-space: nowrap;
            }

            .ready {
                color: #05140b;
                background: var(--green);
            }

            .conditional {
                color: #1d1600;
                background: var(--yellow);
            }

            .blocked {
                color: #fff;
                background: var(--red);
            }

            .mapped {
                color: #dfffea;
                background: rgba(49,208,125,0.16);
                border: 1px solid rgba(49,208,125,0.35);
            }

            .missing {
                color: #ffe5e9;
                background: rgba(255,92,112,0.15);
                border: 1px solid rgba(255,92,112,0.38);
            }

            .partial {
                color: #fff4cc;
                background: rgba(247,201,72,0.15);
                border: 1px solid rgba(247,201,72,0.38);
            }

            .cards {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
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

            .decision {
                display: grid;
                grid-template-columns: 1.1fr 1fr;
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

            @media (max-width: 980px) {
                .grid, .cards, .decision {
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
                <h1>CITrust™ MyAccess Readiness Console</h1>

                <div class="subtitle">
                    Determines whether access approval routing can be operationally trusted for a Configuration Item before relying on it for MyAccess approvals, support routing, LCM accountability, and CMDB-readiness.
                </div>

                <div class="positioning">
                    <strong>Demo-safe positioning:</strong>
                    ServiceNow remains the system of record for CI storage. CITrust™ acts as the governance assurance overlay that validates whether CI ownership, support group, LCM assignment, approver group, access role mapping, SOP linkage, and evidence lineage are trustworthy before ServiceNow-style records are treated as operationally reliable.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/ci-myaccess-blueprint">Existing CI + MyAccess Blueprint</a>
                    <a href="/ci-candidate-factory">CI Candidate Factory</a>
                    <a href="/ci-candidate-review">Candidate Review Board</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                    <a href="/citrust/orphans">Orphan CI Intelligence</a>
                    <a href="/ci-submission-pack">Submission Pack</a>
                </div>
            </section>

            <section class="grid">
                <div class="metric">
                    <div class="label">Total CI Records Assessed</div>
                    <div class="value">8</div>
                    <div class="note">ServiceNow-style records, candidate records, and operational asset references.</div>
                </div>

                <div class="metric">
                    <div class="label">Ready for MyAccess Routing</div>
                    <div class="value" style="color: var(--green);">3</div>
                    <div class="note">Owner, support group, LCM, approver group, and role mapping present.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Routing</div>
                    <div class="value" style="color: var(--yellow);">3</div>
                    <div class="note">Can proceed only with documented governance exceptions or remediation.</div>
                </div>

                <div class="metric">
                    <div class="label">Blocked</div>
                    <div class="value" style="color: var(--red);">2</div>
                    <div class="note">Approval routing cannot be trusted until required governance fields are resolved.</div>
                </div>
            </section>

            <section class="section">
                <h2>MyAccess Routing Readiness Matrix</h2>
                <p>
                    This view evaluates whether each CI has the governance minimums required to support access approval routing. It does not create ServiceNow CIs and does not write to ServiceNow. It identifies whether the record is ready, conditional, or blocked before submission or operational reliance.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>CI Type</th>
                            <th>Owner</th>
                            <th>Support Group</th>
                            <th>LCM</th>
                            <th>Approver Group</th>
                            <th>Access Roles</th>
                            <th>Evidence</th>
                            <th>Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">Building automation / GMP facility support</span></td>
                            <td>Server / Application Dependency</td>
                            <td><span class="badge mapped">Present</span></td>
                            <td><span class="badge mapped">Mapped</span></td>
                            <td><span class="badge mapped">Assigned</span></td>
                            <td><span class="badge mapped">Mapped</span></td>
                            <td><span class="badge mapped">Supervisor Role</span></td>
                            <td><span class="badge partial">Partial</span></td>
                            <td><span class="badge conditional">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance reference</span></td>
                            <td>GMP Application</td>
                            <td><span class="badge mapped">Present</span></td>
                            <td><span class="badge mapped">Mapped</span></td>
                            <td><span class="badge mapped">Assigned</span></td>
                            <td><span class="badge mapped">Mapped</span></td>
                            <td><span class="badge mapped">Mapped</span></td>
                            <td><span class="badge mapped">Available</span></td>
                            <td><span class="badge ready">Ready</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational equipment record</span></td>
                            <td>Manufacturing Equipment</td>
                            <td><span class="badge mapped">Present</span></td>
                            <td><span class="badge partial">Pending</span></td>
                            <td><span class="badge mapped">Assigned</span></td>
                            <td><span class="badge partial">Pending</span></td>
                            <td><span class="badge partial">Partial</span></td>
                            <td><span class="badge partial">Partial</span></td>
                            <td><span class="badge conditional">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service / closure evidence required</span></td>
                            <td>Manufacturing Equipment</td>
                            <td><span class="badge missing">Missing</span></td>
                            <td><span class="badge missing">Missing</span></td>
                            <td><span class="badge partial">Pending</span></td>
                            <td><span class="badge missing">Missing</span></td>
                            <td><span class="badge missing">Not Mapped</span></td>
                            <td><span class="badge partial">Closure Evidence Needed</span></td>
                            <td><span class="badge blocked">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Chromeleon Workstation</strong><br><span style="color: var(--muted);">Lab workstation access dependency</span></td>
                            <td>Lab Workstation</td>
                            <td><span class="badge mapped">Present</span></td>
                            <td><span class="badge mapped">Mapped</span></td>
                            <td><span class="badge mapped">Assigned</span></td>
                            <td><span class="badge mapped">Mapped</span></td>
                            <td><span class="badge mapped">Mapped</span></td>
                            <td><span class="badge mapped">Available</span></td>
                            <td><span class="badge ready">Ready</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">Lab application dependency</span></td>
                            <td>GMP Application</td>
                            <td><span class="badge mapped">Present</span></td>
                            <td><span class="badge mapped">Mapped</span></td>
                            <td><span class="badge mapped">Assigned</span></td>
                            <td><span class="badge partial">Needs Confirmation</span></td>
                            <td><span class="badge partial">Partial</span></td>
                            <td><span class="badge mapped">Available</span></td>
                            <td><span class="badge conditional">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>Operational Workstation</td>
                            <td><span class="badge missing">Missing</span></td>
                            <td><span class="badge partial">Pending</span></td>
                            <td><span class="badge missing">Missing</span></td>
                            <td><span class="badge missing">Missing</span></td>
                            <td><span class="badge missing">Not Mapped</span></td>
                            <td><span class="badge missing">Missing</span></td>
                            <td><span class="badge blocked">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled administrative access route</span></td>
                            <td>Infrastructure Dependency</td>
                            <td><span class="badge mapped">Present</span></td>
                            <td><span class="badge mapped">Mapped</span></td>
                            <td><span class="badge mapped">Assigned</span></td>
                            <td><span class="badge mapped">Mapped</span></td>
                            <td><span class="badge mapped">Admin / Vendor Roles</span></td>
                            <td><span class="badge mapped">Available</span></td>
                            <td><span class="badge ready">Ready</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Readiness Decision Logic</h2>
                <p>
                    CITrust™ applies a governance-first decision model. A CI may exist in a CMDB, spreadsheet, master list, asset system, or intake queue, but it is not operationally trustworthy until the access approval path can be defended.
                </p>

                <div class="decision">
                    <div class="logic-box">
                        <h3>Ready for MyAccess Routing</h3>
                        <ul>
                            <li>CI owner is identified and accountable.</li>
                            <li>Support group is mapped for operational routing.</li>
                            <li>LCM is assigned or clearly inherited.</li>
                            <li>Approver group is mapped to the CI or owning service.</li>
                            <li>Access roles are defined and aligned to operational need.</li>
                            <li>Evidence is available for audit or review.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Blocked from Trusted Routing</h3>
                        <ul>
                            <li>Owner is missing or unclear.</li>
                            <li>Support group cannot be confirmed.</li>
                            <li>LCM accountability is absent.</li>
                            <li>MyAccess approver path cannot be defended.</li>
                            <li>Access roles are not mapped to the CI.</li>
                            <li>Evidence lineage is missing, stale, or not reviewable.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Governance Assurance Checks</h2>

                <div class="cards">
                    <div class="card">
                        <h3>Ownership Assurance</h3>
                        <p>
                            Confirms that the CI has an accountable owner and that ownership is not merely present as a field, but operationally usable for approval, escalation, and audit questions.
                        </p>
                    </div>

                    <div class="card">
                        <h3>Support Group Assurance</h3>
                        <p>
                            Verifies that operational incidents, access questions, and support escalations can route to a real support group instead of becoming orphaned or manually interpreted.
                        </p>
                    </div>

                    <div class="card">
                        <h3>LCM Accountability</h3>
                        <p>
                            Confirms lifecycle ownership for maintenance, change impact, retirement, revalidation triggers, and CMDB governance continuity.
                        </p>
                    </div>

                    <div class="card">
                        <h3>Approver Path Validation</h3>
                        <p>
                            Determines whether MyAccess approval routing can be defended based on CI owner, application owner, support group, or role-based governance mapping.
                        </p>
                    </div>

                    <div class="card">
                        <h3>Role Mapping Readiness</h3>
                        <p>
                            Identifies whether requestable roles are defined, justified, and connected to operational responsibilities such as technician, supervisor, admin, reviewer, or vendor access.
                        </p>
                    </div>

                    <div class="card">
                        <h3>Evidence Lineage</h3>
                        <p>
                            Links the CI to supporting records such as SOPs, validation evidence, access review artifacts, backup review evidence, audit trail review evidence, and submission documentation.
                        </p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Pre-Deviation Readiness View</h2>
                <p>
                    This page supports pre-deviation readiness by identifying weak CI governance before access failures, unsupported approvals, audit findings, or operational ownership gaps become formal issues.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Risk Scenario</th>
                            <th>Governance Gap</th>
                            <th>CITrust™ Control Response</th>
                            <th>Outcome</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Access request routes to the wrong approver</td>
                            <td>Approver group not mapped to CI owner/support model</td>
                            <td>Flag as conditional or blocked before MyAccess reliance</td>
                            <td>Prevents unsupported approval routing</td>
                        </tr>
                        <tr>
                            <td>Incident cannot be assigned correctly</td>
                            <td>Support group missing or stale</td>
                            <td>Require support group confirmation before CMDB-readiness</td>
                            <td>Improves operational continuity</td>
                        </tr>
                        <tr>
                            <td>Audit asks who owns system access</td>
                            <td>Owner and access roles not evidence-backed</td>
                            <td>Generate governance explanation and evidence requirement</td>
                            <td>Improves audit defensibility</td>
                        </tr>
                        <tr>
                            <td>Retired or OOS equipment remains active in access workflow</td>
                            <td>Lifecycle state not reconciled with access routing</td>
                            <td>Block trusted routing until closure evidence is linked</td>
                            <td>Reduces orphaned access exposure</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, or write directly into ServiceNow in this demo. This page is a governance assurance overlay for CMDB-readiness, MyAccess routing readiness, operational accountability, evidence lineage, and audit readiness. Future ServiceNow API integration may be added as a controlled integration layer after governance validation.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_MYACCESS_READINESS_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust MyAccess Readiness page installed with alias route.")
