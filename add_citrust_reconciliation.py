from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_RECONCILIATION_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/reconciliation")'
ROUTE_ALIAS = '@app.route("/citrust/cmdb-reconciliation")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Reconciliation Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_RECONCILIATION_V1_ACTIVE
# ============================================================

@app.route("/citrust/reconciliation")
@app.route("/citrust/cmdb-reconciliation")
def citrust_reconciliation():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ CMDB Reconciliation Console</title>
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
                    radial-gradient(circle at top left, rgba(92,200,255,0.18), transparent 30%),
                    radial-gradient(circle at top right, rgba(180,156,255,0.16), transparent 30%),
                    radial-gradient(circle at bottom, rgba(49,208,125,0.08), transparent 28%),
                    var(--bg);
                color: var(--text);
            }

            .page {
                max-width: 1360px;
                margin: 0 auto;
                padding: 28px;
            }

            .hero {
                border: 1px solid var(--line);
                background: linear-gradient(135deg, rgba(16,29,47,0.96), rgba(20,40,66,0.92));
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
                max-width: 1040px;
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

            .source-grid {
                display: grid;
                grid-template-columns: repeat(5, 1fr);
                gap: 14px;
                margin-top: 16px;
            }

            .source-card {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 18px;
            }

            .source-card h3 {
                margin: 0 0 8px 0;
                font-size: 16px;
            }

            .source-card p {
                margin: 0;
                color: var(--muted);
                font-size: 13px;
                line-height: 1.5;
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

            .trust-strip {
                display: grid;
                grid-template-columns: 1fr 1fr 1fr;
                gap: 14px;
                margin-top: 16px;
            }

            .trust-card {
                border-radius: 18px;
                padding: 18px;
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
            }

            .trust-card h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .trust-card p {
                margin: 0;
                color: var(--muted);
                font-size: 14px;
                line-height: 1.55;
            }

            .footer {
                color: var(--muted);
                font-size: 12px;
                margin-top: 22px;
                line-height: 1.6;
            }

            @media (max-width: 1100px) {
                .kpis, .source-grid, .two-col, .trust-strip {
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
                <h1>CITrust™ CMDB Reconciliation Console</h1>

                <div class="subtitle">
                    Compares ServiceNow-style CI records, MyAccess routing data, Blue Mountain asset references, master system lists, and CI candidate intake records to determine whether each Configuration Item can be operationally trusted.
                </div>

                <div class="positioning">
                    <strong>Governance assurance overlay:</strong>
                    ServiceNow remains the system of record. CITrust™ does not create ServiceNow CIs or write directly into ServiceNow in this demo. This console identifies mismatches, missing ownership, support-group gaps, stale lifecycle records, evidence gaps, and records that require candidate review before CMDB-readiness.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/servicenow-ci-readiness">ServiceNow CI Readiness</a>
                    <a href="/citrust/myaccess-readiness">MyAccess Readiness</a>
                    <a href="/ci-candidate-factory">CI Candidate Factory</a>
                    <a href="/ci-candidate-review">Candidate Review Board</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                    <a href="/citrust/orphans">Orphan CI Intelligence</a>
                    <a href="/ci-submission-pack">Submission Pack</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Records Compared</div>
                    <div class="value">42</div>
                    <div class="note">Across ServiceNow-style records, MyAccess, Blue Mountain, master list, and intake queue.</div>
                </div>

                <div class="metric">
                    <div class="label">Fully Reconciled</div>
                    <div class="value" style="color: var(--green);">18</div>
                    <div class="note">Ownership, support, lifecycle, access, and evidence references align.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Records</div>
                    <div class="value" style="color: var(--yellow);">14</div>
                    <div class="note">Usable only with documented remediation or governance exception.</div>
                </div>

                <div class="metric">
                    <div class="label">Blocked Records</div>
                    <div class="value" style="color: var(--red);">7</div>
                    <div class="note">Cannot be treated as operationally trustworthy until core gaps are resolved.</div>
                </div>

                <div class="metric">
                    <div class="label">Candidate Review Needed</div>
                    <div class="value" style="color: var(--blue);">3</div>
                    <div class="note">Potential CI candidates require review before ServiceNow submission readiness.</div>
                </div>
            </section>

            <section class="section">
                <h2>Source Systems Compared</h2>
                <p>
                    CITrust™ compares multiple operational references to detect whether the same CI is consistently governed across ownership, support routing, lifecycle control, access approval, and evidence lineage.
                </p>

                <div class="source-grid">
                    <div class="source-card">
                        <h3>ServiceNow-style CMDB</h3>
                        <p>Confirms CI class, owner, support group, lifecycle state, and operational relationship references.</p>
                    </div>

                    <div class="source-card">
                        <h3>MyAccess</h3>
                        <p>Checks whether access roles, approver groups, and routing logic can be defended.</p>
                    </div>

                    <div class="source-card">
                        <h3>Blue Mountain</h3>
                        <p>Compares equipment and asset references against governed CI candidate records.</p>
                    </div>

                    <div class="source-card">
                        <h3>Master System List</h3>
                        <p>Validates expected operational system inventory, ownership, and system criticality references.</p>
                    </div>

                    <div class="source-card">
                        <h3>CI Candidate Intake</h3>
                        <p>Tracks records not yet trusted enough for ServiceNow submission or operational reliance.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Reconciliation Matrix</h2>
                <p>
                    This matrix identifies whether each CI record is aligned across major governance sources. A matched field does not only mean data exists; it means the field is usable for operational accountability, access routing, and audit questions.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>ServiceNow-style Record</th>
                            <th>MyAccess Mapping</th>
                            <th>Blue Mountain / Asset Ref</th>
                            <th>Master List</th>
                            <th>Candidate Intake</th>
                            <th>Primary Gap</th>
                            <th>Trust Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge soft-green">Present</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-green">Referenced</span></td>
                            <td><span class="badge soft-green">Listed</span></td>
                            <td><span class="badge soft-blue">Candidate Active</span></td>
                            <td>Access role evidence and final support routing confirmation</td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset / calibration governance system</span></td>
                            <td><span class="badge soft-green">Present</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Primary Source</span></td>
                            <td><span class="badge soft-green">Listed</span></td>
                            <td><span class="badge soft-green">Closed</span></td>
                            <td>No major gap identified</td>
                            <td><span class="badge green">Trusted</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-green">Referenced</span></td>
                            <td><span class="badge soft-green">Listed</span></td>
                            <td><span class="badge soft-blue">Candidate Active</span></td>
                            <td>Support group and MyAccess role mapping not fully reconciled</td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-green">Referenced</span></td>
                            <td><span class="badge soft-yellow">Listed as OOS</span></td>
                            <td><span class="badge soft-blue">Closure Review</span></td>
                            <td>Lifecycle closure evidence and access deactivation proof needed</td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Chromeleon Workstation</strong><br><span style="color: var(--muted);">Lab workstation dependency</span></td>
                            <td><span class="badge soft-green">Present</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-yellow">Indirect</span></td>
                            <td><span class="badge soft-green">Listed</span></td>
                            <td><span class="badge soft-green">Reviewed</span></td>
                            <td>Asset reference should be confirmed for dependency completeness</td>
                            <td><span class="badge green">Trusted</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Present</span></td>
                            <td><span class="badge soft-yellow">Needs Confirmation</span></td>
                            <td><span class="badge soft-yellow">Indirect</span></td>
                            <td><span class="badge soft-green">Listed</span></td>
                            <td><span class="badge soft-green">Reviewed</span></td>
                            <td>Approver group confirmation and role mapping evidence</td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Possible Match</span></td>
                            <td><span class="badge soft-blue">Candidate Needed</span></td>
                            <td>No trusted owner, CI class, support group, or evidence reference</td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled administrative access route</span></td>
                            <td><span class="badge soft-green">Present</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-blue">Dependency</span></td>
                            <td><span class="badge soft-green">Listed</span></td>
                            <td><span class="badge soft-green">Reviewed</span></td>
                            <td>No major gap identified</td>
                            <td><span class="badge green">Trusted</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Reconciliation Decision Rules</h2>
                <p>
                    A CI becomes trusted only when the governing record can survive operational, access, ownership, support, lifecycle, and audit questions.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Trusted Reconciliation</h3>
                        <ul>
                            <li>CI exists in the expected ServiceNow-style or candidate source.</li>
                            <li>Owner and support group are aligned across operational references.</li>
                            <li>MyAccess roles and approver group are mapped or justified.</li>
                            <li>Lifecycle state is not contradictory across sources.</li>
                            <li>Evidence lineage can be reviewed without relying on tribal knowledge.</li>
                            <li>Operational dependency relationships are clear enough for incident, change, and access routing.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Blocked Reconciliation</h3>
                        <ul>
                            <li>CI is present in one source but missing from critical governance sources.</li>
                            <li>Owner, support group, or LCM is missing or contradictory.</li>
                            <li>MyAccess routing cannot be explained or defended.</li>
                            <li>Out-of-service records still appear active in access or operational workflows.</li>
                            <li>Evidence is missing, stale, or disconnected from the CI.</li>
                            <li>Record requires Candidate Review Board decision before ServiceNow-readiness.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Governance Remediation Queue</h2>
                <p>
                    These are the actions CITrust™ would surface before leadership treats a Configuration Item as operationally trusted.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>CI / Record</th>
                            <th>Required Remediation</th>
                            <th>Responsible Governance Area</th>
                            <th>Readiness Impact</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Local Backup Review Workstation</td>
                            <td>Create or review CI candidate; assign owner, support group, LCM, access mapping, and evidence reference.</td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td>Blocked until candidate review is complete.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Speedy Glove 1802</td>
                            <td>Confirm lifecycle closure state, remove active access ambiguity, and attach closure evidence.</td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td>Blocked until OOS evidence is reconciled.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Niagara BMS Server</td>
                            <td>Finalize MyAccess role evidence and confirm support routing model after jump-server access path is validated.</td>
                            <td>Infrastructure / MyAccess Governance</td>
                            <td>Conditional until access routing is defendable.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Empower Lab System</td>
                            <td>Confirm approver group and role mapping against operational responsibilities.</td>
                            <td>Application Governance / Lab Systems</td>
                            <td>Conditional until approver path is confirmed.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Executive Trust Interpretation</h2>

                <div class="trust-strip">
                    <div class="trust-card">
                        <h3><span class="badge green">Trusted</span></h3>
                        <p>
                            The CI has consistent ownership, support, access, lifecycle, and evidence references across the compared sources.
                        </p>
                    </div>

                    <div class="trust-card">
                        <h3><span class="badge yellow">Conditional</span></h3>
                        <p>
                            The CI can remain in controlled review, but leadership should not treat it as fully operationally trusted until the named gaps are remediated.
                        </p>
                    </div>

                    <div class="trust-card">
                        <h3><span class="badge red">Blocked</span></h3>
                        <p>
                            The CI cannot be defended for operational reliance, access routing, audit response, or ServiceNow-readiness until core governance gaps are resolved.
                        </p>
                    </div>
                </div>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, or write directly into ServiceNow in this demo. This reconciliation console is a governance assurance overlay for comparing ServiceNow-style records, MyAccess mapping, Blue Mountain references, master system lists, and CI candidate intake records before CMDB-readiness or operational reliance.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_RECONCILIATION_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Reconciliation Console installed.")
