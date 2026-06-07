from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_PRE_DEVIATION_READINESS_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/pre-deviation-readiness")'
ROUTE_ALIAS = '@app.route("/citrust/pre-deviation-defense")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Pre-Deviation Readiness Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_PRE_DEVIATION_READINESS_V1_ACTIVE
# ============================================================

@app.route("/citrust/pre-deviation-readiness")
@app.route("/citrust/pre-deviation-defense")
def citrust_pre_deviation_readiness():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Pre-Deviation Readiness Console</title>
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
                    radial-gradient(circle at top right, rgba(255,92,112,0.13), transparent 28%),
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
                border: 1px solid rgba(247,201,72,0.38);
                background: rgba(247,201,72,0.10);
                color: #fff4cc;
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

            .prevention-grid {
                display: grid;
                grid-template-columns: repeat(5, 1fr);
                gap: 12px;
                margin-top: 16px;
            }

            .prevention-step {
                border: 1px solid rgba(247,201,72,0.28);
                background: rgba(247,201,72,0.07);
                border-radius: 18px;
                padding: 16px;
            }

            .prevention-step h3 {
                margin: 0 0 8px 0;
                font-size: 15px;
            }

            .prevention-step p {
                margin: 0;
                font-size: 13px;
                color: var(--muted);
                line-height: 1.5;
            }

            .footer {
                color: var(--muted);
                font-size: 12px;
                margin-top: 22px;
                line-height: 1.6;
            }

            @media (max-width: 1180px) {
                .kpis, .cards, .two-col, .prevention-grid {
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
                <h1>CITrust™ Pre-Deviation Readiness Console</h1>

                <div class="subtitle">
                    Identifies weak CI ownership, support routing, MyAccess mapping, evidence lineage, lifecycle state, and dependency governance before those gaps become deviations, audit findings, failed approvals, incident-routing failures, or operational readiness blockers.
                </div>

                <div class="positioning">
                    <strong>Pre-deviation boundary:</strong>
                    CITrust™ does not replace deviation management, CAPA, ServiceNow, or the CMDB. It acts as a governance assurance overlay that detects CI governance weaknesses early, so teams can remediate records before operational failures or formal quality events occur.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/servicenow-ci-readiness">ServiceNow CI Readiness</a>
                    <a href="/citrust/evidence-lineage">Evidence Lineage</a>
                    <a href="/citrust/dependency-lineage">Dependency Lineage</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                    <a href="/citrust/ownership-readiness">Ownership Readiness</a>
                    <a href="/citrust/myaccess-readiness">MyAccess Readiness</a>
                    <a href="/citrust/orphans">Orphan CI Intelligence</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Pre-Deviation Checks</div>
                    <div class="value">64</div>
                    <div class="note">Checks across ownership, access, support, lifecycle, dependency, evidence, and audit readiness.</div>
                </div>

                <div class="metric">
                    <div class="label">Issues Prevented</div>
                    <div class="value" style="color: var(--green);">21</div>
                    <div class="note">Records with gaps detected before becoming formal operational or audit problems.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Watchlist</div>
                    <div class="value" style="color: var(--yellow);">18</div>
                    <div class="note">Records that can remain active only with tracked remediation or documented exception.</div>
                </div>

                <div class="metric">
                    <div class="label">High-Risk Gaps</div>
                    <div class="value" style="color: var(--red);">9</div>
                    <div class="note">Missing owner, support group, LCM, access path, evidence, or lifecycle closure.</div>
                </div>

                <div class="metric">
                    <div class="label">Access-Routing Risks</div>
                    <div class="value" style="color: var(--blue);">7</div>
                    <div class="note">MyAccess, approver group, or role mapping weaknesses that could create approval defects.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Risks</div>
                    <div class="value" style="color: var(--orange);">12</div>
                    <div class="note">SOP, backup, audit trail, closure, validation, or submission evidence gaps.</div>
                </div>
            </section>

            <section class="section">
                <h2>Pre-Deviation Readiness Answer</h2>
                <p>
                    This console answers whether CI governance gaps are being caught before they become formal problems.
                </p>

                <div class="answer">
                    <strong>Current prevention interpretation:</strong>
                    CITrust™ is detecting several early-warning signals before they become deviations or audit findings. The most important prevention opportunities are ownerless operational assets, partial MyAccess role mapping, missing support-group confirmation, OOS lifecycle closure gaps, incomplete evidence lineage, and hidden dependency records used for recurring reviews.
                </div>
            </section>

            <section class="section">
                <h2>Pre-Deviation Detection Model</h2>
                <p>
                    CITrust™ turns CMDB weakness into an early-warning model. The goal is to find governance defects while they are still fixable.
                </p>

                <div class="prevention-grid">
                    <div class="prevention-step">
                        <h3>1. Detect</h3>
                        <p>Find missing owner, support group, LCM, access mapping, evidence, lifecycle, or dependency fields.</p>
                    </div>

                    <div class="prevention-step">
                        <h3>2. Classify</h3>
                        <p>Separate low-risk cleanup items from high-risk operational, access, audit, and readiness gaps.</p>
                    </div>

                    <div class="prevention-step">
                        <h3>3. Route</h3>
                        <p>Send the issue to ownership, MyAccess, reconciliation, orphan, evidence, or candidate review workflow.</p>
                    </div>

                    <div class="prevention-step">
                        <h3>4. Remediate</h3>
                        <p>Assign owner, attach evidence, confirm support group, map access, or reconcile lifecycle state.</p>
                    </div>

                    <div class="prevention-step">
                        <h3>5. Defend</h3>
                        <p>Convert the CI from weak or conditional state into an operationally defensible record.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Pre-Deviation Readiness Matrix</h2>
                <p>
                    This matrix identifies records that could become deviations, audit observations, access failures, support-routing issues, or ServiceNow-readiness blockers if not remediated early.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Early Warning Signal</th>
                            <th>Likely Failure Mode</th>
                            <th>Governance Domain</th>
                            <th>Pre-Deviation Action</th>
                            <th>Risk Level</th>
                            <th>Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>Owner, LCM, MyAccess, SOP, and evidence missing</td>
                            <td>Backup review cannot be defended during audit or inspection</td>
                            <td><span class="badge soft-red">Evidence / Ownership</span></td>
                            <td>Create governed CI candidate and attach review evidence path</td>
                            <td><span class="badge red">High</span></td>
                            <td><span class="badge red">Immediate Remediation</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>OOS closure and access deactivation evidence incomplete</td>
                            <td>Retired/OOS equipment appears active or insufficiently closed</td>
                            <td><span class="badge soft-red">Lifecycle / Access</span></td>
                            <td>Attach closure evidence and confirm access removal</td>
                            <td><span class="badge red">High</span></td>
                            <td><span class="badge red">Block Until Closed</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS server / facility support dependency</span></td>
                            <td>Support routing, access role, and cutover evidence remain partial</td>
                            <td>Incident or access approval path may not be defendable after cutover</td>
                            <td><span class="badge soft-yellow">Support / Access</span></td>
                            <td>Confirm support group, MyAccess role, jump path, and cutover evidence</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge yellow">Conditional Watchlist</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Support group and evidence linkage partial</td>
                            <td>Operational support accountability may be unclear during issue response</td>
                            <td><span class="badge soft-yellow">Support / Evidence</span></td>
                            <td>Reconcile support group and evidence path before ServiceNow-readiness</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge yellow">Remediate Before Submission</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Admin access procedure evidence should be linked</td>
                            <td>Privileged access model may be difficult to explain during audit</td>
                            <td><span class="badge soft-blue">Access / Procedure</span></td>
                            <td>Attach admin-access procedure or vendor-access governance evidence</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge yellow">Procedure Link Needed</span></td>
                        </tr>

                        <tr>
                            <td><strong>Chromeleon Workstation</strong><br><span style="color: var(--muted);">Lab workstation dependency</span></td>
                            <td>Role mapping and workstation dependency should be confirmed</td>
                            <td>Access review may not align with actual workstation use</td>
                            <td><span class="badge soft-blue">Access / Dependency</span></td>
                            <td>Confirm role mapping, workstation reference, and support path</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge yellow">Controlled Review</span></td>
                        </tr>

                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>No major early warning signal</td>
                            <td>Low immediate deviation risk from CI governance perspective</td>
                            <td><span class="badge soft-green">Governed</span></td>
                            <td>Maintain periodic ownership, access, and evidence review</td>
                            <td><span class="badge green">Low</span></td>
                            <td><span class="badge green">Monitor</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>Approver group confirmation needed</td>
                            <td>Access approval route may require manual interpretation</td>
                            <td><span class="badge soft-yellow">Access Governance</span></td>
                            <td>Confirm approver group and role mapping evidence</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge yellow">Conditional Watchlist</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Pre-Deviation Control Domains</h2>
                <p>
                    These are the CI governance gaps most likely to become formal issues if they remain unmanaged.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Ownerless CI Risk</h3>
                        <p>Detects records that cannot answer who owns, supports, escalates, or approves decisions for the CI.</p>
                    </div>

                    <div class="card">
                        <h3>Access Routing Risk</h3>
                        <p>Flags weak MyAccess roles, approver groups, vendor paths, admin routes, and requestability mapping.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Gap Risk</h3>
                        <p>Identifies missing SOP, backup, audit trail, validation, lifecycle, closure, and submission evidence.</p>
                    </div>

                    <div class="card">
                        <h3>Dependency Blind Spot</h3>
                        <p>Finds hidden workstations, local processes, jump paths, support relationships, and operational dependencies.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Pre-Deviation Decision Logic</h2>
                <p>
                    CITrust™ classifies each weakness before it becomes a larger governance event.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Prevented Issue</h3>
                        <ul>
                            <li>Weakness was detected before operational reliance.</li>
                            <li>Owner, support group, or LCM can be assigned before audit or access impact.</li>
                            <li>Evidence can be attached before submission or review.</li>
                            <li>Access routing can be corrected before wrong approvals occur.</li>
                            <li>OOS or retired records can be closed before orphan exposure persists.</li>
                            <li>Candidate remains in governance review until trust criteria are met.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Escalation Needed</h3>
                        <ul>
                            <li>No clear CI owner, support group, LCM, or escalation path exists.</li>
                            <li>Access approval routing cannot be defended.</li>
                            <li>Evidence required for audit or inspection cannot be located.</li>
                            <li>Lifecycle state is contradictory across sources.</li>
                            <li>Hidden dependency affects recurring operational review.</li>
                            <li>ServiceNow-ready status would create a weak or orphaned record.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Pre-Deviation Remediation Queue</h2>
                <p>
                    These are the actions that should be completed before gaps become deviations, audit findings, or operational blockers.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Record</th>
                            <th>Preventive Action</th>
                            <th>Owner Group</th>
                            <th>Target Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Local Backup Review Workstation</td>
                            <td>Create candidate record, assign owner, map support group, define LCM, and link backup review evidence.</td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td>Prevent audit finding from undocumented review dependency.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Speedy Glove 1802</td>
                            <td>Confirm OOS closure, attach closure evidence, and verify access deactivation.</td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td>Prevent orphaned lifecycle and access exposure.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Niagara BMS Server</td>
                            <td>Finalize support group, MyAccess role mapping, jump path, and cutover evidence linkage.</td>
                            <td>Infrastructure / MyAccess Governance</td>
                            <td>Prevent post-cutover routing and access ambiguity.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Empower Lab System</td>
                            <td>Confirm approver group and access role evidence before treating as fully access-ready.</td>
                            <td>Application Governance / Access Governance</td>
                            <td>Prevent unsupported access approval route.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CMDB governance, deviation management, CAPA, or audit systems. This pre-deviation readiness console is a governance assurance overlay for identifying weak CI ownership, support routing, MyAccess mapping, evidence lineage, lifecycle state, dependency gaps, ServiceNow-readiness blockers, and audit exposure before they become formal operational or quality events.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_PRE_DEVIATION_READINESS_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Pre-Deviation Readiness Console installed.")
