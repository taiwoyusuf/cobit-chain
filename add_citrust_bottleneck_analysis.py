from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_BOTTLENECK_ANALYSIS_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/bottleneck-analysis")'
ROUTE_ALIAS = '@app.route("/citrust/readiness-bottlenecks")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Bottleneck Analysis already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_BOTTLENECK_ANALYSIS_V1_ACTIVE
# ============================================================

@app.route("/citrust/bottleneck-analysis")
@app.route("/citrust/readiness-bottlenecks")
def citrust_bottleneck_analysis():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Readiness Bottleneck Analysis</title>
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
                    radial-gradient(circle at top right, rgba(247,201,72,0.15), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(255,92,112,0.08), transparent 30%),
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

            .flow {
                display: grid;
                grid-template-columns: repeat(5, 1fr);
                gap: 12px;
                margin-top: 16px;
            }

            .flow-step {
                border: 1px solid rgba(247,201,72,0.28);
                background: rgba(247,201,72,0.07);
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
                .kpis, .cards, .flow, .two-col {
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
                <h1>CITrust™ Readiness Bottleneck Analysis</h1>

                <div class="subtitle">
                    Identifies the specific governance blockers preventing Configuration Items from becoming ServiceNow-ready, MyAccess-ready, audit-ready, support-ready, evidence-backed, and operationally trusted.
                </div>

                <div class="positioning">
                    <strong>Bottleneck boundary:</strong>
                    ServiceNow remains the system of record. CITrust™ does not create ServiceNow CIs, update CMDB fields, or bypass the Candidate Review Board. This page shows why records are delayed, blocked, conditional, or not yet ready for ServiceNow-style submission and operational reliance.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                    <a href="/citrust/trust-score-model">Trust Score Model</a>
                    <a href="/citrust/submission-board">Submission Board</a>
                    <a href="/citrust/reconciliation">CMDB Reconciliation</a>
                    <a href="/citrust/evidence-lineage">Evidence Lineage</a>
                    <a href="/citrust/orphans">Orphan CI Intelligence</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Total Bottlenecks</div>
                    <div class="value">37</div>
                    <div class="note">Open blockers across ownership, support, access, evidence, lifecycle, data, and dependency domains.</div>
                </div>

                <div class="metric">
                    <div class="label">Critical Blockers</div>
                    <div class="value" style="color: var(--red);">9</div>
                    <div class="note">Must be fixed before CI can be trusted or submitted.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Blockers</div>
                    <div class="value" style="color: var(--yellow);">16</div>
                    <div class="note">Records can remain in review but not fully trusted.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Bottlenecks</div>
                    <div class="value" style="color: var(--orange);">12</div>
                    <div class="note">SOP, backup, audit trail, closure, validation, or submission evidence gaps.</div>
                </div>

                <div class="metric">
                    <div class="label">Ownership Bottlenecks</div>
                    <div class="value" style="color: var(--blue);">8</div>
                    <div class="note">Owner, support group, LCM, or escalation accountability is missing or unclear.</div>
                </div>

                <div class="metric">
                    <div class="label">Ready After Cleanup</div>
                    <div class="value" style="color: var(--green);">14</div>
                    <div class="note">Records likely to become trusted after targeted remediation.</div>
                </div>
            </section>

            <section class="section">
                <h2>Bottleneck Analysis Answer</h2>
                <p>
                    This console answers what is slowing or blocking CITrust™ readiness.
                </p>

                <div class="answer">
                    <strong>Current bottleneck interpretation:</strong>
                    The biggest blockers are evidence lineage, missing or unclear support groups, incomplete MyAccess role mapping, OOS lifecycle closure, hidden operational dependencies, and incomplete candidate data. These bottlenecks should be cleared before records move to ServiceNow-style submission or executive trust reporting.
                </div>
            </section>

            <section class="section">
                <h2>Readiness Bottleneck Flow</h2>
                <p>
                    CITrust™ separates readiness blockers into a sequence so teams know exactly where the record is stuck.
                </p>

                <div class="flow">
                    <div class="flow-step">
                        <h3>1. Intake Block</h3>
                        <p>Candidate lacks enough source data to begin review.</p>
                    </div>

                    <div class="flow-step">
                        <h3>2. Ownership Block</h3>
                        <p>Owner, support group, LCM, or escalation path is missing.</p>
                    </div>

                    <div class="flow-step">
                        <h3>3. Access Block</h3>
                        <p>MyAccess role, approver group, admin path, or vendor route is unclear.</p>
                    </div>

                    <div class="flow-step">
                        <h3>4. Evidence Block</h3>
                        <p>SOP, backup, audit trail, validation, closure, or submission evidence is missing.</p>
                    </div>

                    <div class="flow-step">
                        <h3>5. Submission Block</h3>
                        <p>Record is not ready for ServiceNow-style submission or operational reliance.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Bottleneck Matrix</h2>
                <p>
                    This matrix shows exactly why each CI is blocked, conditional, or delayed.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Primary Bottleneck</th>
                            <th>Secondary Bottleneck</th>
                            <th>Blocked Domain</th>
                            <th>Readiness Impact</th>
                            <th>Owner Needed</th>
                            <th>Severity</th>
                            <th>Next Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>Missing owner, LCM, access, evidence, and classification</td>
                            <td>Hidden operational dependency</td>
                            <td><span class="badge soft-red">Ownership / Evidence</span></td>
                            <td>Cannot be trusted or submitted</td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td><span class="badge red">Critical</span></td>
                            <td>Create governed CI candidate and assign owner, support group, LCM, access route, and evidence path.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>OOS closure evidence incomplete</td>
                            <td>Access deactivation and lifecycle owner unclear</td>
                            <td><span class="badge soft-red">Lifecycle / Access</span></td>
                            <td>Blocked from trusted lifecycle state</td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td><span class="badge red">Critical</span></td>
                            <td>Confirm OOS closure, attach closure evidence, verify access deactivation, and reconcile lifecycle state.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td>Support routing and access role evidence partial</td>
                            <td>Jump path and cutover evidence pending</td>
                            <td><span class="badge soft-yellow">Support / MyAccess</span></td>
                            <td>Conditional until cutover evidence is complete</td>
                            <td>Infrastructure / MyAccess Governance</td>
                            <td><span class="badge orange">High</span></td>
                            <td>Finalize support group, MyAccess role, jump path evidence, and cutover validation reference.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Support group pending</td>
                            <td>Evidence and data quality partial</td>
                            <td><span class="badge soft-yellow">Support / Data Quality</span></td>
                            <td>Conditional before ServiceNow-readiness</td>
                            <td>Operational Owner / CMDB Governance</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Reconcile support group, owner, lifecycle state, and evidence path.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Procedure evidence not fully linked</td>
                            <td>Privileged access explanation needs support evidence</td>
                            <td><span class="badge soft-blue">Access / Evidence</span></td>
                            <td>Conditional before full audit readiness</td>
                            <td>Infrastructure / Access Governance</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Attach admin access procedure, vendor access evidence, and support routing context.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>Approver group confirmation needed</td>
                            <td>Access role evidence should be verified</td>
                            <td><span class="badge soft-yellow">MyAccess</span></td>
                            <td>Conditional before access-readiness</td>
                            <td>Application Governance / Access Governance</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Confirm approver group, role mapping, and access evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>No major active bottleneck</td>
                            <td>Periodic review only</td>
                            <td><span class="badge soft-green">Governed</span></td>
                            <td>Ready for trusted use</td>
                            <td>Current owner</td>
                            <td><span class="badge green">Low</span></td>
                            <td>Maintain periodic owner, support, access, lifecycle, and evidence review.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Bottleneck Control Domains</h2>
                <p>
                    CITrust™ converts readiness delays into actionable governance workstreams.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Ownership Bottleneck</h3>
                        <p>Missing CI owner, support group, LCM, escalation owner, or accountability evidence prevents trust.</p>
                    </div>

                    <div class="card">
                        <h3>Access Bottleneck</h3>
                        <p>Incomplete MyAccess role, approver group, requestability, admin path, or vendor access route blocks access readiness.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Bottleneck</h3>
                        <p>Missing SOP, backup, audit trail, validation, closure, lifecycle, or submission evidence blocks audit readiness.</p>
                    </div>

                    <div class="card">
                        <h3>Data Bottleneck</h3>
                        <p>Incomplete, stale, duplicate, inconsistent, or unclassified CI data blocks ServiceNow-readiness.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Bottleneck Decision Logic</h2>
                <p>
                    A CI should not move forward until its blocking condition is resolved or formally documented.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Can Move Forward</h3>
                        <ul>
                            <li>Owner, support group, and LCM are confirmed.</li>
                            <li>MyAccess route and access roles are mapped.</li>
                            <li>Evidence lineage is complete or documented as not applicable.</li>
                            <li>Lifecycle state is reconciled.</li>
                            <li>Dependency chain is known.</li>
                            <li>Candidate Review Board has no blocking issue.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Must Stay Blocked</h3>
                        <ul>
                            <li>Owner, support group, LCM, or escalation path is missing.</li>
                            <li>Access approval route cannot be defended.</li>
                            <li>Evidence is missing, stale, or disconnected.</li>
                            <li>OOS or retired lifecycle state is unresolved.</li>
                            <li>Dependency is hidden or undocumented.</li>
                            <li>Submission would create weak or orphaned CMDB data.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Bottleneck Remediation Queue</h2>
                <p>
                    These are the highest-value actions to unblock CITrust™ readiness.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Bottleneck</th>
                            <th>Why It Blocks Readiness</th>
                            <th>Required Remediation</th>
                            <th>Expected Unlock</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation</td>
                            <td>No owner, LCM, access mapping, evidence, or classification.</td>
                            <td>Create governed candidate and assign full accountability model.</td>
                            <td>Unlock candidate review and evidence lineage.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS closure gap</td>
                            <td>Out-of-service record cannot be defended without closure and access evidence.</td>
                            <td>Attach closure evidence and confirm access deactivation.</td>
                            <td>Unlock lifecycle readiness and reduce orphan risk.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Cutover support/access gap</td>
                            <td>Cutover-sensitive systems need final support group, jump path, and MyAccess readiness.</td>
                            <td>Confirm support routing, access roles, jump path, and cutover evidence.</td>
                            <td>Unlock change impact and operational readiness.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Partial support group mapping</td>
                            <td>Operational routing cannot be trusted for several equipment records.</td>
                            <td>Reconcile support group against owner, LCM, source list, and candidate record.</td>
                            <td>Unlock ServiceNow-readiness and support-readiness.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, update CMDB data, or bypass candidate review in this demo. This bottleneck analysis is a governance assurance overlay for identifying readiness blockers across ownership, support group, MyAccess, evidence lineage, lifecycle state, dependency lineage, data quality, classification, ServiceNow-readiness, audit readiness, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_BOTTLENECK_ANALYSIS_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Bottleneck Analysis installed.")
