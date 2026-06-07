from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CHANGE_IMPACT_READINESS_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/change-impact-readiness")'
ROUTE_ALIAS = '@app.route("/citrust/change-impact")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Change Impact Readiness Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CHANGE_IMPACT_READINESS_V1_ACTIVE
# ============================================================

@app.route("/citrust/change-impact-readiness")
@app.route("/citrust/change-impact")
def citrust_change_impact_readiness():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Change Impact Readiness Console</title>
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

            .answer {
                border: 1px solid rgba(255,184,107,0.38);
                background: rgba(255,184,107,0.10);
                color: #ffefd8;
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
                border: 1px solid rgba(255,184,107,0.28);
                background: rgba(255,184,107,0.07);
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
                <h1>CITrust™ Change Impact Readiness Console</h1>

                <div class="subtitle">
                    Validates whether a Configuration Item can support change control, migration, cutover, patching, retirement, access modification, or dependency update without creating ownership, support, evidence, access, lifecycle, or audit risk.
                </div>

                <div class="positioning">
                    <strong>Change governance boundary:</strong>
                    ServiceNow may manage change records and CMDB relationships. CITrust™ validates whether the CI has enough governed context to support change impact analysis. This page does not create ServiceNow changes, does not update ServiceNow CIs, and does not replace formal change control.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/servicenow-ci-readiness">ServiceNow CI Readiness</a>
                    <a href="/citrust/dependency-lineage">Dependency Lineage</a>
                    <a href="/citrust/lifecycle-readiness">Lifecycle Readiness</a>
                    <a href="/citrust/support-group-readiness">Support Routing</a>
                    <a href="/citrust/evidence-lineage">Evidence Lineage</a>
                    <a href="/citrust/pre-deviation-readiness">Pre-Deviation Readiness</a>
                    <a href="/citrust/trust-score-model">Trust Score Model</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Change Impact Checks</div>
                    <div class="value">42</div>
                    <div class="note">CIs assessed for change, cutover, migration, access, retirement, and support impact.</div>
                </div>

                <div class="metric">
                    <div class="label">Change-Ready CIs</div>
                    <div class="value" style="color: var(--green);">17</div>
                    <div class="note">Impact path is clear enough for controlled change review.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Impact</div>
                    <div class="value" style="color: var(--yellow);">14</div>
                    <div class="note">Change can proceed only after named governance gaps are closed.</div>
                </div>

                <div class="metric">
                    <div class="label">Blocked Impact</div>
                    <div class="value" style="color: var(--red);">7</div>
                    <div class="note">Impact cannot be defended due to missing ownership, support, evidence, or dependency data.</div>
                </div>

                <div class="metric">
                    <div class="label">Cutover-Sensitive</div>
                    <div class="value" style="color: var(--orange);">8</div>
                    <div class="note">Records affected by migration, revalidation, jump path, or access model changes.</div>
                </div>

                <div class="metric">
                    <div class="label">Access Impact Risks</div>
                    <div class="value" style="color: var(--blue);">9</div>
                    <div class="note">Changes may affect MyAccess roles, approver groups, admin paths, or vendor access.</div>
                </div>
            </section>

            <section class="section">
                <h2>Change Impact Readiness Answer</h2>
                <p>
                    This console answers whether a CI has enough governed context to survive change impact review.
                </p>

                <div class="answer">
                    <strong>Current change interpretation:</strong>
                    The CI estate is partially ready for change impact analysis. Some systems can support controlled change decisions, but records with partial dependency lineage, unclear support group, incomplete MyAccess mapping, missing evidence, or unresolved OOS lifecycle status should not be treated as change-ready until remediation is complete.
                </div>
            </section>

            <section class="section">
                <h2>Change Impact Chain</h2>
                <p>
                    CITrust™ checks whether a proposed change can be traced across the operational trust chain.
                </p>

                <div class="flow">
                    <div class="flow-step">
                        <h3>1. Change Trigger</h3>
                        <p>Cutover, patch, migration, retirement, access change, dependency update, or support model change.</p>
                    </div>

                    <div class="flow-step">
                        <h3>2. CI Context</h3>
                        <p>Owner, support group, LCM, lifecycle state, operational purpose, and CI class are checked.</p>
                    </div>

                    <div class="flow-step">
                        <h3>3. Dependency Impact</h3>
                        <p>Upstream, downstream, infrastructure, workstation, vendor, and access path dependencies are reviewed.</p>
                    </div>

                    <div class="flow-step">
                        <h3>4. Evidence Impact</h3>
                        <p>SOP, validation, backup, audit trail, access, closure, and submission evidence are checked.</p>
                    </div>

                    <div class="flow-step">
                        <h3>5. Readiness Decision</h3>
                        <p>CI is classified as change-ready, conditional, or blocked before relying on it operationally.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Change Impact Readiness Matrix</h2>
                <p>
                    This matrix shows whether each CI can support change impact analysis without relying on tribal knowledge.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Change Scenario</th>
                            <th>Owner / LCM</th>
                            <th>Support Impact</th>
                            <th>Access Impact</th>
                            <th>Dependency Impact</th>
                            <th>Evidence Impact</th>
                            <th>Change Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>Application governance update</td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge green">Change-Ready</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td>Cutover / server transition</td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Needs Final Confirmation</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Jump Path Pending</span></td>
                            <td><span class="badge soft-yellow">Cutover Evidence</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Access model change</td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-yellow">Procedure Link Needed</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Operational support update</td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Local Dependency</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>Retirement / closure</td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Confirmed</span></td>
                            <td><span class="badge soft-red">Unknown</span></td>
                            <td><span class="badge soft-yellow">Closure Needed</span></td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Chromeleon Workstation</strong><br><span style="color: var(--muted);">Lab workstation dependency</span></td>
                            <td>Workstation / access review</td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-yellow">Role Check</span></td>
                            <td><span class="badge soft-yellow">Workstation Link</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>Backup review process change</td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Hidden</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>Application access update</td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Change Impact Control Domains</h2>
                <p>
                    CITrust™ separates change impact into specific governance domains so teams know exactly what must be fixed.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Ownership Impact</h3>
                        <p>Confirms who owns the change impact decision and whether CI owner, LCM, and support group are aligned.</p>
                    </div>

                    <div class="card">
                        <h3>Access Impact</h3>
                        <p>Checks whether the change affects MyAccess roles, approver groups, privileged access, vendor access, or jump paths.</p>
                    </div>

                    <div class="card">
                        <h3>Dependency Impact</h3>
                        <p>Identifies upstream, downstream, workstation, server, infrastructure, and operational review dependencies.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Impact</h3>
                        <p>Links the change decision to SOPs, validation evidence, backup reviews, audit trail reviews, closure records, or cutover artifacts.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Change Decision Logic</h2>
                <p>
                    CITrust™ keeps change readiness separate from change execution.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Change-Ready CI</h3>
                        <ul>
                            <li>Owner, support group, and LCM are confirmed.</li>
                            <li>Change impact can be traced across dependencies.</li>
                            <li>Access impact is mapped through MyAccess or governed access model.</li>
                            <li>Evidence exists for current state and proposed transition.</li>
                            <li>Lifecycle state is clear and current.</li>
                            <li>Support and escalation paths are defined.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Blocked Change Impact</h3>
                        <ul>
                            <li>Owner, support group, or LCM is missing.</li>
                            <li>Access impact cannot be explained.</li>
                            <li>Dependency impact is hidden or unknown.</li>
                            <li>OOS or retired record lacks closure evidence.</li>
                            <li>Evidence is missing or disconnected from the CI.</li>
                            <li>Change would create audit, access, support, or operational readiness risk.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Change Impact Remediation Queue</h2>
                <p>
                    These gaps should be resolved before the related CIs are used for change, cutover, migration, retirement, or access modification decisions.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Record</th>
                            <th>Change Impact Gap</th>
                            <th>Required Action</th>
                            <th>Target State</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Local Backup Review Workstation</td>
                            <td>Change impact cannot be assessed because owner, access, dependency, and evidence are missing.</td>
                            <td>Create governed CI candidate and map owner, support group, LCM, access route, and backup evidence.</td>
                            <td>Change-assessable governed dependency.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Speedy Glove 1802</td>
                            <td>Retirement and OOS impact cannot be defended without closure and access removal evidence.</td>
                            <td>Attach closure evidence, confirm access deactivation, and reconcile lifecycle responsibility.</td>
                            <td>Defensible closed or retired record.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Niagara BMS Server</td>
                            <td>Cutover impact depends on support group, jump path, MyAccess, and validation evidence.</td>
                            <td>Confirm support routing, jump access path, MyAccess role mapping, and cutover evidence.</td>
                            <td>Change-ready cutover CI.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Empower Lab System</td>
                            <td>Access change impact requires approver group and role mapping confirmation.</td>
                            <td>Confirm MyAccess approver group and role evidence before access-related change reliance.</td>
                            <td>Access-change-ready CI.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow Change Management, create ServiceNow changes, create ServiceNow CIs, update CMDB relationships, or write directly into ServiceNow in this demo. This change impact readiness console is a governance assurance overlay for CI change readiness, cutover defensibility, migration impact, retirement impact, access modification readiness, dependency lineage, evidence lineage, audit readiness, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_CHANGE_IMPACT_READINESS_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Change Impact Readiness Console installed.")
