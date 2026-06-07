from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_DEPENDENCY_LINEAGE_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/dependency-lineage")'
ROUTE_ALIAS = '@app.route("/citrust/dependency-map")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Dependency Lineage Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_DEPENDENCY_LINEAGE_V1_ACTIVE
# ============================================================

@app.route("/citrust/dependency-lineage")
@app.route("/citrust/dependency-map")
def citrust_dependency_lineage():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Dependency Lineage Console</title>
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
                    radial-gradient(circle at bottom right, rgba(49,208,125,0.08), transparent 30%),
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
                border: 1px solid rgba(92,200,255,0.36);
                background: rgba(92,200,255,0.10);
                color: #d9f3ff;
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

            .lineage-flow {
                display: grid;
                grid-template-columns: repeat(5, 1fr);
                gap: 12px;
                margin-top: 16px;
            }

            .flow-step {
                border: 1px solid rgba(92,200,255,0.28);
                background: rgba(92,200,255,0.07);
                border-radius: 18px;
                padding: 16px;
            }

            .flow-step h3 {
                margin: 0 0 8px 0;
                font-size: 16px;
            }

            .flow-step p {
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
                .kpis, .cards, .two-col, .lineage-flow {
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
                <h1>CITrust™ Dependency Lineage Console</h1>

                <div class="subtitle">
                    Maps upstream, downstream, infrastructure, access, evidence, support, and operational dependencies so leadership can determine whether a Configuration Item can be trusted without hidden dependency risk.
                </div>

                <div class="positioning">
                    <strong>Governance boundary:</strong>
                    ServiceNow may store CI relationships. CITrust™ validates whether those relationships are complete, explainable, operationally usable, and evidence-backed. This page does not create ServiceNow relationships, does not write directly to ServiceNow, and does not replace CMDB relationship governance.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/servicenow-ci-readiness">ServiceNow CI Readiness</a>
                    <a href="/citrust/reconciliation">CMDB Reconciliation</a>
                    <a href="/citrust/ownership-readiness">Ownership Readiness</a>
                    <a href="/citrust/myaccess-readiness">MyAccess Readiness</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                    <a href="/citrust/orphans">Orphan CI Intelligence</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">CIs Assessed</div>
                    <div class="value">42</div>
                    <div class="note">Records checked for dependency completeness and operational lineage.</div>
                </div>

                <div class="metric">
                    <div class="label">Complete Lineage</div>
                    <div class="value" style="color: var(--green);">21</div>
                    <div class="note">Upstream, downstream, support, access, and evidence dependencies are explainable.</div>
                </div>

                <div class="metric">
                    <div class="label">Partial Lineage</div>
                    <div class="value" style="color: var(--yellow);">13</div>
                    <div class="note">Some dependencies are known but not fully governed or evidence-backed.</div>
                </div>

                <div class="metric">
                    <div class="label">Hidden Dependencies</div>
                    <div class="value" style="color: var(--orange);">9</div>
                    <div class="note">Dependencies discovered from operations but missing from trusted records.</div>
                </div>

                <div class="metric">
                    <div class="label">Blocked Lineage</div>
                    <div class="value" style="color: var(--red);">6</div>
                    <div class="note">Cannot defend impact, access, support, or audit dependency chain.</div>
                </div>

                <div class="metric">
                    <div class="label">Jump-Controlled Paths</div>
                    <div class="value" style="color: var(--blue);">12</div>
                    <div class="note">Dependencies requiring controlled administrative or vendor access path validation.</div>
                </div>
            </section>

            <section class="section">
                <h2>Dependency Lineage Answer</h2>
                <p>
                    This console answers whether a CI can be trusted by looking beyond the CI record itself.
                </p>

                <div class="answer">
                    <strong>Current dependency interpretation:</strong>
                    The CI estate has visible operational dependency risk. Some key records are governed well enough to support incident routing, access routing, and audit response, but several records still depend on hidden workstations, unclear support paths, partial MyAccess mappings, incomplete evidence references, or unconfirmed infrastructure relationships.
                </div>
            </section>

            <section class="section">
                <h2>Dependency Chain Model</h2>
                <p>
                    CITrust™ evaluates dependency lineage as a chain of trust. A CI can fail governance review even when the CI field itself looks complete if its support, access, infrastructure, or evidence dependencies are weak.
                </p>

                <div class="lineage-flow">
                    <div class="flow-step">
                        <h3>1. Business / GMP Use</h3>
                        <p>What process, lab activity, review, or operational task depends on the CI?</p>
                    </div>

                    <div class="flow-step">
                        <h3>2. Application / Equipment</h3>
                        <p>Which system, workstation, server, or equipment record performs the work?</p>
                    </div>

                    <div class="flow-step">
                        <h3>3. Infrastructure Path</h3>
                        <p>What network, jump server, workstation, server, or vendor path supports it?</p>
                    </div>

                    <div class="flow-step">
                        <h3>4. Access / Support Routing</h3>
                        <p>Who approves access, who supports incidents, and who escalates issues?</p>
                    </div>

                    <div class="flow-step">
                        <h3>5. Evidence Lineage</h3>
                        <p>What proof supports backup, audit trail, SOP, lifecycle, validation, or closure status?</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Dependency Lineage Matrix</h2>
                <p>
                    This matrix shows whether each CI has governed upstream, downstream, access, support, infrastructure, and evidence dependencies.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Upstream Dependency</th>
                            <th>Downstream Impact</th>
                            <th>Infrastructure Path</th>
                            <th>Access Dependency</th>
                            <th>Support Dependency</th>
                            <th>Evidence Dependency</th>
                            <th>Lineage Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance</span></td>
                            <td><span class="badge soft-green">Master Asset Source</span></td>
                            <td><span class="badge soft-green">Equipment Records</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge green">Complete Lineage</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge soft-yellow">Cutover Path</span></td>
                            <td><span class="badge soft-green">Facility Monitoring</span></td>
                            <td><span class="badge soft-yellow">Jump Path Pending</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Needs Confirmation</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge yellow">Partial Lineage</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access</span></td>
                            <td><span class="badge soft-green">Infrastructure Control</span></td>
                            <td><span class="badge soft-green">Lab / Server Access</span></td>
                            <td><span class="badge soft-green">Defined</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-yellow">Procedure Link Needed</span></td>
                            <td><span class="badge yellow">Partial Lineage</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-green">Production Use</span></td>
                            <td><span class="badge soft-green">Operational Review</span></td>
                            <td><span class="badge soft-yellow">Local Dependency</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge yellow">Partial Lineage</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-yellow">Closure Impact</span></td>
                            <td><span class="badge soft-red">Unknown</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Closure Needed</span></td>
                            <td><span class="badge red">Blocked Lineage</span></td>
                        </tr>

                        <tr>
                            <td><strong>Chromeleon Workstation</strong><br><span style="color: var(--muted);">Lab workstation dependency</span></td>
                            <td><span class="badge soft-green">Lab Process</span></td>
                            <td><span class="badge soft-green">Data Review</span></td>
                            <td><span class="badge soft-yellow">Workstation Link</span></td>
                            <td><span class="badge soft-yellow">Role Check</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge yellow">Partial Lineage</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Unknown</span></td>
                            <td><span class="badge soft-yellow">Backup Review</span></td>
                            <td><span class="badge soft-red">Unknown</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge red">Blocked Lineage</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Lab Process</span></td>
                            <td><span class="badge soft-green">Data / Review</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge yellow">Partial Lineage</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Hidden Dependency Detection</h2>
                <p>
                    CITrust™ flags dependencies that may not appear clearly in ServiceNow-style records but still affect operational trust.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Access Path Dependency</h3>
                        <p>Detects when a CI depends on a jump server, local admin path, vendor access route, or remote workstation path that must be governed.</p>
                    </div>

                    <div class="card">
                        <h3>Review Activity Dependency</h3>
                        <p>Identifies workstations or records used for backup reviews, audit trail reviews, user administration, or recurring operational checks.</p>
                    </div>

                    <div class="card">
                        <h3>Support Routing Dependency</h3>
                        <p>Checks whether incidents and service requests can route to the correct support group instead of relying on manual escalation.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Dependency</h3>
                        <p>Links CI lineage to SOPs, validation references, closure evidence, backup review evidence, and access review artifacts.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Dependency Decision Logic</h2>
                <p>
                    A CI is not operationally trusted until its dependency chain is explainable.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Complete Dependency Lineage</h3>
                        <ul>
                            <li>Upstream business, GMP, or operational use is known.</li>
                            <li>Downstream impact is understood.</li>
                            <li>Infrastructure path is documented or explainable.</li>
                            <li>Access dependency is mapped through MyAccess or governed process.</li>
                            <li>Support group and escalation path are defined.</li>
                            <li>Evidence dependency is linked to reviewable artifacts.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Blocked Dependency Lineage</h3>
                        <ul>
                            <li>CI appears in one source but dependencies are unknown.</li>
                            <li>Support, access, or infrastructure dependency is hidden.</li>
                            <li>Operational review depends on an undocumented workstation or local process.</li>
                            <li>OOS or retired records have unclear downstream impact.</li>
                            <li>Evidence dependency is missing or disconnected.</li>
                            <li>Impact analysis would fail during incident, audit, or change review.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Dependency Remediation Queue</h2>
                <p>
                    These dependency gaps should be resolved before leadership treats the related CIs as operationally trusted.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Record</th>
                            <th>Dependency Gap</th>
                            <th>Required Action</th>
                            <th>Target State</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Local Backup Review Workstation</td>
                            <td>Hidden dependency used for recurring backup review but missing owner, access, support, and evidence lineage.</td>
                            <td>Create governed CI candidate and map review activity, owner, support group, and evidence location.</td>
                            <td>Known operational dependency with governed lineage.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Speedy Glove 1802</td>
                            <td>OOS dependency chain and closure impact are not fully explainable.</td>
                            <td>Confirm lifecycle closure, access deactivation, support responsibility, and downstream impact.</td>
                            <td>Closed dependency with defensible lifecycle evidence.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Niagara BMS Server</td>
                            <td>Jump path, support routing, and access evidence remain partial.</td>
                            <td>Finalize access path, support group, role mapping, and cutover evidence reference.</td>
                            <td>Complete infrastructure and access dependency lineage.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Chromeleon Workstation</td>
                            <td>Workstation dependency and role mapping should be tied to evidence and access route.</td>
                            <td>Confirm workstation reference, MyAccess role, and support group mapping.</td>
                            <td>Audit-defensible lab dependency chain.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, create ServiceNow relationships, or write directly into ServiceNow in this demo. This dependency lineage console is a governance assurance overlay for CI relationship trust, hidden dependency detection, access path validation, support routing, evidence linkage, CMDB-readiness, operational readiness, audit defensibility, and pre-deviation readiness.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_DEPENDENCY_LINEAGE_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Dependency Lineage Console installed.")
