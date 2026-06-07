from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CHANGE_IMPACT_READINESS_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/change-impact-readiness")'
ROUTE_ALIAS = '@app.route("/citrust/ci-change-impact")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Change Impact Readiness Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CHANGE_IMPACT_READINESS_V1_ACTIVE
# ============================================================

@app.route("/citrust/change-impact-readiness")
@app.route("/citrust/ci-change-impact")
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
                    radial-gradient(circle at top right, rgba(247,201,72,0.14), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(255,92,112,0.08), transparent 30%),
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
                min-height: 145px;
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
                <h1>CITrust™ Change Impact Readiness Console</h1>

                <div class="subtitle">
                    Validates whether each Configuration Item has enough ownership, support, dependency, lifecycle, access, evidence, vendor, and relationship context to support defensible change impact analysis before migration, cutover, reassignment, retirement, access change, or ServiceNow-style submission.
                </div>

                <div class="positioning">
                    <strong>Change impact boundary:</strong>
                    CITrust™ does not approve changes, create ServiceNow change records, update CMDB relationships, or replace change control. It validates whether CI data is strong enough for change stakeholders to understand what will be affected, who must approve, what evidence is needed, and what risks must be remediated.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/dependency-lineage">Dependency Lineage</a>
                    <a href="/citrust/relationship-readiness">Relationship Readiness</a>
                    <a href="/citrust/vendor-handoff-readiness">Vendor Handoff</a>
                    <a href="/citrust/support-group-readiness">Support Routing</a>
                    <a href="/citrust/evidence-pack-builder">Evidence Pack</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Change-Relevant CIs</div>
                    <div class="value">42</div>
                    <div class="note">Records that may be affected by migration, cutover, support, access, lifecycle, or relationship changes.</div>
                </div>

                <div class="metric">
                    <div class="label">Impact-Ready</div>
                    <div class="value" style="color: var(--green);">15</div>
                    <div class="note">CIs with defensible owner, support, relationship, access, and evidence context.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Impact</div>
                    <div class="value" style="color: var(--yellow);">18</div>
                    <div class="note">CIs with known impact path but partial evidence or unresolved dependencies.</div>
                </div>

                <div class="metric">
                    <div class="label">Blocked Impact</div>
                    <div class="value" style="color: var(--red);">9</div>
                    <div class="note">CIs where impact analysis would be unreliable or incomplete.</div>
                </div>

                <div class="metric">
                    <div class="label">Hidden Dependencies</div>
                    <div class="value" style="color: var(--orange);">7</div>
                    <div class="note">Dependencies that may affect change scope but are not fully governed.</div>
                </div>

                <div class="metric">
                    <div class="label">Cutover-Sensitive</div>
                    <div class="value" style="color: var(--blue);">6</div>
                    <div class="note">Records requiring stronger change impact review before transition.</div>
                </div>
            </section>

            <section class="section">
                <h2>Change Impact Answer</h2>
                <p>
                    This console answers whether CI data is strong enough to support a defensible change-impact decision.
                </p>

                <div class="answer">
                    <strong>Current change-impact interpretation:</strong>
                    CITrust™ should not allow a CI to be treated as change-ready if dependencies, support group, owner, LCM, access path, vendor handoff, lifecycle state, or evidence path are incomplete. Weak CI data can cause change scope errors, missed approvers, failed cutover, unresolved access impacts, and post-change support gaps.
                </div>
            </section>

            <section class="section">
                <h2>Change Impact Control Domains</h2>
                <p>
                    CITrust™ separates change impact into the domains required for reliable change reasoning.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Dependency Impact</h3>
                        <p>Identifies upstream, downstream, hosted-on, accessed-through, vendor, and hidden dependencies affected by a change.</p>
                    </div>

                    <div class="card">
                        <h3>Ownership Impact</h3>
                        <p>Confirms which owner, support group, LCM, MyAccess approver, and governance reviewer must be engaged.</p>
                    </div>

                    <div class="card">
                        <h3>Operational Impact</h3>
                        <p>Assesses effect on backup review, audit trail review, SOP linkage, lab/manufacturing operations, and support continuity.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Impact</h3>
                        <p>Defines which evidence must be refreshed after a change, including access, lifecycle, support, validation, and closure proof.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Change Impact Readiness Matrix</h2>
                <p>
                    This matrix shows whether each CI can support change impact analysis.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Change Scenario</th>
                            <th>Dependencies</th>
                            <th>Owner / Support</th>
                            <th>Access Impact</th>
                            <th>Evidence Impact</th>
                            <th>Impact Decision</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>Routine support or record update.</td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Refreshable</span></td>
                            <td><span class="badge green">Impact-Ready</span></td>
                            <td>Maintain periodic relationship and evidence review.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td>Cutover, server migration, support routing, vendor access.</td>
                            <td><span class="badge soft-yellow">Jump Path / Vendor</span></td>
                            <td><span class="badge soft-yellow">Support Pending</span></td>
                            <td><span class="badge soft-yellow">MyAccess Partial</span></td>
                            <td><span class="badge soft-yellow">Cutover Evidence</span></td>
                            <td><span class="badge yellow">Conditional Impact</span></td>
                            <td>Finalize support group, jump path, vendor handoff, role mapping, and cutover evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Access path change, vendor support, privileged admin routing.</td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-yellow">Procedure Needed</span></td>
                            <td><span class="badge soft-yellow">Access Evidence</span></td>
                            <td><span class="badge yellow">Conditional Impact</span></td>
                            <td>Attach admin/vendor procedure and define post-change access evidence capture.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Support reassignment, lifecycle review, vendor or operational update.</td>
                            <td><span class="badge soft-yellow">Local Dependency</span></td>
                            <td><span class="badge soft-yellow">Support Pending</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge yellow">Conditional Impact</span></td>
                            <td>Reconcile support group, LCM, evidence path, and dependency model.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>Access or support model update.</td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge yellow">Near Impact-Ready</span></td>
                            <td>Confirm MyAccess approver group and access impact evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>OOS closure, retirement, access deactivation.</td>
                            <td><span class="badge soft-red">Unknown</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Removal Not Confirmed</span></td>
                            <td><span class="badge soft-red">Closure Missing</span></td>
                            <td><span class="badge red">Impact Blocked</span></td>
                            <td>Attach closure evidence, confirm access removal, assign closure owner, and reconcile dependencies.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>Backup review process, workstation change, access or support update.</td>
                            <td><span class="badge soft-red">Hidden</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge red">No Impact Model</span></td>
                            <td>Create governed candidate and map owner, support, LCM, access, evidence, and dependency impact.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Change Impact Decision Logic</h2>
                <p>
                    Change impact readiness requires relationship evidence, not assumptions.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Impact-Ready CI</h3>
                        <ul>
                            <li>Dependencies and relationships are known.</li>
                            <li>Owner, support group, and LCM are confirmed.</li>
                            <li>MyAccess, admin, vendor, or jump-server access impact is mapped.</li>
                            <li>Operational evidence impact is understood.</li>
                            <li>Post-change evidence refresh is defined.</li>
                            <li>Decision ledger can explain change-readiness status.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Impact-Blocked CI</h3>
                        <ul>
                            <li>Dependency chain is hidden or undocumented.</li>
                            <li>Owner, support group, or LCM is missing.</li>
                            <li>Access impact cannot be defended.</li>
                            <li>OOS or retirement impact lacks closure evidence.</li>
                            <li>Vendor handoff or support route is unclear.</li>
                            <li>Change scope would be based on incomplete CI data.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Change Impact Remediation Queue</h2>
                <p>
                    These actions close change-impact gaps before migration, cutover, reassignment, or lifecycle action.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Impact Gap</th>
                            <th>Why It Matters</th>
                            <th>Required Action</th>
                            <th>Expected Readiness Upgrade</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no impact model.</td>
                            <td>Change could affect recurring backup review without governance visibility.</td>
                            <td>Create governed candidate and map owner, support, LCM, access, evidence, and dependency impact.</td>
                            <td>No Impact Model → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment closure impact is not defensible.</td>
                            <td>Retirement or closure could leave unresolved access, support, or dependency risk.</td>
                            <td>Attach closure evidence, confirm access removal, and reconcile closure dependencies.</td>
                            <td>Impact Blocked → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover impact model is partial.</td>
                            <td>Cutover failure risk increases when support, vendor, jump path, and MyAccess impacts are unresolved.</td>
                            <td>Finalize support, MyAccess role, jump path, vendor handoff, and cutover evidence.</td>
                            <td>Conditional Impact → Impact-Ready</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access-path impact evidence is incomplete.</td>
                            <td>Privileged access changes require evidence-backed impact reasoning.</td>
                            <td>Attach admin/vendor procedure and define access evidence refresh after change.</td>
                            <td>Conditional Impact → Audit-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow change management, change approval, CMDB relationship updates, MyAccess approvals, quality systems, or human governance. This change impact readiness console is a governance assurance overlay for dependency impact, support impact, access impact, lifecycle impact, vendor handoff impact, evidence impact, cutover impact, audit defense, ServiceNow-readiness, and pre-deviation prevention.
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
