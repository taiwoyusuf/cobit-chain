from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_ROLLBACK_READINESS_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/rollback-readiness")'
ROUTE_ALIAS = '@app.route("/citrust/ci-rollback-readiness")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Rollback Readiness Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_ROLLBACK_READINESS_V1_ACTIVE
# ============================================================

@app.route("/citrust/rollback-readiness")
@app.route("/citrust/ci-rollback-readiness")
def citrust_rollback_readiness():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Rollback Readiness Console</title>
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
                    radial-gradient(circle at top right, rgba(255,184,107,0.14), transparent 28%),
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
                border: 1px solid rgba(255,184,107,0.38);
                background: rgba(255,184,107,0.10);
                color: #ffe8c9;
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
                <h1>CITrust™ Rollback Readiness Console</h1>

                <div class="subtitle">
                    Validates whether a Configuration Item has a defensible rollback path before cutover, migration, ownership correction, support reassignment, access change, lifecycle update, vendor handoff, or ServiceNow-style submission remediation.
                </div>

                <div class="positioning">
                    <strong>Rollback boundary:</strong>
                    CITrust™ does not approve changes, execute rollback, create ServiceNow change records, update CMDB records, or replace change control. It validates whether rollback ownership, evidence, dependencies, access reversal, support routing, and post-rollback verification are clear enough to prevent operational failure.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/change-impact-readiness">Change Impact</a>
                    <a href="/citrust/pre-deviation-readiness">Pre-Deviation</a>
                    <a href="/citrust/dependency-lineage">Dependency Lineage</a>
                    <a href="/citrust/evidence-pack-builder">Evidence Pack</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Rollback-Relevant CIs</div>
                    <div class="value">26</div>
                    <div class="note">Records affected by cutover, migration, support reassignment, access changes, or lifecycle correction.</div>
                </div>

                <div class="metric">
                    <div class="label">Rollback-Ready</div>
                    <div class="value" style="color: var(--green);">9</div>
                    <div class="note">Rollback owner, evidence, dependency path, and verification controls are defensible.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Rollback</div>
                    <div class="value" style="color: var(--yellow);">11</div>
                    <div class="note">Rollback path exists but ownership, evidence, or verification is incomplete.</div>
                </div>

                <div class="metric">
                    <div class="label">Rollback Blocked</div>
                    <div class="value" style="color: var(--red);">6</div>
                    <div class="note">Rollback would be unreliable because critical controls are missing.</div>
                </div>

                <div class="metric">
                    <div class="label">Access Reversal Gaps</div>
                    <div class="value" style="color: var(--orange);">7</div>
                    <div class="note">Access removal, role reversal, admin path rollback, or vendor access closure is unclear.</div>
                </div>

                <div class="metric">
                    <div class="label">Post-Check Gaps</div>
                    <div class="value" style="color: var(--blue);">8</div>
                    <div class="note">Post-rollback verification evidence is incomplete or not assigned.</div>
                </div>
            </section>

            <section class="section">
                <h2>Rollback Readiness Answer</h2>
                <p>
                    This console answers whether the team can reverse a CI change safely and prove that rollback was controlled.
                </p>

                <div class="answer">
                    <strong>Current rollback interpretation:</strong>
                    CITrust™ should not allow a cutover-sensitive or access-sensitive CI to be treated as fully ready unless rollback ownership, dependency impact, support routing, access reversal, evidence restoration, vendor handoff reversal, and post-rollback verification are defined. A weak rollback path is a pre-deviation signal because teams may not be able to restore the prior trusted state.
                </div>
            </section>

            <section class="section">
                <h2>Rollback Control Domains</h2>
                <p>
                    CITrust™ separates rollback readiness into the controls needed to recover from a failed CI governance or operational change.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Rollback Owner</h3>
                        <p>Confirms who is accountable for deciding, executing, verifying, and documenting rollback for the CI.</p>
                    </div>

                    <div class="card">
                        <h3>Dependency Reversal</h3>
                        <p>Identifies what upstream, downstream, access, vendor, support, and lifecycle relationships must be restored.</p>
                    </div>

                    <div class="card">
                        <h3>Access Reversal</h3>
                        <p>Validates whether MyAccess roles, admin access, vendor access, and privileged access can be reversed or closed.</p>
                    </div>

                    <div class="card">
                        <h3>Post-Rollback Evidence</h3>
                        <p>Defines verification evidence proving the CI returned to a trusted, supported, evidence-backed state.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Rollback Readiness Matrix</h2>
                <p>
                    This matrix shows whether each CI has a defensible rollback model.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Rollback Scenario</th>
                            <th>Rollback Owner</th>
                            <th>Dependency Reversal</th>
                            <th>Access Reversal</th>
                            <th>Post-Check Evidence</th>
                            <th>Rollback Decision</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>Routine support or record correction.</td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge green">Rollback-Ready</span></td>
                            <td>Maintain periodic rollback and evidence review.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td>Cutover failure, server issue, vendor access issue, jump path failure.</td>
                            <td><span class="badge soft-yellow">Cutover Owner</span></td>
                            <td><span class="badge soft-yellow">Jump / Vendor Partial</span></td>
                            <td><span class="badge soft-yellow">MyAccess Partial</span></td>
                            <td><span class="badge soft-yellow">Rollback Evidence Needed</span></td>
                            <td><span class="badge yellow">Conditional Rollback</span></td>
                            <td>Define rollback owner, support path, jump path reversal, vendor rollback, access reversal, and post-check evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Admin route rollback, vendor access closure, privileged access correction.</td>
                            <td><span class="badge soft-green">Infrastructure</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-yellow">Procedure Needed</span></td>
                            <td><span class="badge soft-yellow">Access Review Needed</span></td>
                            <td><span class="badge yellow">Conditional Rollback</span></td>
                            <td>Attach admin/vendor rollback procedure and access closure evidence path.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Support reassignment, access correction, lifecycle field correction.</td>
                            <td><span class="badge soft-yellow">Likely Owner</span></td>
                            <td><span class="badge soft-yellow">Local Dependency</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Evidence Partial</span></td>
                            <td><span class="badge yellow">Conditional Rollback</span></td>
                            <td>Reconcile rollback owner, support group, access model, dependency path, and verification evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>Access role correction or support model rollback.</td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge yellow">Near Rollback-Ready</span></td>
                            <td>Confirm MyAccess approver group and access rollback evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>OOS closure correction, access deactivation correction, lifecycle rollback.</td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Unknown</span></td>
                            <td><span class="badge soft-red">Removal Not Confirmed</span></td>
                            <td><span class="badge soft-red">Closure Missing</span></td>
                            <td><span class="badge red">Rollback Blocked</span></td>
                            <td>Assign closure owner, attach closure evidence, confirm access removal, and document lifecycle reversal path.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>Backup review workstation change, access rollback, support routing rollback.</td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Hidden</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge red">No Rollback Model</span></td>
                            <td>Create governed candidate and define rollback owner, dependency model, access reversal, evidence, and post-checks.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Rollback Decision Logic</h2>
                <p>
                    Rollback readiness must prove that the prior trusted state can be restored.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Rollback-Ready CI</h3>
                        <ul>
                            <li>Rollback owner is assigned.</li>
                            <li>Support group and escalation path are defined.</li>
                            <li>Dependencies and relationship reversal are known.</li>
                            <li>MyAccess, admin, vendor, or jump path reversal is mapped.</li>
                            <li>Evidence restoration and post-rollback verification are defined.</li>
                            <li>Decision ledger can explain rollback readiness.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Rollback-Blocked CI</h3>
                        <ul>
                            <li>No rollback owner exists.</li>
                            <li>Dependency path is hidden or undocumented.</li>
                            <li>Access reversal or access removal cannot be defended.</li>
                            <li>Support group or LCM is unclear.</li>
                            <li>OOS or retired state lacks closure evidence.</li>
                            <li>Post-rollback verification evidence is missing.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Rollback Remediation Queue</h2>
                <p>
                    These actions close rollback gaps before cutover, access changes, lifecycle updates, or support reassignment.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Rollback Gap</th>
                            <th>Why It Matters</th>
                            <th>Required Action</th>
                            <th>Expected Readiness Upgrade</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no rollback model.</td>
                            <td>Changing or losing this dependency could break recurring backup review without recovery path.</td>
                            <td>Create governed candidate and define rollback owner, support path, access reversal, evidence path, and post-checks.</td>
                            <td>No Rollback Model → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment closure rollback is not defensible.</td>
                            <td>Lifecycle and access reversal cannot be proven without closure and access-removal evidence.</td>
                            <td>Attach closure evidence, confirm access removal, and document lifecycle correction path.</td>
                            <td>Rollback Blocked → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover rollback is partial.</td>
                            <td>Cutover failure requires rapid restoration of support, access, vendor route, and operational evidence.</td>
                            <td>Define rollback owner, jump path reversal, MyAccess rollback, vendor handoff reversal, and post-cutover checks.</td>
                            <td>Conditional Rollback → Rollback-Ready</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Admin/vendor access rollback procedure is incomplete.</td>
                            <td>Privileged access rollback must be evidence-backed and audit-defensible.</td>
                            <td>Attach admin/vendor rollback procedure, access closure evidence, and review owner.</td>
                            <td>Conditional Rollback → Audit-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow change management, rollback execution, MyAccess approval, access removal, CMDB updates, vendor management, audit systems, or human governance. This rollback readiness console is a governance assurance overlay for rollback owner validation, dependency reversal, access rollback, support rollback, vendor handoff rollback, lifecycle rollback, evidence restoration, post-rollback verification, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_ROLLBACK_READINESS_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Rollback Readiness Console installed.")
