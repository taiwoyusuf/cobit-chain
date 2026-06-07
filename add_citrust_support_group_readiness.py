from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_SUPPORT_GROUP_READINESS_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/support-group-readiness")'
ROUTE_ALIAS = '@app.route("/citrust/support-routing")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Support Group Readiness Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_SUPPORT_GROUP_READINESS_V1_ACTIVE
# ============================================================

@app.route("/citrust/support-group-readiness")
@app.route("/citrust/support-routing")
def citrust_support_group_readiness():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Support Group Readiness Console</title>
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
                    radial-gradient(circle at top right, rgba(49,208,125,0.14), transparent 28%),
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
                border: 1px solid rgba(49,208,125,0.36);
                background: rgba(49,208,125,0.10);
                color: #dfffea;
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
                <h1>CITrust™ Support Group Readiness Console</h1>

                <div class="subtitle">
                    Validates whether each Configuration Item has a routable support group, resolver path, escalation queue, vendor handoff, incident route, request route, change support contact, backup support coverage, and evidence-backed operational support model.
                </div>

                <div class="positioning">
                    <strong>Support boundary:</strong>
                    ServiceNow stores support and assignment group fields. CITrust™ validates whether those support fields are operationally trustworthy, current, evidence-backed, and usable for real incident, request, access, lifecycle, and audit scenarios. This demo does not write directly to ServiceNow.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/ownership-readiness">Ownership Readiness</a>
                    <a href="/citrust/escalation-path-console">Escalation Path</a>
                    <a href="/citrust/lcm-assignment-console">LCM Assignment</a>
                    <a href="/citrust/relationship-readiness">Relationship Readiness</a>
                    <a href="/citrust/mandatory-fields-checklist">Mandatory Fields</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Support-Relevant CIs</div>
                    <div class="value">42</div>
                    <div class="note">Records requiring support routing before operational trust.</div>
                </div>

                <div class="metric">
                    <div class="label">Support-Ready</div>
                    <div class="value" style="color: var(--green);">19</div>
                    <div class="note">CIs with routable support group and escalation path.</div>
                </div>

                <div class="metric">
                    <div class="label">Support Conditional</div>
                    <div class="value" style="color: var(--yellow);">15</div>
                    <div class="note">Support group exists but needs confirmation, evidence, or backup coverage.</div>
                </div>

                <div class="metric">
                    <div class="label">Support Missing</div>
                    <div class="value" style="color: var(--red);">8</div>
                    <div class="note">Records blocked from operational trust due to support-routing gaps.</div>
                </div>

                <div class="metric">
                    <div class="label">Vendor Handoff Gaps</div>
                    <div class="value" style="color: var(--orange);">6</div>
                    <div class="note">CIs where vendor support, jump path, or admin handoff is not defensible.</div>
                </div>

                <div class="metric">
                    <div class="label">Escalation Ready</div>
                    <div class="value" style="color: var(--blue);">16</div>
                    <div class="note">Records ready for support escalation and incident routing defense.</div>
                </div>
            </section>

            <section class="section">
                <h2>Support Readiness Answer</h2>
                <p>
                    This console answers whether operational issues can route to the correct accountable support path.
                </p>

                <div class="answer">
                    <strong>Current support interpretation:</strong>
                    CITrust™ should not treat a CI as operationally trusted unless the support group is routable, confirmed, aligned with the CI owner and LCM, and supported by escalation evidence. A CI with unclear support routing creates incident delay, access confusion, lifecycle ambiguity, audit weakness, and ServiceNow-readiness risk.
                </div>
            </section>

            <section class="section">
                <h2>Support Readiness Domains</h2>
                <p>
                    CITrust™ separates support readiness into controls that determine whether the CI can actually be supported in production.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Assignment Group</h3>
                        <p>Validates whether the CI has a routable group that can receive incidents, requests, and support tasks.</p>
                    </div>

                    <div class="card">
                        <h3>Resolver Path</h3>
                        <p>Confirms who resolves issues after routing, including infrastructure, application, vendor, or site support.</p>
                    </div>

                    <div class="card">
                        <h3>Escalation Chain</h3>
                        <p>Maps support escalation from technician or service desk to LCM, CI owner, governance reviewer, or leadership.</p>
                    </div>

                    <div class="card">
                        <h3>Support Evidence</h3>
                        <p>Links support readiness to confirmation evidence, SOP, escalation model, vendor agreement, or operational handoff proof.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Support Group Readiness Matrix</h2>
                <p>
                    This matrix shows whether each CI has defensible support routing.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Support Group</th>
                            <th>Resolver Path</th>
                            <th>Vendor / Admin Handoff</th>
                            <th>Escalation Path</th>
                            <th>Evidence Basis</th>
                            <th>Support Decision</th>
                            <th>Next Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Defined</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-green">Defined</span></td>
                            <td>Support group, owner, lifecycle, and evidence references are available.</td>
                            <td><span class="badge green">Support-Ready</span></td>
                            <td>Maintain periodic support review.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">Cutover-sensitive BMS dependency</span></td>
                            <td><span class="badge soft-yellow">Needs Confirmation</span></td>
                            <td><span class="badge soft-yellow">Infrastructure / Vendor</span></td>
                            <td><span class="badge soft-yellow">Jump Path Partial</span></td>
                            <td><span class="badge soft-yellow">Cutover Watchlist</span></td>
                            <td>Cutover context exists, but support routing and jump path evidence remain partial.</td>
                            <td><span class="badge yellow">Conditional Support</span></td>
                            <td>Confirm support group, vendor handoff, jump path, and cutover escalation.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Infrastructure</span></td>
                            <td><span class="badge soft-yellow">Procedure Needed</span></td>
                            <td><span class="badge soft-yellow">Backup Recommended</span></td>
                            <td>Access route is known, but formal admin or vendor procedure evidence should be linked.</td>
                            <td><span class="badge yellow">Conditional Support</span></td>
                            <td>Attach admin/vendor access procedure and confirm backup support owner.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-yellow">Operational / Site Support</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td>Operational state is known, but support group and evidence path need reconciliation.</td>
                            <td><span class="badge yellow">Conditional Support</span></td>
                            <td>Reconcile support group, LCM, vendor path, and evidence location.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Defined</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-yellow">Access Escalation Check</span></td>
                            <td>Core support model is strong; MyAccess escalation evidence needs confirmation.</td>
                            <td><span class="badge yellow">Near Support-Ready</span></td>
                            <td>Confirm access escalation evidence and approver group.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Not Defensible</span></td>
                            <td><span class="badge soft-red">Closure Escalation Missing</span></td>
                            <td>Closure and access deactivation evidence are missing.</td>
                            <td><span class="badge red">Support Blocked</span></td>
                            <td>Assign closure support path, attach closure evidence, and confirm access removal.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td>No governed candidate, owner, support evidence, or escalation model exists.</td>
                            <td><span class="badge red">No Support Model</span></td>
                            <td>Create governed candidate and assign full support model.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Support Readiness Decision Logic</h2>
                <p>
                    Support group readiness must prove that the CI can be supported when an issue occurs.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Support-Ready CI</h3>
                        <ul>
                            <li>Support group is routable and current.</li>
                            <li>Resolver path is defined.</li>
                            <li>Escalation chain is mapped.</li>
                            <li>Vendor or admin handoff is documented where applicable.</li>
                            <li>Support model aligns with owner, LCM, MyAccess, and lifecycle state.</li>
                            <li>Support evidence is available for audit or review.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Support-Blocked CI</h3>
                        <ul>
                            <li>No support group exists.</li>
                            <li>Support group is stale, disputed, or not routable.</li>
                            <li>Resolver path is unclear.</li>
                            <li>Vendor or admin handoff is informal.</li>
                            <li>OOS closure support path is missing.</li>
                            <li>Hidden dependency has no support accountability.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Support Remediation Queue</h2>
                <p>
                    These actions close support-routing gaps before operational trust or ServiceNow-style readiness is granted.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Support Gap</th>
                            <th>Why It Matters</th>
                            <th>Required Action</th>
                            <th>Expected Readiness Upgrade</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no support model.</td>
                            <td>Recurring operational dependency cannot be supported or escalated defensibly.</td>
                            <td>Create governed candidate and assign support group, resolver path, LCM, access owner, and evidence location.</td>
                            <td>No Support Model → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment lacks closure support path.</td>
                            <td>Closure, access removal, and lifecycle cleanup need accountable support routing.</td>
                            <td>Assign closure support owner, confirm access removal owner, and attach closure evidence.</td>
                            <td>Support Blocked → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover support routing is partial.</td>
                            <td>Cutover systems need support group, vendor path, jump path, and escalation model before trust.</td>
                            <td>Confirm support group, vendor handoff, jump path owner, and cutover escalation chain.</td>
                            <td>Conditional Support → Support-Ready</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Admin/vendor support procedure evidence is incomplete.</td>
                            <td>Support handoff cannot be defended if procedure evidence is missing.</td>
                            <td>Attach admin/vendor access procedure and define backup support owner.</td>
                            <td>Conditional Support → Audit-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, update CMDB support-group fields, assign support groups, or create support tickets in this demo. This support group readiness console is a governance assurance overlay for support group validation, resolver path validation, assignment group defensibility, vendor handoff, admin support routing, incident routing, request routing, escalation readiness, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_SUPPORT_GROUP_READINESS_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Support Group Readiness Console installed.")
