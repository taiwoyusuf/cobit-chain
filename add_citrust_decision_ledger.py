from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_DECISION_LEDGER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/decision-ledger")'
ROUTE_ALIAS = '@app.route("/citrust/governance-decision-log")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Governance Decision Ledger already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_DECISION_LEDGER_V1_ACTIVE
# ============================================================

@app.route("/citrust/decision-ledger")
@app.route("/citrust/governance-decision-log")
def citrust_decision_ledger():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Governance Decision Ledger</title>
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
                    radial-gradient(circle at bottom right, rgba(49,208,125,0.08), transparent 30%),
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
                border: 1px solid rgba(180,156,255,0.38);
                background: rgba(180,156,255,0.10);
                color: #eee7ff;
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
                <h1>CITrust™ Governance Decision Ledger</h1>

                <div class="subtitle">
                    Creates an explainable governance decision log for Configuration Items showing who decided the CI is trusted, conditional, blocked, exception-approved, attestation-ready, or ServiceNow-ready, and what evidence supports that decision.
                </div>

                <div class="positioning">
                    <strong>Decision boundary:</strong>
                    CITrust™ records governance reasoning and readiness decisions in this demo. It does not create ServiceNow CIs, does not approve ServiceNow changes, does not update CMDB records, and does not replace human governance. The decision ledger exists to make CI trust decisions defendable.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/executive-reasoning-panel">Executive Reasoning</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                    <a href="/citrust/exception-register">Exception Register</a>
                    <a href="/citrust/readiness-attestation">Attestation Center</a>
                    <a href="/citrust/submission-board">Submission Board</a>
                    <a href="/ci-candidate-review">Candidate Review</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Logged Decisions</div>
                    <div class="value">42</div>
                    <div class="note">Governance decisions recorded across trusted, conditional, blocked, and exception states.</div>
                </div>

                <div class="metric">
                    <div class="label">Trusted Decisions</div>
                    <div class="value" style="color: var(--green);">18</div>
                    <div class="note">Records with enough evidence-backed reasoning for operational trust.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Decisions</div>
                    <div class="value" style="color: var(--yellow);">15</div>
                    <div class="note">Records allowed only with remediation, exception, or watchlist control.</div>
                </div>

                <div class="metric">
                    <div class="label">Blocked Decisions</div>
                    <div class="value" style="color: var(--red);">9</div>
                    <div class="note">Records that should not be treated as trusted or submission-ready.</div>
                </div>

                <div class="metric">
                    <div class="label">Exception Decisions</div>
                    <div class="value" style="color: var(--orange);">6</div>
                    <div class="note">Conditional risks documented under governance exception logic.</div>
                </div>

                <div class="metric">
                    <div class="label">Submission Decisions</div>
                    <div class="value" style="color: var(--blue);">5</div>
                    <div class="note">Records ready for ServiceNow-style submission-pack preparation.</div>
                </div>
            </section>

            <section class="section">
                <h2>Decision Ledger Answer</h2>
                <p>
                    This ledger answers who made the CI governance decision, why the decision was made, and what evidence supports it.
                </p>

                <div class="answer">
                    <strong>Current decision interpretation:</strong>
                    CITrust™ decisions should not be based on informal confidence, spreadsheet presence, or incomplete CMDB fields. Each decision must identify the decision type, decision owner, evidence basis, unresolved condition, readiness impact, and next action. This creates an audit-defensible path from CI candidate to trusted record.
                </div>
            </section>

            <section class="section">
                <h2>Governance Decision Ledger</h2>
                <p>
                    This ledger records readiness decisions in a format leadership, CMDB teams, MyAccess teams, and audit reviewers can understand.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>CI / Record</th>
                            <th>Decision Type</th>
                            <th>Decision Owner</th>
                            <th>Decision Rationale</th>
                            <th>Evidence Basis</th>
                            <th>Open Condition</th>
                            <th>Readiness Impact</th>
                            <th>Next Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge green">Trusted</span></td>
                            <td>Application Governance / CMDB Governance</td>
                            <td>Owner, support group, access, lifecycle, and evidence are sufficiently aligned.</td>
                            <td>Application inventory, owner confirmation, support mapping, evidence reference.</td>
                            <td>No material open condition.</td>
                            <td>Operationally trusted and passport-ready.</td>
                            <td>Maintain periodic governance review.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Infrastructure / Access Governance</td>
                            <td>Access path is known, but formal admin-access procedure evidence should be linked.</td>
                            <td>Infrastructure access model, support context, vendor/admin route understanding.</td>
                            <td>Procedure evidence not fully linked.</td>
                            <td>Conditional audit and access readiness.</td>
                            <td>Attach admin or vendor access procedure evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">Cutover-sensitive BMS dependency</span></td>
                            <td><span class="badge yellow">Conditional Watchlist</span></td>
                            <td>Infrastructure / MyAccess Governance</td>
                            <td>Owner and lifecycle context exist, but support routing, MyAccess role, jump path, and cutover evidence remain partial.</td>
                            <td>Candidate intake, cutover discussion, infrastructure dependency context.</td>
                            <td>Support group, access role, jump path, and cutover evidence pending.</td>
                            <td>Not fully trusted until cutover controls are complete.</td>
                            <td>Finalize support, access, jump path, and evidence package.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Operational Owner / CMDB Governance</td>
                            <td>Operational state is known, but support group, evidence path, and data quality need reconciliation.</td>
                            <td>Operational context, candidate intake, equipment record.</td>
                            <td>Support group and evidence path need confirmation.</td>
                            <td>Hold from full ServiceNow-readiness.</td>
                            <td>Reconcile owner, support group, LCM, and evidence path.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge red">Blocked</span></td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td>OOS closure, access deactivation, ownership, and lifecycle evidence are not defensible.</td>
                            <td>Legacy equipment context and OOS closure requirement.</td>
                            <td>Closure evidence and access removal proof missing.</td>
                            <td>Do not attest, submit, or treat as trusted.</td>
                            <td>Attach closure evidence and confirm access deactivation.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge red">Blocked</span></td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td>Hidden operational dependency lacks owner, support group, LCM, access route, classification, and evidence lineage.</td>
                            <td>Operational discovery only; no governed candidate record yet.</td>
                            <td>Identity, ownership, support, access, evidence, and dependency all missing.</td>
                            <td>High-priority governance blind spot.</td>
                            <td>Create governed candidate and assign accountability model.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge yellow">Conditional Access-Ready</span></td>
                            <td>Application Governance / MyAccess Governance</td>
                            <td>Core CI context is strong, but approver group and role mapping evidence should be confirmed.</td>
                            <td>Application inventory, owner/support context, access governance path.</td>
                            <td>Approver group confirmation needed.</td>
                            <td>Near trusted; not fully access-attested yet.</td>
                            <td>Confirm MyAccess approver group and role evidence.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Decision Categories</h2>
                <p>
                    CITrust™ standardizes decision categories so teams do not use vague readiness language.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Trusted Decision</h3>
                        <p>CI has enough ownership, support, access, evidence, lifecycle, data, and dependency control for operational reliance.</p>
                    </div>

                    <div class="card">
                        <h3>Conditional Decision</h3>
                        <p>CI can remain visible under controlled review, but remediation or confirmation is required before full trust.</p>
                    </div>

                    <div class="card">
                        <h3>Blocked Decision</h3>
                        <p>CI should not be treated as trusted, attested, or submission-ready because critical controls are missing.</p>
                    </div>

                    <div class="card">
                        <h3>Exception Decision</h3>
                        <p>CI risk is temporarily accepted only with named owner, risk statement, closure condition, and leadership visibility.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Decision Control Logic</h2>
                <p>
                    A CITrust™ decision is defensible only when it connects reason, evidence, owner, and readiness impact.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Decision Can Be Defended</h3>
                        <ul>
                            <li>Decision owner is clear.</li>
                            <li>Decision type is specific: trusted, conditional, blocked, exception, attestation, or submission-ready.</li>
                            <li>Evidence basis is stated.</li>
                            <li>Open condition is documented or marked not applicable.</li>
                            <li>Readiness impact is clear.</li>
                            <li>Next action or periodic review requirement is defined.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Decision Must Be Held</h3>
                        <ul>
                            <li>No accountable decision owner exists.</li>
                            <li>Evidence basis is unclear or missing.</li>
                            <li>Owner, support, LCM, access, or lifecycle state is unresolved.</li>
                            <li>Field conflict remains open.</li>
                            <li>Exception would hide a blocked CI.</li>
                            <li>Submission would create weak, duplicate, or orphaned CMDB data.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Decision Remediation Queue</h2>
                <p>
                    These actions convert weak or blocked decisions into defensible governance outcomes.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Decision Gap</th>
                            <th>Why It Matters</th>
                            <th>Required Action</th>
                            <th>Expected Decision Upgrade</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation lacks a defensible decision record.</td>
                            <td>No decision can be defended without identity, owner, support, access, evidence, and dependency mapping.</td>
                            <td>Create governed candidate and populate mandatory governance fields.</td>
                            <td>Blocked → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment decision lacks closure evidence.</td>
                            <td>Blocked status cannot be closed without lifecycle and access deactivation proof.</td>
                            <td>Attach closure evidence and confirm access removal.</td>
                            <td>Blocked → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover decision remains conditional.</td>
                            <td>Support, access, jump path, and cutover evidence are required for full trust.</td>
                            <td>Finalize support routing, MyAccess role, jump path, and cutover evidence.</td>
                            <td>Conditional → Trusted</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Lab application access decision is not fully attested.</td>
                            <td>Approver group and role evidence must support access-readiness.</td>
                            <td>Confirm MyAccess approver group and role evidence.</td>
                            <td>Conditional → Access-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, approve changes, approve access, or update CMDB records in this demo. This governance decision ledger is an assurance overlay for recording CI trust decisions, conditional decisions, blocked decisions, exception decisions, attestation decisions, submission-readiness decisions, evidence basis, decision owner, open condition, readiness impact, executive reasoning, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_DECISION_LEDGER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Governance Decision Ledger installed.")
