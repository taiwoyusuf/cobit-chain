from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_EXECUTIVE_CONTROL_ACTION_TRACKER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/executive-control-action-tracker")'
ROUTE_ALIAS = '@app.route("/citrust/control-action-tracker")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Executive Control Action Tracker already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_EXECUTIVE_CONTROL_ACTION_TRACKER_V1_ACTIVE
# ============================================================

@app.route("/citrust/executive-control-action-tracker")
@app.route("/citrust/control-action-tracker")
def citrust_executive_control_action_tracker():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Executive Control Action Tracker</title>
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
                    radial-gradient(circle at top left, rgba(49,208,125,0.16), transparent 30%),
                    radial-gradient(circle at top right, rgba(92,200,255,0.15), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(180,156,255,0.10), transparent 30%),
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

            .soft-orange {
                color: #ffe8c9;
                background: rgba(255,184,107,0.14);
                border: 1px solid rgba(255,184,107,0.36);
            }

            .soft-purple {
                color: #eee7ff;
                background: rgba(180,156,255,0.13);
                border: 1px solid rgba(180,156,255,0.35);
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
                <h1>CITrust™ Executive Control Action Tracker</h1>

                <div class="subtitle">
                    Converts executive control assurance briefing decisions into owned actions with priority, accountable function, required evidence, closure condition, assurance impact, and readiness outcome.
                </div>

                <div class="positioning">
                    <strong>Action-tracker boundary:</strong>
                    CITrust™ does not update ServiceNow, approve access, close tasks, or replace human governance in this demo. This tracker organizes executive decisions into governed action items so weak controls move from discussion to closure, re-attestation, or redesign.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/executive-control-assurance-briefing">Executive Briefing</a>
                    <a href="/citrust/executive-control-assurance-register">Control Register</a>
                    <a href="/citrust/control-maturity-uplift-roadmap">Maturity Roadmap</a>
                    <a href="/citrust/control-deficiency-remediation-board">Deficiency Remediation</a>
                    <a href="/citrust/control-remediation-closure-attestation">Closure Attestation</a>
                    <a href="/citrust/control-effectiveness-monitor">Control Effectiveness</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Executive Actions</div>
                    <div class="value">12</div>
                    <div class="note">Leadership-level action items required to strengthen control assurance.</div>
                </div>

                <div class="metric">
                    <div class="label">Critical Open</div>
                    <div class="value" style="color: var(--red);">3</div>
                    <div class="note">Actions blocking reliable assurance, certificate readiness, or audit defense.</div>
                </div>

                <div class="metric">
                    <div class="label">In Progress</div>
                    <div class="value" style="color: var(--yellow);">5</div>
                    <div class="note">Actions with owners identified but evidence closure pending.</div>
                </div>

                <div class="metric">
                    <div class="label">Decision Needed</div>
                    <div class="value" style="color: var(--orange);">4</div>
                    <div class="note">Actions requiring leadership agreement on mandatory gates or ownership.</div>
                </div>

                <div class="metric">
                    <div class="label">Closure Ready</div>
                    <div class="value" style="color: var(--green);">2</div>
                    <div class="note">Actions ready for reviewer acceptance and decision-ledger closure.</div>
                </div>

                <div class="metric">
                    <div class="label">Assurance Lift</div>
                    <div class="value" style="color: var(--blue);">+19%</div>
                    <div class="note">Estimated increase in executive confidence if critical actions close.</div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Action Tracker Answer</h2>
                <p>
                    This tracker answers what leadership must act on next to make CITrust™ control assurance defensible.
                </p>

                <div class="answer">
                    <strong>Current action interpretation:</strong>
                    The highest-value executive actions are to make support and LCM evidence mandatory, force hidden-dependency candidate creation, require exception escalation ownership, and block certificate renewal where privileged access evidence is incomplete. These actions convert conditional assurance into evidence-backed governance.
                </div>
            </section>

            <section class="section">
                <h2>Action Governance Domains</h2>
                <p>
                    CITrust™ groups executive actions by the assurance weakness they resolve.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Mandatory Gate Actions</h3>
                        <p>Actions that turn optional or manual control steps into required readiness gates before approval, renewal, or certification.</p>
                    </div>

                    <div class="card">
                        <h3>Ownership Actions</h3>
                        <p>Actions that assign support owner, LCM, escalation owner, reviewer, evidence owner, and closure accountability.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Actions</h3>
                        <p>Actions that require proof bundles for access, support, lifecycle, cutover, exception closure, and control operation.</p>
                    </div>

                    <div class="card">
                        <h3>Reliance Actions</h3>
                        <p>Actions that decide whether leadership can rely, rely conditionally, or must avoid relying on a control.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Control Action Matrix</h2>
                <p>
                    This matrix converts executive briefing decisions into actionable governance work.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Executive Action</th>
                            <th>Control Area</th>
                            <th>Priority</th>
                            <th>Owner / Reviewer Needed</th>
                            <th>Required Evidence</th>
                            <th>Status</th>
                            <th>Expected Assurance Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Approve mandatory support and LCM evidence gate</strong></td>
                            <td>Support and LCM Confirmation</td>
                            <td><span class="badge red">Critical</span></td>
                            <td>CMDB Governance / Service Operations</td>
                            <td>Support group, resolver path, LCM, escalation owner, evidence location, and review cadence.</td>
                            <td><span class="badge red">Decision Needed</span></td>
                            <td>Not Reliable → Operating Control</td>
                        </tr>

                        <tr>
                            <td><strong>Force hidden-dependency candidate creation</strong></td>
                            <td>Hidden Dependency Intake</td>
                            <td><span class="badge red">Critical</span></td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td>Candidate record, owner, support, LCM, access path, evidence model, cadence, verification model.</td>
                            <td><span class="badge orange">Policy Decision Needed</span></td>
                            <td>Partially Reliable → Effective Intake Control</td>
                        </tr>

                        <tr>
                            <td><strong>Require escalation owner for all exceptions</strong></td>
                            <td>Exception Expiry Governance</td>
                            <td><span class="badge orange">High</span></td>
                            <td>Governance Reviewer / Certificate Owner</td>
                            <td>Exception owner, expiry date, escalation owner, closure evidence, residual-risk statement, decision-ledger entry.</td>
                            <td><span class="badge yellow">In Progress</span></td>
                            <td>Weak Exception Control → Effective Control</td>
                        </tr>

                        <tr>
                            <td><strong>Block renewal when access evidence is incomplete</strong></td>
                            <td>Privileged Access Evidence</td>
                            <td><span class="badge orange">High</span></td>
                            <td>Access Governance / Infrastructure</td>
                            <td>MyAccess mapping, approver group, admin/vendor procedure, access review proof, post-access verification.</td>
                            <td><span class="badge yellow">In Progress</span></td>
                            <td>Conditional Access → Reliable Access Assurance</td>
                        </tr>

                        <tr>
                            <td><strong>Require cutover recovery attestation before certificate-ready status</strong></td>
                            <td>Cutover Evidence Assurance</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Cutover Owner / Infrastructure / Access Governance</td>
                            <td>Support evidence, vendor handoff, rollback readiness, jump path, post-cutover verification.</td>
                            <td><span class="badge yellow">Evidence Pending</span></td>
                            <td>Conditional Cutover Trust → Certificate-Ready Defense</td>
                        </tr>

                        <tr>
                            <td><strong>Adopt benchmark evidence model as standard</strong></td>
                            <td>Strong Control Benchmark</td>
                            <td><span class="badge blue">Scale</span></td>
                            <td>Application Governance / CMDB Governance</td>
                            <td>Owner, support, access, lifecycle, evidence, cadence, trust decision, monitoring proof.</td>
                            <td><span class="badge green">Closure Ready</span></td>
                            <td>Executive Ready → Standard Operating Model</td>
                        </tr>

                        <tr>
                            <td><strong>Connect certificate lifecycle outputs to executive trust reporting</strong></td>
                            <td>Certificate Lifecycle Governance</td>
                            <td><span class="badge blue">Executive</span></td>
                            <td>Certificate Owner / Governance Leadership</td>
                            <td>Certificate issuance, renewal, suspension, restoration, exception, and passport linkage summary.</td>
                            <td><span class="badge green">Ready For Review</span></td>
                            <td>Reliable With Monitoring → Executive Reporting</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Action Closure Decision Logic</h2>
                <p>
                    Executive actions should only close when evidence proves the intended assurance outcome was achieved.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Action Can Close</h3>
                        <ul>
                            <li>Action owner is assigned.</li>
                            <li>Required evidence is attached or defined.</li>
                            <li>Control gate, rule, or reviewer decision is active.</li>
                            <li>Closure evidence directly addresses the executive decision.</li>
                            <li>Assurance state improves or limitation is documented.</li>
                            <li>Decision ledger captures the closure rationale.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Action Must Stay Open</h3>
                        <ul>
                            <li>Ownership remains unclear.</li>
                            <li>Evidence is missing, stale, or informal.</li>
                            <li>Decision has not been accepted by leadership.</li>
                            <li>Control remains optional or manual.</li>
                            <li>Assurance state would be overstated.</li>
                            <li>Closure would create false confidence.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Priority Queue</h2>
                <p>
                    These actions should be completed first because they unlock the greatest assurance improvement.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Action</th>
                            <th>Why It Matters</th>
                            <th>Closure Requirement</th>
                            <th>Trust Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Make support and LCM evidence mandatory.</td>
                            <td>ServiceNow-readiness and operational response cannot be defended without support ownership.</td>
                            <td>No candidate approval without support group, resolver path, LCM, escalation owner, and evidence location.</td>
                            <td>Support trust becomes operating and reviewable.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Mandate hidden-dependency candidate creation.</td>
                            <td>Unmanaged dependencies create invisible governance debt and weak certificate assurance.</td>
                            <td>Any backup, audit, access, support, or review dependency must become a CI candidate.</td>
                            <td>Hidden dependency risk becomes governed intake.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Require exception escalation owner.</td>
                            <td>Expired exceptions become audit weaknesses if no one owns closure.</td>
                            <td>No exception approval without owner, expiry, escalation owner, closure evidence, and decision-ledger entry.</td>
                            <td>Exception governance becomes defensible.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Block renewal when access evidence is incomplete.</td>
                            <td>Access assurance cannot be defended without current MyAccess, admin, vendor, and review proof.</td>
                            <td>Renewal requires full access evidence bundle and reviewer acceptance.</td>
                            <td>Access trust becomes reliable instead of conditional.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This executive control action tracker is a governance assurance overlay for executive decisions, action ownership, evidence closure, control reliance, maturity uplift, certificate readiness, CMDB-readiness, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_EXECUTIVE_CONTROL_ACTION_TRACKER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Executive Control Action Tracker installed.")
