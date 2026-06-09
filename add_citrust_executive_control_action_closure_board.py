from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_EXECUTIVE_CONTROL_ACTION_CLOSURE_BOARD_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/executive-control-action-closure-board")'
ROUTE_ALIAS = '@app.route("/citrust/control-action-closure")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Executive Control Action Closure Board already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_EXECUTIVE_CONTROL_ACTION_CLOSURE_BOARD_V1_ACTIVE
# ============================================================

@app.route("/citrust/executive-control-action-closure-board")
@app.route("/citrust/control-action-closure")
def citrust_executive_control_action_closure_board():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Executive Control Action Closure Board</title>
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
                    radial-gradient(circle at top left, rgba(49,208,125,0.17), transparent 30%),
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
                <h1>CITrust™ Executive Control Action Closure Board</h1>

                <div class="subtitle">
                    Closure board for executive CITrust™ control actions, confirming whether leadership decisions have been implemented, evidence has been attached, reviewers have accepted closure, and the control assurance state has improved.
                </div>

                <div class="positioning">
                    <strong>Closure boundary:</strong>
                    CITrust™ does not close ServiceNow tasks, approve access, update CMDB records, or replace human governance in this demo. This board validates whether executive actions can be closed from the assurance layer and whether closure improves certificate readiness, CMDB-readiness, audit defense, and operational trust.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/executive-control-action-tracker">Executive Action Tracker</a>
                    <a href="/citrust/executive-control-assurance-briefing">Executive Briefing</a>
                    <a href="/citrust/executive-control-assurance-register">Control Register</a>
                    <a href="/citrust/control-remediation-closure-attestation">Remediation Closure</a>
                    <a href="/citrust/post-remediation-effectiveness-review">Post-Remediation Review</a>
                    <a href="/citrust/control-assurance-attestation">Control Attestation</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Actions Reviewed</div>
                    <div class="value">12</div>
                    <div class="note">Executive control actions under closure review.</div>
                </div>

                <div class="metric">
                    <div class="label">Closed With Evidence</div>
                    <div class="value" style="color: var(--green);">3</div>
                    <div class="note">Actions with closure proof and reviewer acceptance.</div>
                </div>

                <div class="metric">
                    <div class="label">Close Conditional</div>
                    <div class="value" style="color: var(--yellow);">4</div>
                    <div class="note">Actions that can close with monitoring or residual-risk disclosure.</div>
                </div>

                <div class="metric">
                    <div class="label">Closure Blocked</div>
                    <div class="value" style="color: var(--red);">2</div>
                    <div class="note">Actions missing proof, decision acceptance, or required ownership.</div>
                </div>

                <div class="metric">
                    <div class="label">Reviewer Pending</div>
                    <div class="value" style="color: var(--orange);">5</div>
                    <div class="note">Actions requiring governance, access, CMDB, lifecycle, or infrastructure acceptance.</div>
                </div>

                <div class="metric">
                    <div class="label">Assurance Improved</div>
                    <div class="value" style="color: var(--blue);">+13%</div>
                    <div class="note">Demo improvement in executive assurance confidence after accepted closures.</div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Action Closure Answer</h2>
                <p>
                    This board answers whether executive actions have been completed strongly enough to improve the control assurance story.
                </p>

                <div class="answer">
                    <strong>Current closure interpretation:</strong>
                    An executive action should close only when the required decision was made, the control requirement is active, evidence exists, the accountable reviewer accepts closure, and the assurance state improves. If evidence is missing or the control remains optional, the action should stay open or close only conditionally.
                </div>
            </section>

            <section class="section">
                <h2>Closure Review Domains</h2>
                <p>
                    CITrust™ separates executive action closure into the evidence domains needed to avoid false closure.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Decision Closure</h3>
                        <p>Confirms leadership approved the required gate, rule, ownership model, limitation language, or reliance decision.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Closure</h3>
                        <p>Confirms the action produced proof that is current, reviewable, and tied to the control weakness.</p>
                    </div>

                    <div class="card">
                        <h3>Reviewer Closure</h3>
                        <p>Confirms the accountable governance, access, infrastructure, CMDB, or lifecycle reviewer accepts closure.</p>
                    </div>

                    <div class="card">
                        <h3>Assurance Closure</h3>
                        <p>Confirms the action actually moves the control from weak, conditional, or not reliable into a stronger assurance state.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Control Action Closure Matrix</h2>
                <p>
                    This matrix determines which leadership actions can close and what assurance state they create.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Executive Action</th>
                            <th>Closure Evidence</th>
                            <th>Reviewer Acceptance</th>
                            <th>Control Impact</th>
                            <th>Closure Decision</th>
                            <th>New Assurance State</th>
                            <th>Next Governance Step</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Adopt benchmark evidence model as standard</strong></td>
                            <td>Minimum readiness template defined for owner, support, access, lifecycle, evidence, cadence, and trust decision.</td>
                            <td><span class="badge soft-green">Accepted</span></td>
                            <td>Creates reusable standard for candidate, certificate, and passport review.</td>
                            <td><span class="badge green">Close With Evidence</span></td>
                            <td>Executive-ready standard.</td>
                            <td>Scale across CI candidate factory and certificate board.</td>
                        </tr>

                        <tr>
                            <td><strong>Connect certificate lifecycle outputs to executive trust reporting</strong></td>
                            <td>Issuance, renewal, suspension, restoration, exception, and passport linkage summary defined.</td>
                            <td><span class="badge soft-green">Ready For Review</span></td>
                            <td>Improves leadership visibility into certificate assurance state.</td>
                            <td><span class="badge green">Close Pending Final Review</span></td>
                            <td>Reliable with executive monitoring.</td>
                            <td>Add quarterly executive review cadence.</td>
                        </tr>

                        <tr>
                            <td><strong>Require escalation owner for all exceptions</strong></td>
                            <td>Exception owner and expiry are visible; escalation owner rule still requires formal adoption.</td>
                            <td><span class="badge soft-yellow">Governance Review Needed</span></td>
                            <td>Reduces risk of expired exceptions becoming governance debt.</td>
                            <td><span class="badge yellow">Close Conditional</span></td>
                            <td>Conditionally effective exception control.</td>
                            <td>Make escalation owner mandatory before exception approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Block renewal when access evidence is incomplete</strong></td>
                            <td>MyAccess mapping improving; admin/vendor procedure, access review proof, and post-access verification still need closure.</td>
                            <td><span class="badge soft-yellow">Access Reviewer Pending</span></td>
                            <td>Improves access trust but remains conditional until full proof is attached.</td>
                            <td><span class="badge yellow">Close Conditional</span></td>
                            <td>Conditional access assurance.</td>
                            <td>Require full access evidence bundle for renewal.</td>
                        </tr>

                        <tr>
                            <td><strong>Require cutover recovery attestation before certificate-ready status</strong></td>
                            <td>Cutover evidence chain exists but post-cutover verification and recovery attestation remain incomplete.</td>
                            <td><span class="badge soft-orange">Cutover Review Pending</span></td>
                            <td>Protects cutover-sensitive CI trust from unsupported readiness claims.</td>
                            <td><span class="badge orange">Do Not Close Yet</span></td>
                            <td>Conditional cutover control.</td>
                            <td>Complete recovery attestation and post-cutover verification.</td>
                        </tr>

                        <tr>
                            <td><strong>Approve mandatory support and LCM evidence gate</strong></td>
                            <td>Support group, resolver path, LCM, escalation owner, evidence location, and cadence are not yet consistently enforced.</td>
                            <td><span class="badge soft-red">Not Accepted</span></td>
                            <td>Support-routing assurance remains weak without mandatory gate approval.</td>
                            <td><span class="badge red">Closure Blocked</span></td>
                            <td>Not reliable yet.</td>
                            <td>Require gate approval before candidate review can advance.</td>
                        </tr>

                        <tr>
                            <td><strong>Force hidden-dependency candidate creation</strong></td>
                            <td>Candidate creation requirement identified but still partly manual.</td>
                            <td><span class="badge soft-orange">CMDB Governance Review Needed</span></td>
                            <td>Reduces hidden dependency risk but does not eliminate manual bypass yet.</td>
                            <td><span class="badge orange">Retest Before Closure</span></td>
                            <td>Partially reliable intake control.</td>
                            <td>Force candidate creation before exception, certificate, or trust review.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Closure Decision Logic</h2>
                <p>
                    Executive actions should not close just because they were discussed.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Action Can Close</h3>
                        <ul>
                            <li>Executive decision is recorded.</li>
                            <li>Owner and reviewer are assigned.</li>
                            <li>Required evidence is attached or made mandatory.</li>
                            <li>Control state improves measurably.</li>
                            <li>Residual risk is documented if closure is conditional.</li>
                            <li>Decision ledger records closure rationale.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Action Must Remain Open</h3>
                        <ul>
                            <li>Decision has not been accepted.</li>
                            <li>Evidence is missing, stale, or informal.</li>
                            <li>Control remains optional or manual.</li>
                            <li>Reviewer has not accepted closure.</li>
                            <li>Assurance state would be overstated.</li>
                            <li>Closure would create false executive confidence.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Closure Priority Queue</h2>
                <p>
                    These closure actions should be handled first to convert executive decisions into defensible control assurance.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Closure Gap</th>
                            <th>Why It Matters</th>
                            <th>Closure Requirement</th>
                            <th>Expected Assurance Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Support and LCM gate closure is blocked.</td>
                            <td>ServiceNow-readiness and incident response cannot be defended without support ownership proof.</td>
                            <td>Approve mandatory support group, resolver path, LCM, escalation owner, evidence location, and cadence gate.</td>
                            <td>Not Reliable → Operating Control</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">2</span></td>
                            <td>Hidden-dependency intake still needs enforcement.</td>
                            <td>Operational dependencies can still bypass trust review if candidate creation remains manual.</td>
                            <td>Mandate candidate creation before exception, certificate, or trust review.</td>
                            <td>Partially Reliable → Effective Intake Control</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Cutover action cannot close without post-cutover proof.</td>
                            <td>Cutover-sensitive readiness cannot be defended without recovery and verification evidence.</td>
                            <td>Attach recovery attestation, rollback readiness, vendor handoff, and post-cutover verification.</td>
                            <td>Conditional Cutover → Certificate-Ready Defense</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access action can close only conditionally.</td>
                            <td>Access trust remains conditional without current procedure and review proof.</td>
                            <td>Attach full access bundle and obtain reviewer acceptance.</td>
                            <td>Conditional Access → Reliable Access Assurance</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This executive control action closure board is a governance assurance overlay for executive action closure, evidence acceptance, reviewer sign-off, decision-ledger rationale, control assurance improvement, certificate readiness, CMDB-readiness, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_EXECUTIVE_CONTROL_ACTION_CLOSURE_BOARD_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Executive Control Action Closure Board installed.")
