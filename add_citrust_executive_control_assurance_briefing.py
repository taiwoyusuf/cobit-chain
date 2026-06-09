from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_EXECUTIVE_CONTROL_ASSURANCE_BRIEFING_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/executive-control-assurance-briefing")'
ROUTE_ALIAS = '@app.route("/citrust/control-assurance-briefing")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Executive Control Assurance Briefing already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_EXECUTIVE_CONTROL_ASSURANCE_BRIEFING_V1_ACTIVE
# ============================================================

@app.route("/citrust/executive-control-assurance-briefing")
@app.route("/citrust/control-assurance-briefing")
def citrust_executive_control_assurance_briefing():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Executive Control Assurance Briefing</title>
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
                    radial-gradient(circle at top right, rgba(180,156,255,0.14), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(49,208,125,0.10), transparent 30%),
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
                border: 1px solid rgba(92,200,255,0.38);
                background: rgba(92,200,255,0.10);
                color: #d9f3ff;
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

            .briefing {
                display: grid;
                grid-template-columns: 1.2fr 1fr;
                gap: 16px;
                margin-top: 16px;
            }

            .briefing-box {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 18px;
            }

            .briefing-box h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .briefing-box p {
                margin: 0;
                color: var(--muted);
                line-height: 1.6;
                font-size: 14px;
            }

            .footer {
                color: var(--muted);
                font-size: 12px;
                margin-top: 22px;
                line-height: 1.6;
            }

            @media (max-width: 1180px) {
                .kpis, .cards, .two-col, .briefing {
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
                <h1>CITrust™ Executive Control Assurance Briefing</h1>

                <div class="subtitle">
                    Leadership briefing view that summarizes what CITrust™ controls can be relied on, what remains conditional, what should not be claimed, and what executive action is required to strengthen CMDB-readiness, certificate assurance, access governance, lifecycle trust, and audit defense.
                </div>

                <div class="positioning">
                    <strong>Briefing boundary:</strong>
                    CITrust™ does not update ServiceNow, approve access, certify legal compliance, or replace human governance in this demo. This briefing translates control assurance evidence into executive-ready statements, risk limits, open decisions, and action priorities.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/executive-control-assurance-register">Control Register</a>
                    <a href="/citrust/control-maturity-uplift-roadmap">Maturity Roadmap</a>
                    <a href="/citrust/control-assurance-maturity-scorecard">Maturity Scorecard</a>
                    <a href="/citrust/control-audit-defense-pack">Control Defense Pack</a>
                    <a href="/citrust/control-assurance-attestation">Control Attestation</a>
                    <a href="/citrust/certificate-lifecycle-command-center">Certificate Command Center</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Briefing Topics</div>
                    <div class="value">9</div>
                    <div class="note">Executive assurance topics prepared for leadership review.</div>
                </div>

                <div class="metric">
                    <div class="label">Safe To Defend</div>
                    <div class="value" style="color: var(--green);">4</div>
                    <div class="note">Control statements supported by evidence and maturity.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Statements</div>
                    <div class="value" style="color: var(--yellow);">4</div>
                    <div class="note">Claims requiring limitation language or residual-risk disclosure.</div>
                </div>

                <div class="metric">
                    <div class="label">Do Not Claim</div>
                    <div class="value" style="color: var(--red);">2</div>
                    <div class="note">Statements not defensible until remediation closes.</div>
                </div>

                <div class="metric">
                    <div class="label">Leadership Decisions</div>
                    <div class="value" style="color: var(--orange);">4</div>
                    <div class="note">Decisions requiring ownership, priority, or mandatory gate approval.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Confidence</div>
                    <div class="value" style="color: var(--blue);">74%</div>
                    <div class="note">Demo confidence score based on evidence, maturity, and open gaps.</div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Briefing Answer</h2>
                <p>
                    This briefing answers what leadership can say with confidence today.
                </p>

                <div class="answer">
                    <strong>Current briefing interpretation:</strong>
                    CITrust™ can defend lifecycle closure controls, the benchmark evidence model, and certificate lifecycle visibility. It should present privileged access, cutover evidence, and hidden-dependency intake as conditional. It should not claim support and LCM confirmation is reliable until that control becomes a mandatory candidate-review gate with evidence and ownership.
                </div>
            </section>

            <section class="section">
                <h2>Executive Talking Points</h2>
                <p>
                    These are the leadership-ready points that summarize the current assurance position.
                </p>

                <div class="briefing">
                    <div class="briefing-box">
                        <h3><span class="badge green">Defensible</span> What We Can Say</h3>
                        <p>
                            CITrust™ has a structured control assurance model covering evidence, maturity, control effectiveness, deficiencies, remediation, certificate lifecycle, exceptions, and audit defense. Some controls are already evidence-backed enough to support executive reliance.
                        </p>
                    </div>

                    <div class="briefing-box">
                        <h3><span class="badge yellow">Conditional</span> What Needs Limitation</h3>
                        <p>
                            Access assurance, cutover readiness, hidden-dependency intake, and exception expiry governance should be described as improving but not fully mature until required evidence and ownership gates are mandatory.
                        </p>
                    </div>

                    <div class="briefing-box">
                        <h3><span class="badge red">Do Not Overstate</span> What We Should Not Claim</h3>
                        <p>
                            Do not claim all CI support routing, LCM ownership, or hidden dependencies are fully controlled while evidence remains inconsistent or candidate creation is still partly manual.
                        </p>
                    </div>

                    <div class="briefing-box">
                        <h3><span class="badge blue">Executive Ask</span> What Leadership Must Decide</h3>
                        <p>
                            Leadership should approve mandatory evidence gates for support/LCM, hidden-dependency intake, privileged access renewal, and exception escalation ownership.
                        </p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Control Assurance Briefing Matrix</h2>
                <p>
                    This matrix converts the control register into leadership-ready briefing statements.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Briefing Topic</th>
                            <th>Executive Statement</th>
                            <th>Evidence Basis</th>
                            <th>Reliance Level</th>
                            <th>Risk Limitation</th>
                            <th>Leadership Action</th>
                            <th>Briefing Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Lifecycle Closure Assurance</strong></td>
                            <td>OOS and retired CI restoration is blocked unless closure and access-removal evidence exist.</td>
                            <td>Closure evidence, access deactivation proof, lifecycle decision, decision-ledger update.</td>
                            <td><span class="badge green">High Confidence</span></td>
                            <td>Maintain gate discipline; do not allow bypass.</td>
                            <td>Support continued mandatory gate.</td>
                            <td><span class="badge green">Safe To Defend</span></td>
                        </tr>

                        <tr>
                            <td><strong>Benchmark Evidence Model</strong></td>
                            <td>Mature CI evidence models can be reused as a minimum readiness standard.</td>
                            <td>Owner, support, access, lifecycle, evidence, cadence, and trust-decision alignment.</td>
                            <td><span class="badge blue">Executive Ready</span></td>
                            <td>Do not claim every CI has reached this standard yet.</td>
                            <td>Adopt as standard for candidate, certificate, and passport review.</td>
                            <td><span class="badge blue">Scale</span></td>
                        </tr>

                        <tr>
                            <td><strong>Certificate Lifecycle Visibility</strong></td>
                            <td>CITrust™ provides a governed view of issuance, registry, renewal, suspension, restoration, exceptions, and passport linkage.</td>
                            <td>Certificate board, registry, renewal, suspension, exception, recovery, and lifecycle views.</td>
                            <td><span class="badge green">Reliable With Monitoring</span></td>
                            <td>Certificate status must continue to reflect evidence freshness.</td>
                            <td>Connect certificate outputs into executive trust reporting.</td>
                            <td><span class="badge green">Safe To Defend</span></td>
                        </tr>

                        <tr>
                            <td><strong>Privileged Access Assurance</strong></td>
                            <td>Access assurance is improving but should remain conditional until the full access evidence bundle is current.</td>
                            <td>MyAccess mapping, approver group, admin/vendor procedure, access review proof, post-access verification.</td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Do not claim full access defensibility where procedure or review proof is stale.</td>
                            <td>Block certificate renewal when access proof is incomplete.</td>
                            <td><span class="badge yellow">Use Limitation Language</span></td>
                        </tr>

                        <tr>
                            <td><strong>Cutover Evidence Assurance</strong></td>
                            <td>Cutover-sensitive CIs should remain conditional until support, access, vendor, rollback, and verification evidence closes.</td>
                            <td>Support group, MyAccess role, jump path, vendor handoff, rollback readiness, post-cutover verification.</td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Do not claim full cutover readiness before post-cutover verification.</td>
                            <td>Require recovery attestation before certificate-ready status.</td>
                            <td><span class="badge yellow">Conditional Briefing</span></td>
                        </tr>

                        <tr>
                            <td><strong>Exception Expiry Governance</strong></td>
                            <td>Exceptions are visible, but escalation ownership must become mandatory to prevent governance debt.</td>
                            <td>Exception owner, expiry date, escalation owner, closure evidence, residual-risk statement, decision ledger.</td>
                            <td><span class="badge orange">Needs Executive Action</span></td>
                            <td>Expired exceptions remain a risk if no escalation owner is assigned.</td>
                            <td>Make escalation owner mandatory before exception approval.</td>
                            <td><span class="badge orange">Decision Required</span></td>
                        </tr>

                        <tr>
                            <td><strong>Support and LCM Assurance</strong></td>
                            <td>Support and LCM confirmation is not reliable enough for executive reliance yet.</td>
                            <td>Support group, resolver path, LCM, escalation owner, evidence location, review cadence.</td>
                            <td><span class="badge red">Not Reliable</span></td>
                            <td>Do not claim support-routing assurance until the gate is mandatory.</td>
                            <td>Require support and LCM evidence before candidate approval.</td>
                            <td><span class="badge red">Do Not Claim Yet</span></td>
                        </tr>

                        <tr>
                            <td><strong>Hidden Dependency Intake</strong></td>
                            <td>Hidden dependencies are being identified, but intake must become mandatory to be fully reliable.</td>
                            <td>Candidate record, owner, support, LCM, access path, evidence model, cadence, verification model.</td>
                            <td><span class="badge orange">Partially Reliable</span></td>
                            <td>Manual intake can still allow invisible operational dependencies.</td>
                            <td>Force candidate creation before exception, certificate, or trust review.</td>
                            <td><span class="badge orange">Strengthen Before Reliance</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Executive Briefing Decision Logic</h2>
                <p>
                    The briefing should separate defensible claims from conditional claims and unsupported claims.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Safe For Leadership To Say</h3>
                        <ul>
                            <li>Evidence exists and is reviewable.</li>
                            <li>Control owner and reviewer are clear.</li>
                            <li>Control is operating or effectiveness has been demonstrated.</li>
                            <li>Decision ledger supports the assurance statement.</li>
                            <li>Any limitation is clearly stated.</li>
                            <li>Claim does not overstate ServiceNow, MyAccess, or audit authority.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Do Not Say Yet</h3>
                        <ul>
                            <li>Evidence is missing, stale, or informal.</li>
                            <li>Control remains ad hoc or owner-dependent.</li>
                            <li>Same deficiency recurs after remediation.</li>
                            <li>Exception ownership or escalation is unclear.</li>
                            <li>Claim implies full readiness when status is conditional.</li>
                            <li>Statement would create false executive confidence.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Decision Queue</h2>
                <p>
                    These decisions will materially improve leadership confidence in the control assurance layer.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Executive Decision Needed</th>
                            <th>Why It Matters</th>
                            <th>Decision To Make</th>
                            <th>Expected Assurance Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Approve mandatory support and LCM evidence gate.</td>
                            <td>ServiceNow-readiness and incident-routing trust cannot be defended without support evidence.</td>
                            <td>No candidate approval without support group, resolver path, LCM, escalation owner, and evidence location.</td>
                            <td>Not Reliable → Operating Control</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">2</span></td>
                            <td>Mandate hidden-dependency candidate creation.</td>
                            <td>Operational dependencies can bypass trust review and create invisible governance debt.</td>
                            <td>Any backup, audit, access, support, or review dependency must become a CI candidate.</td>
                            <td>Partially Reliable → Effective Intake Control</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Require escalation owner for exceptions.</td>
                            <td>Expired exceptions become audit weaknesses if no one owns closure.</td>
                            <td>No exception approval without owner, expiry date, escalation owner, closure evidence, and decision-ledger entry.</td>
                            <td>Weak Exception Control → Effective Control</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Block certificate renewal when access evidence is incomplete.</td>
                            <td>Access assurance cannot be fully defended without current procedure and review proof.</td>
                            <td>Require MyAccess mapping, approver group, admin/vendor procedure, access review proof, and post-access verification.</td>
                            <td>Conditional Access → Reliable Access Assurance</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This executive control assurance briefing is a governance assurance overlay for leadership-ready control assurance, defensible claims, conditional claims, unsupported-claim prevention, executive decisions, maturity uplift, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_EXECUTIVE_CONTROL_ASSURANCE_BRIEFING_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Executive Control Assurance Briefing installed.")
