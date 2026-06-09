from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_EXECUTIVE_ASSURANCE_DIGITAL_TWIN_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/executive-assurance-digital-twin")'
ROUTE_ALIAS = '@app.route("/citrust/trust-digital-twin")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Executive Assurance Digital Twin already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_EXECUTIVE_ASSURANCE_DIGITAL_TWIN_V1_ACTIVE
# ============================================================

@app.route("/citrust/executive-assurance-digital-twin")
@app.route("/citrust/trust-digital-twin")
def citrust_executive_assurance_digital_twin():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Executive Assurance Digital Twin</title>
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
                    radial-gradient(circle at top left, rgba(92,200,255,0.20), transparent 30%),
                    radial-gradient(circle at top right, rgba(180,156,255,0.18), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(49,208,125,0.12), transparent 30%),
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
                max-width: 1160px;
                margin-top: 14px;
            }

            .positioning {
                margin-top: 18px;
                padding: 16px 18px;
                border: 1px solid rgba(180,156,255,0.38);
                background: rgba(180,156,255,0.10);
                border-radius: 16px;
                color: #eee7ff;
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
                min-height: 155px;
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

            .simulation-strip {
                display: grid;
                grid-template-columns: 1.2fr 1fr 1fr;
                gap: 16px;
                margin-top: 16px;
            }

            .sim-box {
                border: 1px solid rgba(92,200,255,0.30);
                background: rgba(92,200,255,0.08);
                border-radius: 18px;
                padding: 18px;
            }

            .sim-box h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .sim-box p {
                margin: 0;
                color: #d9f3ff;
                font-size: 14px;
                line-height: 1.6;
            }

            .footer {
                color: var(--muted);
                font-size: 12px;
                margin-top: 22px;
                line-height: 1.6;
            }

            @media (max-width: 1180px) {
                .kpis, .cards, .two-col, .simulation-strip {
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
                <h1>CITrust™ Executive Assurance Digital Twin</h1>

                <div class="subtitle">
                    A category-defining CITrust™ feature that creates a simulated governance twin of the CI environment, predicts how evidence gaps could turn into trust failure, models executive reliance risk, and recommends preventive control actions before audit, cutover, access, support, lifecycle, or certificate weakness becomes visible.
                </div>

                <div class="positioning">
                    <strong>World-class assurance concept:</strong>
                    This is not another dashboard. It is a governance simulation layer that asks: “If nothing changes, where will CI trust fail, what evidence will be missing, who will be unable to defend it, and what control action prevents the failure before it becomes a deviation, audit finding, or executive surprise?”
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/executive-assurance-decision-ledger">Executive Decision Ledger</a>
                    <a href="/citrust/executive-control-action-closure-board">Action Closure</a>
                    <a href="/citrust/executive-control-assurance-register">Control Register</a>
                    <a href="/citrust/control-maturity-uplift-roadmap">Maturity Roadmap</a>
                    <a href="/citrust/trust-decay-forecast">Trust Decay Forecast</a>
                    <a href="/citrust/continuous-trust-monitor">Continuous Trust</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Simulated Trust Futures</div>
                    <div class="value">24</div>
                    <div class="note">Forward-looking scenarios generated from CI evidence, control, and exception states.</div>
                </div>

                <div class="metric">
                    <div class="label">Predicted Trust Failures</div>
                    <div class="value" style="color: var(--red);">5</div>
                    <div class="note">Future-state failures likely if no control action is taken.</div>
                </div>

                <div class="metric">
                    <div class="label">Pre-Deviation Alerts</div>
                    <div class="value" style="color: var(--orange);">7</div>
                    <div class="note">Signals where weak governance could become deviation-like exposure.</div>
                </div>

                <div class="metric">
                    <div class="label">Preventable Failures</div>
                    <div class="value" style="color: var(--green);">9</div>
                    <div class="note">Issues avoidable by closing the recommended control action.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Reliance Risk</div>
                    <div class="value" style="color: var(--yellow);">Medium</div>
                    <div class="note">Current reliance risk if conditional controls are treated as fully reliable.</div>
                </div>

                <div class="metric">
                    <div class="label">Assurance Recovery Gain</div>
                    <div class="value" style="color: var(--blue);">+31%</div>
                    <div class="note">Simulated confidence improvement if top preventive controls close.</div>
                </div>
            </section>

            <section class="section">
                <h2>Digital Twin Answer</h2>
                <p>
                    This page answers what will likely break in the assurance model before it breaks operationally.
                </p>

                <div class="answer">
                    <strong>Current simulation interpretation:</strong>
                    CITrust™ predicts that the biggest future trust failures will come from support/LCM ambiguity, hidden-dependency bypass, incomplete privileged access evidence, cutover verification gaps, and exception escalation weakness. These are not just current issues; they are future assurance-collapse paths unless they become mandatory evidence gates.
                </div>
            </section>

            <section class="section">
                <h2>Assurance Digital Twin Engines</h2>
                <p>
                    This feature introduces simulation concepts that go beyond normal CMDB reporting.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Trust Time Machine</h3>
                        <p>Projects the CI’s future trust state based on evidence freshness, exception aging, certificate status, support readiness, and access proof decay.</p>
                    </div>

                    <div class="card">
                        <h3>Counterfactual Governance Reasoner</h3>
                        <p>Asks what would have happened if the missing control had been mandatory before candidate, certificate, renewal, or exception review.</p>
                    </div>

                    <div class="card">
                        <h3>Assurance Collapse Simulator</h3>
                        <p>Models how one weak control can cascade into access uncertainty, support ambiguity, stale certificate status, audit exposure, and executive reliance failure.</p>
                    </div>

                    <div class="card">
                        <h3>Preventive Control Prescriber</h3>
                        <p>Recommends the exact governance control that prevents the simulated failure before it becomes visible to audit, QA, operations, or leadership.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Live Simulation Snapshot</h2>
                <p>
                    This is the executive “what happens next?” view.
                </p>

                <div class="simulation-strip">
                    <div class="sim-box">
                        <h3><span class="badge red">Highest-Risk Future</span> Support Trust Failure</h3>
                        <p>
                            If support group, resolver path, LCM, and escalation owner remain optional, operational CIs may appear ready while incident response and ServiceNow-readiness remain weak.
                        </p>
                    </div>

                    <div class="sim-box">
                        <h3><span class="badge orange">Most Preventable</span> Hidden Dependency Bypass</h3>
                        <p>
                            If backup, audit, access, or review dependencies must become CI candidates, hidden governance debt can be converted into governed intake before failure.
                        </p>
                    </div>

                    <div class="sim-box">
                        <h3><span class="badge blue">Best Intervention</span> Mandatory Evidence Gates</h3>
                        <p>
                            The highest-confidence improvement comes from making support, access, hidden dependency, and exception escalation evidence mandatory before reliance.
                        </p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Assurance Digital Twin Matrix</h2>
                <p>
                    This matrix simulates future failure paths and the preventive control that stops them.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Simulated Future</th>
                            <th>Trigger Condition</th>
                            <th>Predicted Failure Path</th>
                            <th>Executive Impact</th>
                            <th>Preventive Control</th>
                            <th>Simulation Result</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Support Trust Collapse</strong></td>
                            <td>Support group, resolver path, LCM, and escalation owner remain non-mandatory.</td>
                            <td>CI appears ready, but incident routing and ownership cannot be defended when questioned.</td>
                            <td><span class="badge red">High Executive Exposure</span></td>
                            <td>Mandatory Support and LCM Confirmation Gate.</td>
                            <td><span class="badge red">Failure Predicted</span></td>
                            <td>Block candidate approval unless support, LCM, resolver, escalation, and evidence location are complete.</td>
                        </tr>

                        <tr>
                            <td><strong>Hidden Dependency Bypass</strong></td>
                            <td>Backup, audit review, lab workstation, access, or support dependency remains outside candidate review.</td>
                            <td>Operational dependency supports a trusted CI but has no owner, evidence, cadence, or verification model.</td>
                            <td><span class="badge orange">Invisible Governance Debt</span></td>
                            <td>Hidden-Dependency Candidate Creation Trigger.</td>
                            <td><span class="badge orange">Pre-Deviation Signal</span></td>
                            <td>Force candidate record before exception, certificate, or trust review can proceed.</td>
                        </tr>

                        <tr>
                            <td><strong>Privileged Access Reliance Failure</strong></td>
                            <td>MyAccess mapping exists but admin/vendor procedure, jump path, review proof, or post-access verification is stale.</td>
                            <td>Leadership claims access assurance, but evidence cannot defend admin or vendor access governance.</td>
                            <td><span class="badge yellow">Conditional Reliance Risk</span></td>
                            <td>Privileged Access Evidence Bundle Gate.</td>
                            <td><span class="badge yellow">Failure Preventable</span></td>
                            <td>Block renewal unless the full access evidence bundle is current and reviewer accepted.</td>
                        </tr>

                        <tr>
                            <td><strong>Cutover Readiness Overstatement</strong></td>
                            <td>Cutover evidence pack exists but rollback, vendor handoff, recovery attestation, or post-cutover verification is incomplete.</td>
                            <td>CI is described as ready before recovery and verification proof can defend the claim.</td>
                            <td><span class="badge orange">Readiness Overstatement</span></td>
                            <td>Cutover Recovery Attestation Gate.</td>
                            <td><span class="badge orange">Trust Decay Likely</span></td>
                            <td>Require recovery attestation and post-cutover verification before certificate-ready status.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception Debt Accumulation</strong></td>
                            <td>Exceptions have owner and expiry date but no mandatory escalation owner or closure evidence requirement.</td>
                            <td>Exceptions age, expire, and become normalized governance debt.</td>
                            <td><span class="badge red">Audit Defense Weakness</span></td>
                            <td>Exception Expiry Escalation Rule.</td>
                            <td><span class="badge red">Recurring Pattern Predicted</span></td>
                            <td>Require escalation owner, closure evidence, residual-risk statement, and decision-ledger entry.</td>
                        </tr>

                        <tr>
                            <td><strong>False Closure Loop</strong></td>
                            <td>Executive action closes because it was discussed, not because evidence proves the control improved.</td>
                            <td>Weak control reappears after closure and damages confidence in governance maturity.</td>
                            <td><span class="badge orange">False Assurance Risk</span></td>
                            <td>Executive Control Action Closure Board.</td>
                            <td><span class="badge yellow">Preventable With Closure Evidence</span></td>
                            <td>Require reviewer acceptance, evidence proof, assurance-state update, and decision-ledger rationale.</td>
                        </tr>

                        <tr>
                            <td><strong>Best-Case Trust Recovery</strong></td>
                            <td>Mandatory support, access, hidden dependency, exception, and cutover evidence gates are all adopted.</td>
                            <td>Conditional reliance converts into operating controls, evidence-backed decisions, and executive-ready trust reporting.</td>
                            <td><span class="badge green">Executive Confidence Gain</span></td>
                            <td>Governance Control Operating Model.</td>
                            <td><span class="badge green">Trust Recovery Simulated</span></td>
                            <td>Convert these gates into CITrust™ operating model and quarterly review cadence.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Digital Twin Decision Logic</h2>
                <p>
                    The digital twin does not wait for failure. It treats weak evidence as a future signal.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Future Failure Is Likely When</h3>
                        <ul>
                            <li>Evidence is optional, stale, or manually chased.</li>
                            <li>Support, access, lifecycle, or escalation owner is unclear.</li>
                            <li>Conditional controls are treated as fully reliable.</li>
                            <li>Hidden dependency can bypass CI candidate review.</li>
                            <li>Exception can expire without escalation owner.</li>
                            <li>Closure happens without operating-effectiveness proof.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Failure Becomes Preventable When</h3>
                        <ul>
                            <li>Evidence gates are mandatory before reliance.</li>
                            <li>Owner, reviewer, and escalation roles are explicit.</li>
                            <li>Certificate readiness depends on evidence freshness.</li>
                            <li>Hidden dependencies become governed candidates.</li>
                            <li>Exception closure requires proof and rationale.</li>
                            <li>Executive decisions are recorded in the assurance ledger.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Preventive Assurance Prescription Queue</h2>
                <p>
                    These are the highest-value actions predicted to prevent future CI trust failure.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Predicted Future Risk</th>
                            <th>Why It Matters</th>
                            <th>Preventive Control Prescription</th>
                            <th>Expected Future State</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Support trust failure will continue unless support and LCM evidence becomes mandatory.</td>
                            <td>Operational readiness cannot be defended if support ownership is unclear.</td>
                            <td>Mandatory support group, resolver path, LCM, escalation owner, evidence location, and cadence gate.</td>
                            <td>Support assurance becomes operating and reviewable.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">2</span></td>
                            <td>Hidden dependency bypass will create invisible governance debt.</td>
                            <td>Dependencies that support trusted CIs must themselves become governed candidates.</td>
                            <td>Force candidate creation for backup, audit, access, support, workstation, or review dependencies.</td>
                            <td>Hidden dependencies become visible, owned, evidenced, and reviewable.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Exception debt will accumulate without escalation ownership.</td>
                            <td>Expired exceptions weaken audit defense and normalize unresolved risk.</td>
                            <td>Require escalation owner, expiry date, closure evidence, residual-risk statement, and decision-ledger entry.</td>
                            <td>Exception governance becomes defensible and closure-driven.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access reliance will remain conditional without full access proof.</td>
                            <td>Admin, vendor, jump path, and MyAccess assurance cannot be claimed without current evidence.</td>
                            <td>Block renewal unless full access evidence bundle is current and reviewer accepted.</td>
                            <td>Access assurance moves from conditional to reliable.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This executive assurance digital twin is a governance assurance overlay for future trust simulation, counterfactual governance reasoning, assurance collapse prediction, preventive control prescription, executive reliance modeling, certificate readiness forecasting, CMDB-readiness defense, audit survivability, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_EXECUTIVE_ASSURANCE_DIGITAL_TWIN_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Executive Assurance Digital Twin installed.")
