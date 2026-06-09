from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_TRUST_FAILURE_PREMORTEM_ENGINE_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/trust-failure-premortem-engine")'
ROUTE_ALIAS = '@app.route("/citrust/assurance-premortem")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Trust Failure Pre-Mortem Engine already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_TRUST_FAILURE_PREMORTEM_ENGINE_V1_ACTIVE
# ============================================================

@app.route("/citrust/trust-failure-premortem-engine")
@app.route("/citrust/assurance-premortem")
def citrust_trust_failure_premortem_engine():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Trust Failure Pre-Mortem Engine</title>
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
                    radial-gradient(circle at top left, rgba(255,92,112,0.18), transparent 30%),
                    radial-gradient(circle at top right, rgba(92,200,255,0.17), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(180,156,255,0.12), transparent 30%),
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
                border: 1px solid rgba(255,92,112,0.38);
                background: rgba(255,92,112,0.10);
                border-radius: 16px;
                color: #ffe5e9;
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

            .premortem-strip {
                display: grid;
                grid-template-columns: 1fr 1fr 1fr;
                gap: 16px;
                margin-top: 16px;
            }

            .premortem-box {
                border: 1px solid rgba(255,92,112,0.30);
                background: rgba(255,92,112,0.08);
                border-radius: 18px;
                padding: 18px;
            }

            .premortem-box h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .premortem-box p {
                margin: 0;
                color: #ffe5e9;
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
                .kpis, .cards, .two-col, .premortem-strip {
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
                <h1>CITrust™ Trust Failure Pre-Mortem Engine</h1>

                <div class="subtitle">
                    A world-class CITrust™ reasoning layer that assumes a CI trust failure has already happened, reconstructs the most likely failure chain, identifies the missing evidence or control that caused it, and prescribes the preventive governance action before leadership relies on a weak claim.
                </div>

                <div class="positioning">
                    <strong>Category-defining capability:</strong>
                    Normal dashboards report what is already wrong. This pre-mortem engine asks: “If this CITrust™ assurance claim fails six weeks from now, what will be the most likely reason, what evidence will be missing, who will be unable to defend it, and what control must become mandatory today to prevent that failure?”
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/executive-assurance-digital-twin">Assurance Digital Twin</a>
                    <a href="/citrust/executive-assurance-decision-ledger">Assurance Decision Ledger</a>
                    <a href="/citrust/executive-control-action-closure-board">Action Closure</a>
                    <a href="/citrust/control-maturity-uplift-roadmap">Maturity Roadmap</a>
                    <a href="/citrust/trust-decay-forecast">Trust Decay Forecast</a>
                    <a href="/citrust/control-audit-defense-pack">Control Defense Pack</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Pre-Mortem Scenarios</div>
                    <div class="value">32</div>
                    <div class="note">Future failure narratives simulated from evidence and control states.</div>
                </div>

                <div class="metric">
                    <div class="label">Likely Failure Chains</div>
                    <div class="value" style="color: var(--red);">6</div>
                    <div class="note">Failure paths likely to damage executive reliance if unresolved.</div>
                </div>

                <div class="metric">
                    <div class="label">Preventable Failures</div>
                    <div class="value" style="color: var(--green);">12</div>
                    <div class="note">Failure scenarios preventable with mandatory evidence gates.</div>
                </div>

                <div class="metric">
                    <div class="label">Claim Guardrails</div>
                    <div class="value" style="color: var(--yellow);">9</div>
                    <div class="note">Statements leadership should limit, condition, or avoid.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Red Lines</div>
                    <div class="value" style="color: var(--orange);">5</div>
                    <div class="note">Claims that must not be made until evidence closes.</div>
                </div>

                <div class="metric">
                    <div class="label">Prevention Confidence</div>
                    <div class="value" style="color: var(--blue);">86%</div>
                    <div class="note">Estimated confidence that top prescribed controls reduce future trust failure.</div>
                </div>
            </section>

            <section class="section">
                <h2>Pre-Mortem Answer</h2>
                <p>
                    This page answers what would most likely cause CITrust™ assurance to fail in the future.
                </p>

                <div class="answer">
                    <strong>Current pre-mortem interpretation:</strong>
                    The most likely future assurance failure is not a missing dashboard. It is leadership relying on a CI that looks ready while support ownership, hidden dependency intake, privileged access evidence, exception escalation, or cutover verification remains conditional. The pre-mortem prevents false confidence before it becomes an audit weakness, operational confusion, or governance debt.
                </div>
            </section>

            <section class="section">
                <h2>Pre-Mortem Intelligence Engines</h2>
                <p>
                    CITrust™ uses pre-failure reasoning to convert weak signals into preventive governance action.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Future Audit Interrogator</h3>
                        <p>Simulates the hardest audit or executive question that would expose weak evidence, unclear ownership, or unsupported readiness claims.</p>
                    </div>

                    <div class="card">
                        <h3>Failure Chain Reconstructor</h3>
                        <p>Works backward from a simulated failure to identify the first weak control, missing owner, stale proof, or bypassed gate.</p>
                    </div>

                    <div class="card">
                        <h3>Executive Claim Guardrail</h3>
                        <p>Warns leadership which statements are safe, conditional, exaggerated, or completely unsupported by the evidence state.</p>
                    </div>

                    <div class="card">
                        <h3>Control Kill-Switch Prescriber</h3>
                        <p>Recommends the exact mandatory gate that stops the simulated failure path before it becomes visible.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Pre-Mortem Executive Snapshot</h2>
                <p>
                    This is the “assume it failed — why did it fail?” view.
                </p>

                <div class="premortem-strip">
                    <div class="premortem-box">
                        <h3><span class="badge red">Most Likely Failure</span> Unsupported Support Reliance</h3>
                        <p>
                            Six weeks from now, leadership may ask who owns support for an operational CI, and the evidence may not clearly show support group, resolver path, LCM, and escalation owner.
                        </p>
                    </div>

                    <div class="premortem-box">
                        <h3><span class="badge orange">Most Hidden Failure</span> Dependency Bypass</h3>
                        <p>
                            A local workstation, backup review dependency, audit review process, or access dependency may support a trusted CI without becoming a governed CI candidate.
                        </p>
                    </div>

                    <div class="premortem-box">
                        <h3><span class="badge blue">Best Prevention</span> Claim Before Evidence Block</h3>
                        <p>
                            Any executive claim of readiness should be blocked or marked conditional until support, access, lifecycle, exception, and cutover evidence proves the claim.
                        </p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Trust Failure Pre-Mortem Matrix</h2>
                <p>
                    This matrix simulates future failure stories and prescribes preventive controls.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Future Failure Story</th>
                            <th>Simulated Audit / Executive Question</th>
                            <th>Likely Root Cause</th>
                            <th>Weak Signal Today</th>
                            <th>Executive Claim Risk</th>
                            <th>Prevention Control</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Support Ownership Cannot Be Defended</strong></td>
                            <td>“Who owns this CI operationally, who resolves incidents, and who is accountable for lifecycle support?”</td>
                            <td>Support group, resolver path, LCM, and escalation owner were not mandatory before candidate approval.</td>
                            <td>Support and LCM gate remains ad hoc or inconsistently evidenced.</td>
                            <td><span class="badge red">Do Not Claim Reliable</span></td>
                            <td>Mandatory Support and LCM Evidence Gate.</td>
                            <td>Block candidate advancement without support group, resolver path, LCM, escalation owner, evidence location, and cadence.</td>
                        </tr>

                        <tr>
                            <td><strong>Vendor Access Cannot Be Defended</strong></td>
                            <td>“How do you know vendor/admin access was governed, reviewed, routed, and verified?”</td>
                            <td>MyAccess evidence existed, but admin/vendor procedure, jump path, access review proof, or post-access verification was stale.</td>
                            <td>Privileged access evidence bundle remains conditional.</td>
                            <td><span class="badge yellow">Claim With Limitation</span></td>
                            <td>Privileged Access Evidence Bundle Gate.</td>
                            <td>Block renewal unless full access evidence bundle is current and reviewer accepted.</td>
                        </tr>

                        <tr>
                            <td><strong>Hidden Dependency Surfaces During Review</strong></td>
                            <td>“What system or process supports the backup, audit review, access review, or operational verification for this CI?”</td>
                            <td>A dependency supported the trusted CI but never became a CI candidate with owner, support, access, evidence, and cadence.</td>
                            <td>Hidden dependency intake still allows manual delay or bypass.</td>
                            <td><span class="badge orange">Strengthen Before Reliance</span></td>
                            <td>Hidden-Dependency Candidate Creation Trigger.</td>
                            <td>Force candidate creation for backup, audit, access, support, workstation, or review dependencies.</td>
                        </tr>

                        <tr>
                            <td><strong>Cutover Readiness Is Overstated</strong></td>
                            <td>“Where is the evidence that cutover, rollback, vendor support, jump path, and post-change verification were completed?”</td>
                            <td>Cutover evidence pack existed, but recovery attestation and post-cutover verification were incomplete.</td>
                            <td>Cutover-sensitive CI remains conditionally ready.</td>
                            <td><span class="badge orange">Conditional Only</span></td>
                            <td>Cutover Recovery Attestation Gate.</td>
                            <td>Require support, access, vendor handoff, rollback, recovery, and post-cutover verification before certificate-ready status.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception Becomes Governance Debt</strong></td>
                            <td>“Why was the exception still open, who owned closure, and why was it not escalated?”</td>
                            <td>Exception had owner and expiry date but no mandatory escalation owner, closure evidence, or residual-risk statement.</td>
                            <td>Exception expiry escalation rule remains defined but not enforced.</td>
                            <td><span class="badge red">Do Not Claim Controlled</span></td>
                            <td>Exception Expiry Escalation Rule.</td>
                            <td>Require escalation owner, closure evidence, residual-risk statement, and decision-ledger entry before exception approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Executive Action Closes Without Real Control Change</strong></td>
                            <td>“What evidence proves the leadership action actually improved the control?”</td>
                            <td>Action closed because it was discussed, not because evidence, reviewer acceptance, and assurance-state change were recorded.</td>
                            <td>Closure board shows reviewer pending or evidence partial.</td>
                            <td><span class="badge orange">False Closure Risk</span></td>
                            <td>Executive Action Closure Attestation.</td>
                            <td>Require closure proof, reviewer acceptance, assurance-state update, and decision-ledger rationale.</td>
                        </tr>

                        <tr>
                            <td><strong>Certificate Status Becomes Misleading</strong></td>
                            <td>“Does certificate-ready mean evidence is current, reviewed, and still valid?”</td>
                            <td>Certificate status was treated as static while evidence freshness, exceptions, access reviews, or lifecycle status decayed.</td>
                            <td>Certificate lifecycle visibility needs stronger linkage to evidence freshness and trust decay.</td>
                            <td><span class="badge yellow">Rely With Monitoring</span></td>
                            <td>Evidence Freshness and Certificate Renewal Gate.</td>
                            <td>Connect certificate state to evidence age, exception state, access review status, and lifecycle closure signals.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Pre-Mortem Decision Logic</h2>
                <p>
                    The pre-mortem blocks claims before the evidence fails.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Failure Is Likely If</h3>
                        <ul>
                            <li>Leadership relies on conditional controls as if they are fully reliable.</li>
                            <li>Support, access, lifecycle, or escalation ownership remains unclear.</li>
                            <li>Evidence is stale, partial, manual, or not tied to a decision.</li>
                            <li>Hidden dependencies support trusted CIs without becoming candidates.</li>
                            <li>Exceptions can age without escalation and closure evidence.</li>
                            <li>Executive actions close without proving control improvement.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Failure Is Prevented If</h3>
                        <ul>
                            <li>Mandatory evidence gates block unsupported reliance.</li>
                            <li>Claim language matches evidence strength and maturity.</li>
                            <li>Hidden dependencies become governed CI candidates.</li>
                            <li>Certificate readiness depends on current evidence.</li>
                            <li>Exceptions require owner, escalation, closure, and rationale.</li>
                            <li>Decision ledger records the reason for reliance or refusal.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Pre-Mortem Prevention Queue</h2>
                <p>
                    These are the control actions most likely to prevent future CITrust™ assurance failure.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Predicted Failure</th>
                            <th>Why It Will Hurt</th>
                            <th>Preventive Action</th>
                            <th>Assurance Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Support ownership cannot be defended.</td>
                            <td>ServiceNow-readiness, incident routing, and executive reliance fail when support accountability is unclear.</td>
                            <td>Make support group, resolver path, LCM, escalation owner, evidence location, and review cadence mandatory.</td>
                            <td>Support trust becomes evidence-backed and defensible.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Hidden dependency bypass surfaces during audit or operations review.</td>
                            <td>Unmanaged dependencies create invisible trust debt behind apparently trusted CIs.</td>
                            <td>Force candidate creation for backup, audit, access, support, workstation, or review dependencies.</td>
                            <td>Hidden dependencies become visible, owned, and reviewable.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Exception governance turns into unresolved debt.</td>
                            <td>Expired exceptions weaken audit defense and normalize unresolved risk.</td>
                            <td>Require escalation owner, closure evidence, residual-risk statement, expiry date, and decision-ledger entry.</td>
                            <td>Exceptions become closure-driven and defensible.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access reliance remains conditional or unsupported.</td>
                            <td>Admin, vendor, jump path, and MyAccess assurance cannot be defended with stale proof.</td>
                            <td>Block renewal unless full access evidence bundle is current and accepted.</td>
                            <td>Access trust moves from conditional to reliable.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This trust failure pre-mortem engine is a governance assurance overlay for pre-failure reasoning, future audit interrogation, failure-chain reconstruction, executive claim guardrails, preventive control prescription, evidence reliance limits, certificate readiness defense, CMDB-readiness defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_TRUST_FAILURE_PREMORTEM_ENGINE_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Trust Failure Pre-Mortem Engine installed.")
