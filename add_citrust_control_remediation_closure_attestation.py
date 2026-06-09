from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CONTROL_REMEDIATION_CLOSURE_ATTESTATION_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/control-remediation-closure-attestation")'
ROUTE_ALIAS = '@app.route("/citrust/control-remediation-closure")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Control Remediation Closure Attestation already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CONTROL_REMEDIATION_CLOSURE_ATTESTATION_V1_ACTIVE
# ============================================================

@app.route("/citrust/control-remediation-closure-attestation")
@app.route("/citrust/control-remediation-closure")
def citrust_control_remediation_closure_attestation():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Control Remediation Closure Attestation</title>
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
                    radial-gradient(circle at bottom right, rgba(255,184,107,0.10), transparent 30%),
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
                <h1>CITrust™ Control Remediation Closure Attestation</h1>

                <div class="subtitle">
                    Confirms whether control deficiencies have been remediated with enough evidence, reviewer acceptance, operating-effectiveness retest, residual-risk closure, and decision-ledger support to move the control back to attestable, conditional, redesigned, or escalated status.
                </div>

                <div class="positioning">
                    <strong>Closure-attestation boundary:</strong>
                    CITrust™ does not close ServiceNow tasks, approve access, change CMDB records, or replace human governance in this demo. This page validates whether a control remediation item can be closed from the CITrust™ assurance layer and whether the control can support certificate, passport, audit, and operational trust decisions again.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/control-deficiency-remediation-board">Deficiency Remediation</a>
                    <a href="/citrust/control-audit-defense-pack">Control Defense Pack</a>
                    <a href="/citrust/control-assurance-evidence-pack">Control Evidence Pack</a>
                    <a href="/citrust/control-assurance-attestation">Control Attestation</a>
                    <a href="/citrust/control-effectiveness-monitor">Control Effectiveness</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                    <a href="/citrust/continuous-trust-monitor">Continuous Trust</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Closure Reviews</div>
                    <div class="value">10</div>
                    <div class="note">Control deficiency remediation items awaiting closure decision.</div>
                </div>

                <div class="metric">
                    <div class="label">Close As Effective</div>
                    <div class="value" style="color: var(--green);">3</div>
                    <div class="note">Remediations with evidence, reviewer acceptance, and retest support.</div>
                </div>

                <div class="metric">
                    <div class="label">Close Conditional</div>
                    <div class="value" style="color: var(--yellow);">4</div>
                    <div class="note">Remediations that can close with residual-risk monitoring or stronger cadence.</div>
                </div>

                <div class="metric">
                    <div class="label">Retest Required</div>
                    <div class="value" style="color: var(--orange);">3</div>
                    <div class="note">Controls requiring operating-effectiveness evidence before closure.</div>
                </div>

                <div class="metric">
                    <div class="label">Closure Blocked</div>
                    <div class="value" style="color: var(--red);">2</div>
                    <div class="note">Items missing owner, evidence, reviewer, or control redesign proof.</div>
                </div>

                <div class="metric">
                    <div class="label">Redesign Needed</div>
                    <div class="value" style="color: var(--blue);">2</div>
                    <div class="note">Controls that should not close because the same weakness continues.</div>
                </div>
            </section>

            <section class="section">
                <h2>Remediation Closure Answer</h2>
                <p>
                    This page answers whether a weak CITrust™ control has really been fixed.
                </p>

                <div class="answer">
                    <strong>Current closure interpretation:</strong>
                    A control deficiency should close only when remediation evidence proves the gap has been resolved, the accountable reviewer accepts closure, the control has been retested or monitored, residual risk is controlled, and the decision ledger explains the updated assurance state. If remediation only documents intent without operating proof, closure should be blocked or marked conditional.
                </div>
            </section>

            <section class="section">
                <h2>Closure Attestation Domains</h2>
                <p>
                    CITrust™ separates remediation closure into the domains needed to prevent false closure.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Remediation Evidence</h3>
                        <p>Confirms the required proof has been attached and directly addresses the original control deficiency.</p>
                    </div>

                    <div class="card">
                        <h3>Reviewer Acceptance</h3>
                        <p>Confirms the accountable owner, reviewer, or governance function accepts the remediation result.</p>
                    </div>

                    <div class="card">
                        <h3>Operating Retest</h3>
                        <p>Confirms the control is actually working after remediation and not just documented.</p>
                    </div>

                    <div class="card">
                        <h3>Assurance State Update</h3>
                        <p>Determines whether the control becomes attestable, conditional, redesigned, escalated, or still blocked.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Control Remediation Closure Matrix</h2>
                <p>
                    This matrix shows which control deficiencies can be closed and what assurance state they move into.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Control Deficiency</th>
                            <th>Remediation Evidence</th>
                            <th>Reviewer Acceptance</th>
                            <th>Operating Retest</th>
                            <th>Residual Risk</th>
                            <th>Closure Decision</th>
                            <th>New Assurance State</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Lifecycle Closure Evidence Gate</strong></td>
                            <td>Closure evidence, access deactivation proof, lifecycle decision, decision-ledger update.</td>
                            <td><span class="badge soft-green">Accepted</span></td>
                            <td><span class="badge soft-green">Working</span></td>
                            <td>Low if gate remains mandatory.</td>
                            <td><span class="badge green">Close As Effective</span></td>
                            <td>Attestable control.</td>
                        </tr>

                        <tr>
                            <td><strong>Strong Control Benchmark Replication</strong></td>
                            <td>Minimum readiness template defined from mature CI evidence pattern.</td>
                            <td><span class="badge soft-green">Accepted</span></td>
                            <td><span class="badge soft-green">Reusable</span></td>
                            <td>Low if applied consistently.</td>
                            <td><span class="badge green">Close As Standard</span></td>
                            <td>Benchmark control model.</td>
                        </tr>

                        <tr>
                            <td><strong>Privileged Access Evidence Gap</strong></td>
                            <td>MyAccess mapping and approver evidence exist; admin/vendor procedure and access review proof still need refresh.</td>
                            <td><span class="badge soft-yellow">Access Reviewer Needed</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td>Access assurance remains conditional until proof is current.</td>
                            <td><span class="badge yellow">Close Conditional</span></td>
                            <td>Conditionally attestable access control.</td>
                        </tr>

                        <tr>
                            <td><strong>Cutover Evidence Chain Partiality</strong></td>
                            <td>Support, access, vendor, rollback, and post-change evidence remain partially complete.</td>
                            <td><span class="badge soft-yellow">Cutover Review Needed</span></td>
                            <td><span class="badge soft-yellow">Pending Post-Cutover Verification</span></td>
                            <td>Cutover trust remains conditional.</td>
                            <td><span class="badge yellow">Close With Monitoring</span></td>
                            <td>Conditional cutover control.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception Expiry Escalation Weakness</strong></td>
                            <td>Exception owner and expiry date defined; escalation owner not consistently assigned.</td>
                            <td><span class="badge soft-orange">Governance Reviewer Needed</span></td>
                            <td><span class="badge soft-orange">Retest Required</span></td>
                            <td>Expired exceptions may still become governance debt.</td>
                            <td><span class="badge orange">Do Not Close Yet</span></td>
                            <td>Retest required.</td>
                        </tr>

                        <tr>
                            <td><strong>Support and LCM Confirmation Gate Weakness</strong></td>
                            <td>Support group and LCM evidence requirement proposed but not consistently enforced.</td>
                            <td><span class="badge soft-red">Not Accepted</span></td>
                            <td><span class="badge soft-red">Not Proven</span></td>
                            <td>Support-routing ambiguity remains material.</td>
                            <td><span class="badge red">Closure Blocked</span></td>
                            <td>Redesign as mandatory gate.</td>
                        </tr>

                        <tr>
                            <td><strong>Hidden Dependency Intake Weakness</strong></td>
                            <td>Candidate creation requirement identified, but some intake remains manual.</td>
                            <td><span class="badge soft-yellow">CMDB Governance Review Needed</span></td>
                            <td><span class="badge soft-orange">Retest Required</span></td>
                            <td>Hidden dependencies may still bypass governance.</td>
                            <td><span class="badge orange">Retest Before Closure</span></td>
                            <td>Conditional intake control.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Closure Decision Logic</h2>
                <p>
                    Control remediation closure must prove the weakness is resolved, not just acknowledged.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Remediation Can Close</h3>
                        <ul>
                            <li>Original deficiency is clearly identified.</li>
                            <li>Closure evidence directly resolves the deficiency.</li>
                            <li>Control owner accepts remediation.</li>
                            <li>Operating retest confirms the control works.</li>
                            <li>Residual risk is documented and controlled.</li>
                            <li>Decision ledger records closure rationale.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Closure Must Be Blocked</h3>
                        <ul>
                            <li>Evidence only describes future intent.</li>
                            <li>No reviewer accepts the remediation.</li>
                            <li>Same deficiency still appears in active exceptions.</li>
                            <li>Control has not been retested.</li>
                            <li>Residual risk remains unclear.</li>
                            <li>Closure would create false assurance.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Closure Action Queue</h2>
                <p>
                    These actions must close before weak controls can move to an attestable state.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Closure Gap</th>
                            <th>Why It Matters</th>
                            <th>Closure Requirement</th>
                            <th>Expected Assurance Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Support and LCM gate cannot close.</td>
                            <td>Support-routing ambiguity weakens incident response, ServiceNow-readiness, and audit defense.</td>
                            <td>Enforce support group, resolver path, LCM, escalation owner, evidence location, and cadence before candidate approval.</td>
                            <td>Closure Blocked → Mandatory Gate</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">2</span></td>
                            <td>Exception expiry rule needs retest.</td>
                            <td>Expired exceptions can still become governance debt without escalation owner proof.</td>
                            <td>Assign escalation owner, update decision ledger, and retest overdue exception handling.</td>
                            <td>Retest Required → Attestable Control</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Hidden-dependency intake remains partly manual.</td>
                            <td>Operational dependencies can bypass trust review if candidate creation is not mandatory.</td>
                            <td>Force candidate record creation before exception, certificate, or trust review.</td>
                            <td>Conditional Intake → Attestable Intake</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Privileged access control can close only conditionally.</td>
                            <td>Access assurance cannot be fully defended with stale or missing admin/vendor procedure evidence.</td>
                            <td>Attach current procedure, access review proof, approver mapping, and post-access verification.</td>
                            <td>Conditional Access → Fully Attestable</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This control remediation closure attestation console is a governance assurance overlay for remediation closure, closure evidence validation, reviewer acceptance, operating-effectiveness retest, residual-risk closure, control redesign, audit defense, certificate readiness, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_CONTROL_REMEDIATION_CLOSURE_ATTESTATION_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Control Remediation Closure Attestation installed.")
