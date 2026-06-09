from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CONTROL_EFFECTIVENESS_MONITOR_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/control-effectiveness-monitor")'
ROUTE_ALIAS = '@app.route("/citrust/uplift-effectiveness")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Control Effectiveness Monitor already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CONTROL_EFFECTIVENESS_MONITOR_V1_ACTIVE
# ============================================================

@app.route("/citrust/control-effectiveness-monitor")
@app.route("/citrust/uplift-effectiveness")
def citrust_control_effectiveness_monitor():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Control Effectiveness Monitor</title>
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
                    radial-gradient(circle at top right, rgba(92,200,255,0.16), transparent 28%),
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
                <h1>CITrust™ Control Effectiveness Monitor</h1>

                <div class="subtitle">
                    Measures whether systemic control uplifts are actually reducing recurring CITrust™ failures across CI candidate intake, MyAccess evidence, support routing, lifecycle closure, evidence completeness, certificate exceptions, and continuous trust.
                </div>

                <div class="positioning">
                    <strong>Effectiveness boundary:</strong>
                    CITrust™ does not update ServiceNow, approve access, create CMDB records, or enforce live controls in this demo. This monitor evaluates whether governance controls are working by comparing exception patterns, certificate outcomes, evidence quality, and trust-state movement before and after uplift.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/systemic-control-uplift-board">Control Uplift Board</a>
                    <a href="/citrust/exception-pattern-intelligence">Exception Patterns</a>
                    <a href="/citrust/certificate-lifecycle-command-center">Certificate Command Center</a>
                    <a href="/citrust/continuous-trust-monitor">Continuous Trust</a>
                    <a href="/citrust/trust-decay-forecast">Trust Decay Forecast</a>
                    <a href="/citrust/governance-debt-register">Governance Debt</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Controls Monitored</div>
                    <div class="value">12</div>
                    <div class="note">Reusable CITrust™ controls currently tracked for operating effectiveness.</div>
                </div>

                <div class="metric">
                    <div class="label">Effective</div>
                    <div class="value" style="color: var(--green);">5</div>
                    <div class="note">Controls reducing exceptions, improving evidence quality, or preserving trust.</div>
                </div>

                <div class="metric">
                    <div class="label">Partially Effective</div>
                    <div class="value" style="color: var(--yellow);">4</div>
                    <div class="note">Controls working in some CI groups but not consistently across the population.</div>
                </div>

                <div class="metric">
                    <div class="label">Ineffective</div>
                    <div class="value" style="color: var(--red);">2</div>
                    <div class="note">Controls not reducing repeated exception or trust-decay behavior.</div>
                </div>

                <div class="metric">
                    <div class="label">Needs Redesign</div>
                    <div class="value" style="color: var(--orange);">3</div>
                    <div class="note">Controls that require clearer evidence, ownership, cadence, or escalation rules.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Escalation</div>
                    <div class="value" style="color: var(--blue);">3</div>
                    <div class="note">Controls with cross-team ownership gaps requiring leadership decision.</div>
                </div>
            </section>

            <section class="section">
                <h2>Control Effectiveness Answer</h2>
                <p>
                    This monitor answers whether the controls added after systemic pattern analysis are actually working.
                </p>

                <div class="answer">
                    <strong>Current effectiveness interpretation:</strong>
                    A control is effective only if it reduces recurrence, improves evidence quality, shortens exception closure, prevents certificate suspension, or keeps CIs continuously trusted. If the same gaps continue after uplift, the control should be redesigned, escalated, or converted into a stricter gate.
                </div>
            </section>

            <section class="section">
                <h2>Effectiveness Measurement Domains</h2>
                <p>
                    CITrust™ measures control effectiveness across the governance outcomes that matter most for CMDB trust.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Exception Reduction</h3>
                        <p>Measures whether recurring certificate exceptions reduce after control uplift is introduced.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Quality</h3>
                        <p>Measures whether required proof is complete before certificate, passport, renewal, or exception review.</p>
                    </div>

                    <div class="card">
                        <h3>Trust Stability</h3>
                        <p>Measures whether CIs remain active, renewed, certificate-ready, or passport-eligible without trust decay.</p>
                    </div>

                    <div class="card">
                        <h3>Closure Discipline</h3>
                        <p>Measures whether exceptions, remediation items, OOS closures, and certificate renewals close on time.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Control Effectiveness Matrix</h2>
                <p>
                    This matrix shows whether key uplift controls are effective, partially effective, ineffective, or needing redesign.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Control Uplift</th>
                            <th>Target Pattern</th>
                            <th>Effectiveness Signal</th>
                            <th>Observed Result</th>
                            <th>Effectiveness Rating</th>
                            <th>Control Decision</th>
                            <th>Next Governance Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Hidden-Dependency Intake Trigger</strong></td>
                            <td>Unmanaged local dependencies and backup review workstations.</td>
                            <td>Hidden dependencies should convert into CI candidates earlier.</td>
                            <td>Some dependencies are identified, but candidate creation is still manual.</td>
                            <td><span class="badge yellow">Partially Effective</span></td>
                            <td>Strengthen intake trigger.</td>
                            <td>Require candidate record before exception, certificate, or trust review can proceed.</td>
                        </tr>

                        <tr>
                            <td><strong>Privileged Access Evidence Bundle</strong></td>
                            <td>MyAccess, admin, vendor, jump path, approver group, and access-review gaps.</td>
                            <td>Access exceptions should reduce across certificate-tracked CIs.</td>
                            <td>Access evidence quality improved, but jump server and vendor procedure evidence still need refresh.</td>
                            <td><span class="badge yellow">Partially Effective</span></td>
                            <td>Upgrade to mandatory gate.</td>
                            <td>Block certificate renewal until access procedure and review proof are attached.</td>
                        </tr>

                        <tr>
                            <td><strong>Support and LCM Confirmation Gate</strong></td>
                            <td>Support group, resolver path, LCM, backup owner, and escalation gaps.</td>
                            <td>Support-routing exceptions should decline before certificate review.</td>
                            <td>Support gaps remain for operational equipment and local dependencies.</td>
                            <td><span class="badge orange">Needs Redesign</span></td>
                            <td>Escalate ownership model.</td>
                            <td>Define required support-group evidence and escalation owner before candidate review approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Lifecycle Closure Evidence Gate</strong></td>
                            <td>OOS, retired, closed, access-removal, and lifecycle-owner proof gaps.</td>
                            <td>Suspended OOS certificates should restore only after closure proof exists.</td>
                            <td>OOS evidence gaps remain blocked rather than hidden.</td>
                            <td><span class="badge green">Effective</span></td>
                            <td>Keep mandatory gate.</td>
                            <td>Continue preventing closure attestation without access deactivation proof.</td>
                        </tr>

                        <tr>
                            <td><strong>Cutover Evidence Pack Requirement</strong></td>
                            <td>Support, access, vendor, rollback, and post-cutover evidence scattered across owners.</td>
                            <td>Cutover-sensitive CIs should have one evidence chain.</td>
                            <td>BMS cutover trust remains conditional until evidence chain closes.</td>
                            <td><span class="badge yellow">Partially Effective</span></td>
                            <td>Keep conditional gate.</td>
                            <td>Require recovery attestation before moving to certificate-ready status.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception Expiry Escalation Rule</strong></td>
                            <td>Expired, aging, or repeatedly extended certificate exceptions.</td>
                            <td>Overdue exceptions should decrease and closure discipline should improve.</td>
                            <td>Overdue exceptions are now visible, but escalation ownership is not always clear.</td>
                            <td><span class="badge orange">Needs Owner Clarity</span></td>
                            <td>Add escalation owner requirement.</td>
                            <td>Every exception must have owner, expiry date, closure evidence, and escalation path.</td>
                        </tr>

                        <tr>
                            <td><strong>Strong Control Benchmark Model</strong></td>
                            <td>Replication of mature evidence model from well-governed CIs.</td>
                            <td>Other CIs should adopt stronger certificate-readiness evidence patterns.</td>
                            <td>Blue Mountain-style model provides reusable reference structure.</td>
                            <td><span class="badge green">Effective</span></td>
                            <td>Replicate as template.</td>
                            <td>Use mature CI evidence model as minimum readiness template for new candidates.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Effectiveness Decision Logic</h2>
                <p>
                    Controls should be judged by outcomes, not by their existence.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Control Is Effective</h3>
                        <ul>
                            <li>Recurring exception pattern decreases.</li>
                            <li>Evidence is available earlier in the CI lifecycle.</li>
                            <li>Certificate renewals happen with fewer conditions.</li>
                            <li>Suspended certificates reduce over time.</li>
                            <li>Trust decay is prevented before escalation.</li>
                            <li>Control owner and cadence are clear.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Control Needs Redesign</h3>
                        <ul>
                            <li>Same exception continues after uplift.</li>
                            <li>Evidence remains manual, late, or owner-dependent.</li>
                            <li>Support, access, or lifecycle accountability remains unclear.</li>
                            <li>Exceptions still expire without closure.</li>
                            <li>Certificate status improves without stronger proof.</li>
                            <li>Control lacks measurable closure criteria.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Effectiveness Improvement Queue</h2>
                <p>
                    These actions improve controls that are not yet producing strong governance outcomes.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Control Weakness</th>
                            <th>Why It Matters</th>
                            <th>Effectiveness Improvement</th>
                            <th>Expected Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden-dependency intake remains partly manual.</td>
                            <td>Unmanaged dependencies cannot become trusted without governed candidate identity.</td>
                            <td>Force hidden dependency into candidate factory before exception or certificate review.</td>
                            <td>Higher candidate capture and fewer hidden dependency exceptions.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">2</span></td>
                            <td>Support and LCM gate lacks consistent ownership evidence.</td>
                            <td>Support-routing ambiguity weakens CMDB trust and incident readiness.</td>
                            <td>Require support group, resolver path, LCM, and escalation owner before candidate review approval.</td>
                            <td>Reduced support exceptions and stronger ServiceNow-readiness.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Access evidence bundle is not always complete before renewal.</td>
                            <td>Privileged access assurance cannot be renewed with stale procedure evidence.</td>
                            <td>Block renewal if admin/vendor procedure, access review proof, and approver evidence are missing.</td>
                            <td>Fewer access-related conditional certificates.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Exception expiry escalation lacks owner clarity.</td>
                            <td>Expired exceptions become governance debt if no one owns closure.</td>
                            <td>Require owner, expiry date, escalation owner, closure evidence, and decision-ledger update for every exception.</td>
                            <td>Fewer overdue exceptions and fewer certificate suspensions.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This control effectiveness monitor is a governance assurance overlay for measuring whether CITrust™ controls actually reduce repeated exceptions, improve certificate readiness, strengthen access evidence, improve lifecycle closure, reduce hidden dependencies, stabilize continuous trust, reduce governance debt, and prevent pre-deviation risk.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_CONTROL_EFFECTIVENESS_MONITOR_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Control Effectiveness Monitor installed.")
