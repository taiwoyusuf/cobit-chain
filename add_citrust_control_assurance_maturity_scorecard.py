from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CONTROL_ASSURANCE_MATURITY_SCORECARD_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/control-assurance-maturity-scorecard")'
ROUTE_ALIAS = '@app.route("/citrust/control-maturity-scorecard")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Control Assurance Maturity Scorecard already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CONTROL_ASSURANCE_MATURITY_SCORECARD_V1_ACTIVE
# ============================================================

@app.route("/citrust/control-assurance-maturity-scorecard")
@app.route("/citrust/control-maturity-scorecard")
def citrust_control_assurance_maturity_scorecard():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Control Assurance Maturity Scorecard</title>
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
                    radial-gradient(circle at top left, rgba(180,156,255,0.18), transparent 30%),
                    radial-gradient(circle at top right, rgba(92,200,255,0.15), transparent 28%),
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
                grid-template-columns: repeat(5, 1fr);
                gap: 16px;
                margin-top: 16px;
            }

            .card {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 18px;
                min-height: 150px;
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
                <h1>CITrust™ Control Assurance Maturity Scorecard</h1>

                <div class="subtitle">
                    Executive maturity scorecard for CITrust™ controls, showing whether each assurance control is ad hoc, defined, operating, effective, optimized, or executive-ready across CI intake, access governance, support routing, lifecycle closure, exception governance, remediation, and certificate assurance.
                </div>

                <div class="positioning">
                    <strong>Maturity boundary:</strong>
                    CITrust™ does not update ServiceNow, approve access, enforce live controls, or replace human governance in this demo. This scorecard assesses the maturity of the governance assurance layer so leadership can see where controls are reliable, conditional, immature, or ready for executive defense.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/post-remediation-effectiveness-review">Post-Remediation Review</a>
                    <a href="/citrust/control-remediation-closure-attestation">Closure Attestation</a>
                    <a href="/citrust/control-deficiency-remediation-board">Deficiency Remediation</a>
                    <a href="/citrust/control-assurance-attestation">Control Attestation</a>
                    <a href="/citrust/control-effectiveness-monitor">Control Effectiveness</a>
                    <a href="/citrust/certificate-lifecycle-command-center">Certificate Command Center</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Average Maturity</div>
                    <div class="value" style="color: var(--blue);">3.2</div>
                    <div class="note">Average maturity across current CITrust™ control population.</div>
                </div>

                <div class="metric">
                    <div class="label">Optimized Controls</div>
                    <div class="value" style="color: var(--green);">3</div>
                    <div class="note">Controls that are effective, repeatable, evidenced, and executive-ready.</div>
                </div>

                <div class="metric">
                    <div class="label">Operating Controls</div>
                    <div class="value" style="color: var(--yellow);">5</div>
                    <div class="note">Controls that operate but still require stronger evidence or owner clarity.</div>
                </div>

                <div class="metric">
                    <div class="label">Defined Only</div>
                    <div class="value" style="color: var(--orange);">3</div>
                    <div class="note">Controls documented but not yet consistently proven effective.</div>
                </div>

                <div class="metric">
                    <div class="label">Ad Hoc / Weak</div>
                    <div class="value" style="color: var(--red);">2</div>
                    <div class="note">Controls still relying on manual follow-up, informal ownership, or incomplete evidence.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Ready</div>
                    <div class="value" style="color: var(--purple);">4</div>
                    <div class="note">Controls ready to support leadership assurance statements.</div>
                </div>
            </section>

            <section class="section">
                <h2>Control Maturity Answer</h2>
                <p>
                    This scorecard answers how mature the CITrust™ control system is.
                </p>

                <div class="answer">
                    <strong>Current maturity interpretation:</strong>
                    The CITrust™ control layer is strongest where lifecycle closure, mature evidence templates, and certificate governance are evidence-backed and repeatable. It remains less mature where support routing, hidden-dependency intake, escalation ownership, and privileged access evidence still depend on manual closure or conditional review.
                </div>
            </section>

            <section class="section">
                <h2>Maturity Levels</h2>
                <p>
                    CITrust™ maturity levels show how much confidence leadership can place in each control.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3><span class="badge red">1</span><br>Ad Hoc</h3>
                        <p>Control exists informally, depends on individuals, lacks repeatable evidence, and cannot support strong assurance.</p>
                    </div>

                    <div class="card">
                        <h3><span class="badge orange">2</span><br>Defined</h3>
                        <p>Control purpose is documented, but evidence, owner, cadence, and operating proof are still incomplete.</p>
                    </div>

                    <div class="card">
                        <h3><span class="badge yellow">3</span><br>Operating</h3>
                        <p>Control is active and producing evidence, but performance is inconsistent or conditional.</p>
                    </div>

                    <div class="card">
                        <h3><span class="badge green">4</span><br>Effective</h3>
                        <p>Control reduces exceptions, prevents trust decay, supports certificate decisions, and is reviewable.</p>
                    </div>

                    <div class="card">
                        <h3><span class="badge blue">5</span><br>Optimized</h3>
                        <p>Control is repeatable, measured, continuously monitored, executive-ready, and reusable across CI populations.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Control Assurance Maturity Matrix</h2>
                <p>
                    This matrix scores core CITrust™ controls by maturity, defensibility, and next improvement action.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Control Area</th>
                            <th>Current Maturity</th>
                            <th>Evidence Strength</th>
                            <th>Operating Strength</th>
                            <th>Executive Defensibility</th>
                            <th>Maturity Decision</th>
                            <th>Next Uplift</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Lifecycle Closure Evidence Gate</strong></td>
                            <td><span class="badge green">Level 4 - Effective</span></td>
                            <td>Closure evidence, access deactivation proof, lifecycle decision, decision-ledger update.</td>
                            <td>Blocks unsupported OOS restoration and false closure.</td>
                            <td><span class="badge green">Defensible</span></td>
                            <td>Keep as mandatory gate.</td>
                            <td>Move toward optimized monitoring with periodic closure trend review.</td>
                        </tr>

                        <tr>
                            <td><strong>Strong Control Benchmark Model</strong></td>
                            <td><span class="badge blue">Level 5 - Optimized</span></td>
                            <td>Owner, support, access, lifecycle, evidence, cadence, and trust decision are aligned.</td>
                            <td>Reusable readiness template for certificate-ready CIs.</td>
                            <td><span class="badge blue">Executive Ready</span></td>
                            <td>Use as standard evidence model.</td>
                            <td>Apply to candidate factory, certificate board, and passport review.</td>
                        </tr>

                        <tr>
                            <td><strong>Privileged Access Evidence Bundle</strong></td>
                            <td><span class="badge yellow">Level 3 - Operating</span></td>
                            <td>MyAccess and approver evidence improving; admin/vendor procedure and access review proof still conditional.</td>
                            <td>Works partially but renewal remains conditional where proof is stale.</td>
                            <td><span class="badge yellow">Conditionally Defensible</span></td>
                            <td>Continue as operating control.</td>
                            <td>Block renewal if access procedure and review proof are missing.</td>
                        </tr>

                        <tr>
                            <td><strong>Cutover Evidence Pack Requirement</strong></td>
                            <td><span class="badge yellow">Level 3 - Operating</span></td>
                            <td>Support, access, vendor, rollback, and post-change evidence are bundled but not always closed.</td>
                            <td>Improves cutover visibility but still requires recovery attestation.</td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Keep as conditional gate.</td>
                            <td>Require post-cutover verification before certificate-ready status.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception Expiry Escalation Rule</strong></td>
                            <td><span class="badge orange">Level 2 - Defined</span></td>
                            <td>Exception owner and expiry date visible; escalation owner inconsistent.</td>
                            <td>Overdue exceptions are visible but escalation discipline is not mature.</td>
                            <td><span class="badge orange">Limited Defense</span></td>
                            <td>Upgrade control design.</td>
                            <td>Make escalation owner mandatory before exception approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Support and LCM Confirmation Gate</strong></td>
                            <td><span class="badge red">Level 1 - Ad Hoc</span></td>
                            <td>Support group, resolver path, LCM, and escalation evidence remain inconsistent.</td>
                            <td>Support-routing ambiguity still recurs after remediation.</td>
                            <td><span class="badge red">Not Defensible</span></td>
                            <td>Redesign as mandatory gate.</td>
                            <td>Require support and LCM evidence before candidate approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Hidden Dependency Intake Trigger</strong></td>
                            <td><span class="badge orange">Level 2 - Defined</span></td>
                            <td>Candidate creation requirement identified but still partly manual.</td>
                            <td>Hidden dependency risk reduced but not eliminated.</td>
                            <td><span class="badge orange">Partially Defensible</span></td>
                            <td>Strengthen intake rule.</td>
                            <td>Force candidate creation before exception, certificate, or trust review.</td>
                        </tr>

                        <tr>
                            <td><strong>Certificate Lifecycle Governance</strong></td>
                            <td><span class="badge green">Level 4 - Effective</span></td>
                            <td>Issuance, registry, renewal, suspension, restoration, and exception pathways are visible.</td>
                            <td>Provides structured certificate-state governance.</td>
                            <td><span class="badge green">Defensible</span></td>
                            <td>Maintain lifecycle discipline.</td>
                            <td>Connect lifecycle outcomes to executive trust register and passport renewal.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Maturity Decision Logic</h2>
                <p>
                    A control should move up the maturity scale only when evidence and outcomes justify it.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Move Control Up</h3>
                        <ul>
                            <li>Evidence is complete, current, and reviewable.</li>
                            <li>Control owner and reviewer are clear.</li>
                            <li>Control operates consistently across CIs.</li>
                            <li>Exceptions reduce or close faster.</li>
                            <li>Certificate readiness improves with stronger proof.</li>
                            <li>Decision ledger supports the maturity rating.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Hold Or Move Down</h3>
                        <ul>
                            <li>Evidence remains optional, stale, or manual.</li>
                            <li>Owner, reviewer, or escalation path is unclear.</li>
                            <li>Same deficiency recurs after remediation.</li>
                            <li>Control does not prevent trust decay.</li>
                            <li>Certificate status improves without stronger proof.</li>
                            <li>Maturity rating would create false confidence.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Maturity Uplift Queue</h2>
                <p>
                    These actions improve the weakest maturity areas first.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Maturity Gap</th>
                            <th>Why It Matters</th>
                            <th>Required Uplift</th>
                            <th>Target Maturity</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Support and LCM gate is still ad hoc.</td>
                            <td>ServiceNow-readiness and operational incident defense remain weak without support evidence.</td>
                            <td>Make support group, resolver path, LCM, escalation owner, evidence location, and cadence mandatory.</td>
                            <td>Level 1 → Level 3 Operating</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">2</span></td>
                            <td>Hidden dependency intake is defined but not fully enforced.</td>
                            <td>Unmanaged dependencies can still bypass candidate review.</td>
                            <td>Force candidate creation before exception, certificate, or trust review.</td>
                            <td>Level 2 → Level 4 Effective</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Exception expiry escalation lacks mandatory escalation owner.</td>
                            <td>Expired exceptions become governance debt when closure accountability is weak.</td>
                            <td>Require exception owner, escalation owner, closure evidence, expiry date, and decision-ledger update.</td>
                            <td>Level 2 → Level 4 Effective</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access evidence bundle operates conditionally.</td>
                            <td>Access trust cannot become fully defensible while procedure and review proof remain stale.</td>
                            <td>Block renewal until MyAccess mapping, approver group, admin/vendor procedure, and access review proof are attached.</td>
                            <td>Level 3 → Level 4 Effective</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This control assurance maturity scorecard is a governance assurance overlay for control maturity, executive readiness, evidence maturity, operating maturity, remediation maturity, certificate governance maturity, audit defense maturity, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_CONTROL_ASSURANCE_MATURITY_SCORECARD_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Control Assurance Maturity Scorecard installed.")
