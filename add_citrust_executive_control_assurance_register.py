from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_EXECUTIVE_CONTROL_ASSURANCE_REGISTER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/executive-control-assurance-register")'
ROUTE_ALIAS = '@app.route("/citrust/control-assurance-register")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Executive Control Assurance Register already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_EXECUTIVE_CONTROL_ASSURANCE_REGISTER_V1_ACTIVE
# ============================================================

@app.route("/citrust/executive-control-assurance-register")
@app.route("/citrust/control-assurance-register")
def citrust_executive_control_assurance_register():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Executive Control Assurance Register</title>
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
                <h1>CITrust™ Executive Control Assurance Register</h1>

                <div class="subtitle">
                    Executive register of CITrust™ controls showing assurance state, maturity level, evidence status, deficiency status, remediation status, control owner, executive action, and readiness for certificate, passport, CMDB, access, lifecycle, and audit-defense reliance.
                </div>

                <div class="positioning">
                    <strong>Register boundary:</strong>
                    CITrust™ does not update ServiceNow, approve access, certify compliance, or replace human governance in this demo. This register gives leadership a single view of which controls can be trusted, which remain conditional, which require remediation, and which must not be relied on yet.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/control-maturity-uplift-roadmap">Maturity Roadmap</a>
                    <a href="/citrust/control-assurance-maturity-scorecard">Maturity Scorecard</a>
                    <a href="/citrust/control-assurance-attestation">Control Attestation</a>
                    <a href="/citrust/control-effectiveness-monitor">Control Effectiveness</a>
                    <a href="/citrust/control-deficiency-remediation-board">Deficiency Remediation</a>
                    <a href="/citrust/control-audit-defense-pack">Control Defense Pack</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Registered Controls</div>
                    <div class="value">16</div>
                    <div class="note">Controls tracked in the executive assurance register.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Reliable</div>
                    <div class="value" style="color: var(--green);">5</div>
                    <div class="note">Controls leadership can rely on with evidence-backed confidence.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Reliance</div>
                    <div class="value" style="color: var(--yellow);">6</div>
                    <div class="note">Controls usable only with limitation language or residual-risk disclosure.</div>
                </div>

                <div class="metric">
                    <div class="label">Do Not Rely</div>
                    <div class="value" style="color: var(--red);">2</div>
                    <div class="note">Controls not mature enough for executive assurance claims.</div>
                </div>

                <div class="metric">
                    <div class="label">Needs Executive Action</div>
                    <div class="value" style="color: var(--orange);">4</div>
                    <div class="note">Controls requiring cross-team ownership or decision escalation.</div>
                </div>

                <div class="metric">
                    <div class="label">Audit-Ready Controls</div>
                    <div class="value" style="color: var(--blue);">6</div>
                    <div class="note">Controls ready to support audit-style questioning and evidence review.</div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Register Answer</h2>
                <p>
                    This register answers which CITrust™ controls leadership can rely on today.
                </p>

                <div class="answer">
                    <strong>Current executive interpretation:</strong>
                    Leadership can rely on controls that are evidence-backed, operating, reviewed, and producing measurable assurance outcomes. Controls that still depend on manual follow-up, incomplete ownership, stale access evidence, or conditional cutover proof should remain visible as conditional or not reliable until remediation and re-attestation are complete.
                </div>
            </section>

            <section class="section">
                <h2>Executive Assurance Domains</h2>
                <p>
                    CITrust™ organizes the register around the control questions executives care about.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Can We Rely?</h3>
                        <p>Shows whether the control is reliable, conditional, weak, not reliable, or executive-ready.</p>
                    </div>

                    <div class="card">
                        <h3>What Is The Proof?</h3>
                        <p>Connects each control to evidence, operating effectiveness, maturity, and audit-defense support.</p>
                    </div>

                    <div class="card">
                        <h3>What Needs Action?</h3>
                        <p>Identifies ownership gaps, evidence gaps, remediation needs, escalation needs, and maturity uplift actions.</p>
                    </div>

                    <div class="card">
                        <h3>What Should Not Be Claimed?</h3>
                        <p>Prevents leadership from overstating readiness where the control is not yet defensible.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Control Assurance Register Matrix</h2>
                <p>
                    This matrix gives a single executive view of control assurance status.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Control</th>
                            <th>Assurance State</th>
                            <th>Maturity</th>
                            <th>Evidence Status</th>
                            <th>Deficiency / Risk</th>
                            <th>Executive Decision</th>
                            <th>Next Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Lifecycle Closure Evidence Gate</strong></td>
                            <td><span class="badge green">Reliable</span></td>
                            <td>Level 4 - Effective</td>
                            <td>Closure evidence, access deactivation proof, lifecycle decision, and decision-ledger update.</td>
                            <td>Low if mandatory gate remains enforced.</td>
                            <td><span class="badge green">Rely</span></td>
                            <td>Optimize with periodic closure trend review.</td>
                        </tr>

                        <tr>
                            <td><strong>Strong Control Benchmark Model</strong></td>
                            <td><span class="badge blue">Executive Ready</span></td>
                            <td>Level 5 - Optimized</td>
                            <td>Mature owner, support, access, lifecycle, evidence, cadence, and trust decision model.</td>
                            <td>Risk is low if replicated consistently.</td>
                            <td><span class="badge blue">Scale</span></td>
                            <td>Apply as minimum evidence standard for candidate factory, certificate board, and passport review.</td>
                        </tr>

                        <tr>
                            <td><strong>Certificate Lifecycle Governance</strong></td>
                            <td><span class="badge green">Reliable</span></td>
                            <td>Level 4 - Effective</td>
                            <td>Issuance, registry, renewal, suspension, restoration, exception, and passport linkage views.</td>
                            <td>Needs executive linkage into trust register for full optimization.</td>
                            <td><span class="badge green">Rely With Monitoring</span></td>
                            <td>Connect certificate outcomes to executive trust reporting.</td>
                        </tr>

                        <tr>
                            <td><strong>Privileged Access Evidence Bundle</strong></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Level 3 - Operating</td>
                            <td>MyAccess and approver evidence improving; admin/vendor procedure and access review proof still conditional.</td>
                            <td>Access assurance remains conditional where procedure or review proof is stale.</td>
                            <td><span class="badge yellow">Rely With Limitation</span></td>
                            <td>Block renewal if full access evidence bundle is missing.</td>
                        </tr>

                        <tr>
                            <td><strong>Cutover Evidence Pack Requirement</strong></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Level 3 - Operating</td>
                            <td>Support, access, vendor, rollback, and post-change evidence are bundled but not always closed.</td>
                            <td>Cutover-sensitive trust cannot be fully claimed until post-cutover verification is complete.</td>
                            <td><span class="badge yellow">Rely Only As Conditional</span></td>
                            <td>Require recovery attestation and post-cutover verification before certificate-ready status.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception Expiry Escalation Rule</strong></td>
                            <td><span class="badge orange">Weak / Defined</span></td>
                            <td>Level 2 - Defined</td>
                            <td>Exception owner and expiry date visible; escalation owner inconsistent.</td>
                            <td>Expired exceptions may become governance debt without escalation-owner discipline.</td>
                            <td><span class="badge orange">Executive Action Needed</span></td>
                            <td>Make escalation owner mandatory before exception approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Support and LCM Confirmation Gate</strong></td>
                            <td><span class="badge red">Not Reliable</span></td>
                            <td>Level 1 - Ad Hoc</td>
                            <td>Support group, resolver path, LCM, and escalation evidence remain inconsistent.</td>
                            <td>Support-routing ambiguity weakens ServiceNow-readiness and operational incident defense.</td>
                            <td><span class="badge red">Do Not Rely Yet</span></td>
                            <td>Make support and LCM evidence mandatory before candidate approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Hidden Dependency Intake Trigger</strong></td>
                            <td><span class="badge orange">Partially Reliable</span></td>
                            <td>Level 2 - Defined</td>
                            <td>Candidate creation requirement identified but still partly manual.</td>
                            <td>Operational dependencies can still bypass candidate review.</td>
                            <td><span class="badge orange">Strengthen Before Reliance</span></td>
                            <td>Force candidate creation before exception, certificate, or trust review.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Executive Reliance Decision Logic</h2>
                <p>
                    Control reliance must match the strength of evidence and maturity.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Leadership Can Rely</h3>
                        <ul>
                            <li>Control has current evidence.</li>
                            <li>Control owner and reviewer are clear.</li>
                            <li>Control is operating consistently.</li>
                            <li>Deficiencies are closed or controlled.</li>
                            <li>Maturity level supports the assurance claim.</li>
                            <li>Decision ledger supports executive reliance.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Leadership Should Not Rely Yet</h3>
                        <ul>
                            <li>Evidence is missing, stale, or informal.</li>
                            <li>Ownership or escalation path is unclear.</li>
                            <li>Control weakness recurs after remediation.</li>
                            <li>Exception closure remains conditional.</li>
                            <li>Control is ad hoc or only defined.</li>
                            <li>Reliance would overstate operational trust.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Action Queue</h2>
                <p>
                    These actions should be escalated first because they affect executive reliance.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Executive Issue</th>
                            <th>Why It Matters</th>
                            <th>Required Leadership Action</th>
                            <th>Expected Assurance Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Support and LCM gate is not reliable.</td>
                            <td>ServiceNow-readiness and incident-routing trust cannot be defended without support evidence.</td>
                            <td>Require support group, resolver path, LCM, escalation owner, evidence location, and cadence before candidate approval.</td>
                            <td>Not Reliable → Operating Control</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">2</span></td>
                            <td>Hidden dependency intake is still partly manual.</td>
                            <td>Operational dependencies can bypass trust review and create invisible governance debt.</td>
                            <td>Mandate CI candidate creation for backup, audit, access, support, or review dependencies.</td>
                            <td>Partially Reliable → Effective Intake Control</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Exception expiry escalation needs ownership discipline.</td>
                            <td>Expired exceptions become audit weaknesses when no one owns closure.</td>
                            <td>Require exception owner, escalation owner, expiry date, closure evidence, and decision-ledger update.</td>
                            <td>Weak / Defined → Effective Control</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Privileged access assurance remains conditional.</td>
                            <td>Access trust cannot be fully defended without current procedure and review proof.</td>
                            <td>Block renewal unless MyAccess mapping, approver group, admin/vendor procedure, access review proof, and post-access verification are attached.</td>
                            <td>Conditional → Reliable Access Assurance</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This executive control assurance register is a governance assurance overlay for executive reliance, control assurance status, evidence defensibility, maturity visibility, remediation tracking, certificate support, CMDB-readiness, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_EXECUTIVE_CONTROL_ASSURANCE_REGISTER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Executive Control Assurance Register installed.")
