from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CONTROL_MATURITY_UPLIFT_ROADMAP_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/control-maturity-uplift-roadmap")'
ROUTE_ALIAS = '@app.route("/citrust/maturity-uplift-roadmap")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Control Maturity Uplift Roadmap already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CONTROL_MATURITY_UPLIFT_ROADMAP_V1_ACTIVE
# ============================================================

@app.route("/citrust/control-maturity-uplift-roadmap")
@app.route("/citrust/maturity-uplift-roadmap")
def citrust_control_maturity_uplift_roadmap():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Control Maturity Uplift Roadmap</title>
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
                    radial-gradient(circle at top right, rgba(180,156,255,0.15), transparent 28%),
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
                <h1>CITrust™ Control Maturity Uplift Roadmap</h1>

                <div class="subtitle">
                    Executive roadmap for moving CITrust™ controls from weak, manual, or conditional states into repeatable, evidence-backed, effective, optimized, and executive-defensible governance controls.
                </div>

                <div class="positioning">
                    <strong>Roadmap boundary:</strong>
                    CITrust™ does not update ServiceNow, approve access, enforce live controls, or replace human governance in this demo. This roadmap prioritizes which controls need uplift, what evidence must be added, who should own the action, and what maturity state the control should reach.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/control-assurance-maturity-scorecard">Maturity Scorecard</a>
                    <a href="/citrust/post-remediation-effectiveness-review">Post-Remediation Review</a>
                    <a href="/citrust/control-remediation-closure-attestation">Closure Attestation</a>
                    <a href="/citrust/control-deficiency-remediation-board">Deficiency Remediation</a>
                    <a href="/citrust/control-effectiveness-monitor">Control Effectiveness</a>
                    <a href="/citrust/systemic-control-uplift-board">Control Uplift</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Roadmap Items</div>
                    <div class="value">14</div>
                    <div class="note">Control maturity uplift actions currently tracked.</div>
                </div>

                <div class="metric">
                    <div class="label">Immediate Uplifts</div>
                    <div class="value" style="color: var(--red);">4</div>
                    <div class="note">Weak controls that can materially affect CI trust and audit defense.</div>
                </div>

                <div class="metric">
                    <div class="label">Near-Term Uplifts</div>
                    <div class="value" style="color: var(--orange);">5</div>
                    <div class="note">Controls that need evidence closure, reviewer clarity, or operating retest.</div>
                </div>

                <div class="metric">
                    <div class="label">Optimization Items</div>
                    <div class="value" style="color: var(--green);">3</div>
                    <div class="note">Effective controls ready for monitoring, scaling, and executive reuse.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Decisions</div>
                    <div class="value" style="color: var(--blue);">4</div>
                    <div class="note">Items requiring cross-team ownership or leadership prioritization.</div>
                </div>

                <div class="metric">
                    <div class="label">Target Maturity</div>
                    <div class="value" style="color: var(--purple);">4.3</div>
                    <div class="note">Desired average maturity after roadmap execution.</div>
                </div>
            </section>

            <section class="section">
                <h2>Maturity Uplift Roadmap Answer</h2>
                <p>
                    This roadmap answers how CITrust™ moves from current maturity to executive-ready governance assurance.
                </p>

                <div class="answer">
                    <strong>Current roadmap interpretation:</strong>
                    CITrust™ should focus first on controls that repeatedly weaken operational trust: support and LCM ownership, hidden-dependency intake, privileged access evidence, exception escalation, and cutover evidence closure. Mature controls such as lifecycle closure and benchmark evidence models should be scaled as reusable standards.
                </div>
            </section>

            <section class="section">
                <h2>Roadmap Phases</h2>
                <p>
                    CITrust™ maturity uplift should be sequenced so weak controls become stable before executive assurance claims are made.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3><span class="badge red">Phase 1</span><br>Stabilize</h3>
                        <p>Stop weak controls from creating false assurance by blocking unsupported certificate, exception, or closure decisions.</p>
                    </div>

                    <div class="card">
                        <h3><span class="badge orange">Phase 2</span><br>Define</h3>
                        <p>Document required owner, evidence, trigger, cadence, reviewer, escalation, and closure rules.</p>
                    </div>

                    <div class="card">
                        <h3><span class="badge yellow">Phase 3</span><br>Operate</h3>
                        <p>Run controls consistently across CI candidates, certificates, exceptions, remediation, and passport review.</p>
                    </div>

                    <div class="card">
                        <h3><span class="badge green">Phase 4</span><br>Prove</h3>
                        <p>Confirm controls reduce exceptions, improve readiness, prevent trust decay, and support audit defense.</p>
                    </div>

                    <div class="card">
                        <h3><span class="badge blue">Phase 5</span><br>Optimize</h3>
                        <p>Turn mature controls into reusable executive-ready patterns with continuous monitoring and trend review.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Control Maturity Uplift Roadmap Matrix</h2>
                <p>
                    This matrix translates maturity gaps into sequenced actions.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Control Area</th>
                            <th>Current Maturity</th>
                            <th>Target Maturity</th>
                            <th>Uplift Required</th>
                            <th>Owner / Reviewer</th>
                            <th>Roadmap Priority</th>
                            <th>Completion Evidence</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Support and LCM Confirmation Gate</strong></td>
                            <td><span class="badge red">Level 1 - Ad Hoc</span></td>
                            <td><span class="badge yellow">Level 3 - Operating</span></td>
                            <td>Convert support group, resolver path, LCM, escalation owner, evidence location, and cadence into mandatory candidate-review fields.</td>
                            <td>CMDB Governance / Service Operations</td>
                            <td><span class="badge red">Phase 1 Stabilize</span></td>
                            <td>Candidate cannot advance without support and LCM evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Hidden Dependency Intake Trigger</strong></td>
                            <td><span class="badge orange">Level 2 - Defined</span></td>
                            <td><span class="badge green">Level 4 - Effective</span></td>
                            <td>Force candidate creation before exception, certificate, or trust review for backup, audit, access, support, or review dependencies.</td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td><span class="badge red">Phase 1 Stabilize</span></td>
                            <td>Hidden dependency creates candidate record with owner, support, access, evidence, cadence, and verification model.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception Expiry Escalation Rule</strong></td>
                            <td><span class="badge orange">Level 2 - Defined</span></td>
                            <td><span class="badge green">Level 4 - Effective</span></td>
                            <td>Make escalation owner, expiry date, closure evidence, residual-risk statement, and decision-ledger update mandatory.</td>
                            <td>Governance Reviewer / Certificate Owner</td>
                            <td><span class="badge orange">Phase 2 Define</span></td>
                            <td>No exception can remain open without owner, expiry, escalation, and closure evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Privileged Access Evidence Bundle</strong></td>
                            <td><span class="badge yellow">Level 3 - Operating</span></td>
                            <td><span class="badge green">Level 4 - Effective</span></td>
                            <td>Block renewal when MyAccess mapping, approver group, admin/vendor procedure, access review proof, or post-access verification is missing.</td>
                            <td>Access Governance / Infrastructure</td>
                            <td><span class="badge orange">Phase 2 Define</span></td>
                            <td>Certificate renewal requires current access proof bundle.</td>
                        </tr>

                        <tr>
                            <td><strong>Cutover Evidence Pack Requirement</strong></td>
                            <td><span class="badge yellow">Level 3 - Operating</span></td>
                            <td><span class="badge green">Level 4 - Effective</span></td>
                            <td>Require support, access, vendor, rollback, and post-change verification evidence before certificate-ready status.</td>
                            <td>Cutover Owner / Infrastructure / Access Governance</td>
                            <td><span class="badge yellow">Phase 3 Operate</span></td>
                            <td>Recovery attestation and post-cutover verification complete.</td>
                        </tr>

                        <tr>
                            <td><strong>Lifecycle Closure Evidence Gate</strong></td>
                            <td><span class="badge green">Level 4 - Effective</span></td>
                            <td><span class="badge blue">Level 5 - Optimized</span></td>
                            <td>Add periodic closure trend review and continuous monitoring of OOS, retired, and access-removal proof.</td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td><span class="badge green">Phase 4 Prove</span></td>
                            <td>Closure trend report shows no unsupported restorations.</td>
                        </tr>

                        <tr>
                            <td><strong>Strong Control Benchmark Model</strong></td>
                            <td><span class="badge blue">Level 5 - Optimized</span></td>
                            <td><span class="badge blue">Level 5 - Scale</span></td>
                            <td>Use as the minimum evidence standard for candidate factory, certificate review, passport review, and control audit defense.</td>
                            <td>Application Governance / CMDB Governance</td>
                            <td><span class="badge blue">Phase 5 Optimize</span></td>
                            <td>Benchmark model adopted as standard readiness template.</td>
                        </tr>

                        <tr>
                            <td><strong>Certificate Lifecycle Governance</strong></td>
                            <td><span class="badge green">Level 4 - Effective</span></td>
                            <td><span class="badge blue">Level 5 - Optimized</span></td>
                            <td>Connect issuance, registry, renewal, suspension, restoration, exceptions, and passport linkage into executive trust reporting.</td>
                            <td>Certificate Owner / Governance Leadership</td>
                            <td><span class="badge blue">Phase 5 Optimize</span></td>
                            <td>Executive certificate lifecycle summary supports leadership assurance review.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Roadmap Decision Logic</h2>
                <p>
                    Uplift priority should be based on risk, recurrence, and assurance dependency.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Prioritize Immediately</h3>
                        <ul>
                            <li>Control weakness affects certificate readiness or audit defense.</li>
                            <li>Same gap recurs after remediation.</li>
                            <li>Ownership, access, lifecycle, or support evidence is unclear.</li>
                            <li>Hidden dependency can bypass candidate review.</li>
                            <li>Exception can expire without escalation owner.</li>
                            <li>Executive assurance would be overstated without uplift.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Optimize Later</h3>
                        <ul>
                            <li>Control is already operating effectively.</li>
                            <li>Evidence is complete and repeatable.</li>
                            <li>Control reduces exception or trust-decay patterns.</li>
                            <li>Reviewer and owner are clear.</li>
                            <li>Decision ledger supports current state.</li>
                            <li>Primary need is scale, monitoring, or executive reporting.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Uplift Action Queue</h2>
                <p>
                    These actions should be handled first to move CITrust™ toward executive-ready assurance.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Roadmap Action</th>
                            <th>Why It Matters</th>
                            <th>Required Uplift</th>
                            <th>Target Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Make support and LCM evidence mandatory.</td>
                            <td>ServiceNow-readiness and incident-routing trust remain weak without support evidence.</td>
                            <td>Block candidate approval without support group, resolver path, LCM, escalation owner, and evidence location.</td>
                            <td>Ad Hoc → Operating Control</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Force hidden-dependency candidate creation.</td>
                            <td>Unmanaged dependencies cannot be trusted, certified, or exception-managed.</td>
                            <td>Any operational backup, audit, access, support, or review dependency must become a CI candidate.</td>
                            <td>Defined → Effective Control</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Strengthen exception expiry escalation.</td>
                            <td>Expired exceptions become governance debt without owner and escalation discipline.</td>
                            <td>Require owner, expiry, escalation owner, closure evidence, residual-risk statement, and decision-ledger entry.</td>
                            <td>Defined → Effective Control</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Upgrade privileged access evidence gate.</td>
                            <td>Access trust cannot be fully defended while procedure and review evidence remain stale.</td>
                            <td>Block certificate renewal until the full access evidence bundle is attached.</td>
                            <td>Operating → Effective Control</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This control maturity uplift roadmap is a governance assurance overlay for maturity planning, control uplift sequencing, executive prioritization, evidence strengthening, ownership clarification, certificate assurance, CMDB-readiness, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_CONTROL_MATURITY_UPLIFT_ROADMAP_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Control Maturity Uplift Roadmap installed.")
