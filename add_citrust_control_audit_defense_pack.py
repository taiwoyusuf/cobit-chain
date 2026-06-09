from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CONTROL_AUDIT_DEFENSE_PACK_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/control-audit-defense-pack")'
ROUTE_ALIAS = '@app.route("/citrust/control-defense-pack")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Control Audit Defense Pack already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CONTROL_AUDIT_DEFENSE_PACK_V1_ACTIVE
# ============================================================

@app.route("/citrust/control-audit-defense-pack")
@app.route("/citrust/control-defense-pack")
def citrust_control_audit_defense_pack():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Control Audit Defense Pack</title>
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
                    radial-gradient(circle at top right, rgba(247,201,72,0.14), transparent 28%),
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
                <h1>CITrust™ Control Audit Defense Pack</h1>

                <div class="subtitle">
                    Converts CITrust™ control evidence into an audit-defense package that shows what can be defended, what remains conditional, what must be escalated, and what leadership should not claim until proof is complete.
                </div>

                <div class="positioning">
                    <strong>Audit-defense boundary:</strong>
                    CITrust™ does not replace official audit records, ServiceNow, MyAccess, validation systems, or human governance. This page organizes control assurance evidence into inspection-style defense statements, proof references, risk limits, and required closure actions.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/control-assurance-evidence-pack">Control Evidence Pack</a>
                    <a href="/citrust/control-assurance-attestation">Control Attestation</a>
                    <a href="/citrust/control-effectiveness-monitor">Control Effectiveness</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                    <a href="/citrust/audit-question-bank">Audit Question Bank</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Defense Statements</div>
                    <div class="value">18</div>
                    <div class="note">Inspection-style statements prepared for control assurance defense.</div>
                </div>

                <div class="metric">
                    <div class="label">Fully Defensible</div>
                    <div class="value" style="color: var(--green);">7</div>
                    <div class="note">Claims supported by evidence, owner, cadence, and outcome proof.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditionally Defensible</div>
                    <div class="value" style="color: var(--yellow);">6</div>
                    <div class="note">Claims that need limitation language or residual-risk disclosure.</div>
                </div>

                <div class="metric">
                    <div class="label">Do Not Claim</div>
                    <div class="value" style="color: var(--red);">3</div>
                    <div class="note">Statements not supported by current evidence.</div>
                </div>

                <div class="metric">
                    <div class="label">Reviewer Needed</div>
                    <div class="value" style="color: var(--orange);">5</div>
                    <div class="note">Claims requiring access, lifecycle, CMDB, or governance reviewer acceptance.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Ready</div>
                    <div class="value" style="color: var(--blue);">4</div>
                    <div class="note">Statements ready for leadership-level assurance summary.</div>
                </div>
            </section>

            <section class="section">
                <h2>Audit Defense Answer</h2>
                <p>
                    This pack answers what CITrust™ can safely defend if leadership, QA, audit, infrastructure, or CMDB governance asks for evidence.
                </p>

                <div class="answer">
                    <strong>Current defense interpretation:</strong>
                    CITrust™ should defend only what the evidence proves. Strong controls can be described as operating effectively. Partial controls must be described as conditional with clear closure actions. Missing controls should not be represented as effective because that creates false assurance and weakens inspection defensibility.
                </div>
            </section>

            <section class="section">
                <h2>Audit Defense Domains</h2>
                <p>
                    CITrust™ organizes defense language around the questions an auditor or executive reviewer is likely to ask.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Control Design Defense</h3>
                        <p>Explains what the control is designed to prevent, who owns it, and what evidence proves its design.</p>
                    </div>

                    <div class="card">
                        <h3>Operating Effectiveness Defense</h3>
                        <p>Explains whether the control actually reduced exceptions, improved readiness, or prevented trust decay.</p>
                    </div>

                    <div class="card">
                        <h3>Exception Defense</h3>
                        <p>Explains how exceptions, expiry, closure, escalation, and residual risk are governed.</p>
                    </div>

                    <div class="card">
                        <h3>Boundary Defense</h3>
                        <p>Clarifies what CITrust™ does not do, preventing confusion with ServiceNow, MyAccess, or official records.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Control Audit Defense Matrix</h2>
                <p>
                    This matrix maps control topics to defensible claims, supporting evidence, and approved language.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Audit Topic</th>
                            <th>Defensible Statement</th>
                            <th>Evidence Supporting Statement</th>
                            <th>Defense Status</th>
                            <th>What Not To Claim</th>
                            <th>Reviewer</th>
                            <th>Closure Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Lifecycle Closure Control</strong></td>
                            <td>OOS and retired CI trust is blocked until closure evidence and access deactivation proof exist.</td>
                            <td>Closure evidence, access deactivation proof, lifecycle decision, decision-ledger update.</td>
                            <td><span class="badge green">Fully Defensible</span></td>
                            <td>Do not claim closure is complete where proof is missing.</td>
                            <td>Lifecycle / Access Governance</td>
                            <td>Maintain mandatory closure gate.</td>
                        </tr>

                        <tr>
                            <td><strong>Privileged Access Evidence</strong></td>
                            <td>Access trust requires MyAccess mapping, approver evidence, admin/vendor procedure, jump path, and access review proof.</td>
                            <td>MyAccess role, approver group, admin/vendor procedure, access review proof, post-access verification.</td>
                            <td><span class="badge yellow">Conditionally Defensible</span></td>
                            <td>Do not claim all access routes are fully defended until procedure and review proof are current.</td>
                            <td>Access Governance / Infrastructure</td>
                            <td>Attach current admin/vendor procedure and access review proof.</td>
                        </tr>

                        <tr>
                            <td><strong>Cutover Evidence Chain</strong></td>
                            <td>Cutover-sensitive CI trust remains conditional until support, access, vendor, rollback, and post-change checks close.</td>
                            <td>Support group, MyAccess role, jump path, vendor handoff, rollback readiness, post-cutover verification.</td>
                            <td><span class="badge yellow">Conditionally Defensible</span></td>
                            <td>Do not claim cutover readiness is fully defensible until the evidence chain is complete.</td>
                            <td>Cutover Owner / Infrastructure</td>
                            <td>Complete recovery attestation and post-cutover verification.</td>
                        </tr>

                        <tr>
                            <td><strong>Support and LCM Control</strong></td>
                            <td>Support-routing assurance requires support group, resolver path, LCM, escalation owner, and evidence location.</td>
                            <td>Support group evidence, resolver path, LCM assignment, escalation owner, evidence location.</td>
                            <td><span class="badge red">Not Defensible Yet</span></td>
                            <td>Do not claim support-routing is controlled where support and LCM evidence are incomplete.</td>
                            <td>CMDB Governance / Service Operations</td>
                            <td>Redesign as mandatory candidate-review gate.</td>
                        </tr>

                        <tr>
                            <td><strong>Hidden Dependency Intake</strong></td>
                            <td>Operational dependencies should become governed CI candidates before certificate or exception review.</td>
                            <td>Candidate record, owner, support group, LCM, access path, evidence model, cadence, verification model.</td>
                            <td><span class="badge yellow">Conditionally Defensible</span></td>
                            <td>Do not claim hidden dependencies are controlled until candidate creation is mandatory.</td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td>Force candidate creation before trust review.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception Expiry Governance</strong></td>
                            <td>Certificate exceptions must have owner, expiry date, closure evidence, escalation path, and decision-ledger entry.</td>
                            <td>Exception register, expiry monitor, closure attestation, residual-risk statement, decision ledger.</td>
                            <td><span class="badge orange">Reviewer Required</span></td>
                            <td>Do not claim expired exceptions are controlled without escalation-owner clarity.</td>
                            <td>Governance Reviewer / Certificate Owner</td>
                            <td>Assign escalation owner before exception approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Strong Control Benchmark</strong></td>
                            <td>Mature CI evidence patterns can be reused as a minimum readiness model for other CIs.</td>
                            <td>Owner, support, access, lifecycle, evidence pack, cadence, and trust decision alignment.</td>
                            <td><span class="badge green">Fully Defensible</span></td>
                            <td>Do not claim all CIs match this model yet.</td>
                            <td>Application Governance / CMDB Governance</td>
                            <td>Use as standard CI readiness template.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Audit Defense Decision Logic</h2>
                <p>
                    CITrust™ defense language must match the strength of the evidence.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Safe To Defend</h3>
                        <ul>
                            <li>Evidence is current and reviewable.</li>
                            <li>Control owner and reviewer are clear.</li>
                            <li>Control outcome is measurable.</li>
                            <li>Exception pathway is documented.</li>
                            <li>Decision ledger supports the claim.</li>
                            <li>Boundary language is clear and accurate.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Do Not Defend Yet</h3>
                        <ul>
                            <li>Evidence is missing, stale, or informal.</li>
                            <li>Control owner is unclear.</li>
                            <li>Control has not reduced repeated failures.</li>
                            <li>Exception closure is unsupported.</li>
                            <li>Statement would overstate readiness.</li>
                            <li>Claim depends on assumption instead of evidence.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Audit Defense Closure Queue</h2>
                <p>
                    These gaps must close before the control assurance story is fully defensible.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Defense Gap</th>
                            <th>Why It Matters</th>
                            <th>Closure Requirement</th>
                            <th>Expected Defense Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Support and LCM control is not defensible yet.</td>
                            <td>Support-routing ambiguity weakens ServiceNow-readiness and operational response defense.</td>
                            <td>Require support group, resolver path, LCM, escalation owner, evidence location, and cadence.</td>
                            <td>Not Defensible → Conditionally Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">2</span></td>
                            <td>Exception expiry governance needs escalation owner clarity.</td>
                            <td>Expired exceptions become audit weaknesses if no one owns closure.</td>
                            <td>Assign exception owner, expiry date, escalation owner, closure evidence, and decision-ledger update.</td>
                            <td>Reviewer Required → Fully Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">3</span></td>
                            <td>Privileged access evidence remains conditional.</td>
                            <td>Access assurance cannot be defended without current procedure and review proof.</td>
                            <td>Attach MyAccess mapping, approver group, admin/vendor procedure, access review proof, and post-access verification.</td>
                            <td>Conditional → Fully Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Cutover evidence chain remains conditional.</td>
                            <td>Cutover-sensitive trust must be defended with support, access, vendor, rollback, and verification proof.</td>
                            <td>Complete cutover evidence pack and recovery attestation.</td>
                            <td>Conditional → Certificate-Ready Defense</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This control audit defense pack is a governance assurance overlay for audit defense statements, evidence-backed claims, control assurance language, exception defense, certificate defense, CMDB-readiness defense, access governance defense, lifecycle defense, decision-ledger support, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_CONTROL_AUDIT_DEFENSE_PACK_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Control Audit Defense Pack installed.")
