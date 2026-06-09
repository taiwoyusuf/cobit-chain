from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CONTROL_ASSURANCE_ATTESTATION_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/control-assurance-attestation")'
ROUTE_ALIAS = '@app.route("/citrust/control-attestation")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Control Assurance Attestation already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CONTROL_ASSURANCE_ATTESTATION_V1_ACTIVE
# ============================================================

@app.route("/citrust/control-assurance-attestation")
@app.route("/citrust/control-attestation")
def citrust_control_assurance_attestation():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Control Assurance Attestation</title>
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
                <h1>CITrust™ Control Assurance Attestation</h1>

                <div class="subtitle">
                    Formal attestation layer confirming whether CITrust™ controls are operating effectively enough to support certificate readiness, ServiceNow-style CMDB-readiness, MyAccess routing, lifecycle trust, audit defensibility, and continuous CI governance.
                </div>

                <div class="positioning">
                    <strong>Attestation boundary:</strong>
                    CITrust™ does not update ServiceNow, approve access, certify legal compliance, or replace human governance. This console gives leadership a governed view of whether the assurance controls themselves can be trusted based on evidence, outcomes, exceptions, and operating effectiveness.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/control-effectiveness-monitor">Control Effectiveness</a>
                    <a href="/citrust/systemic-control-uplift-board">Control Uplift Board</a>
                    <a href="/citrust/exception-pattern-intelligence">Exception Patterns</a>
                    <a href="/citrust/certificate-lifecycle-command-center">Certificate Command Center</a>
                    <a href="/citrust/continuous-trust-monitor">Continuous Trust</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Controls For Attestation</div>
                    <div class="value">12</div>
                    <div class="note">CITrust™ controls evaluated for assurance sign-off.</div>
                </div>

                <div class="metric">
                    <div class="label">Attestable</div>
                    <div class="value" style="color: var(--green);">5</div>
                    <div class="note">Controls with evidence, owner, cadence, and outcome support.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional</div>
                    <div class="value" style="color: var(--yellow);">4</div>
                    <div class="note">Controls working but requiring closure, owner clarity, or stronger evidence.</div>
                </div>

                <div class="metric">
                    <div class="label">Not Attestable</div>
                    <div class="value" style="color: var(--red);">2</div>
                    <div class="note">Controls that cannot be accepted due to missing evidence or recurring failure.</div>
                </div>

                <div class="metric">
                    <div class="label">Reviewer Required</div>
                    <div class="value" style="color: var(--orange);">6</div>
                    <div class="note">Controls needing owner, access, lifecycle, or governance reviewer acceptance.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Sign-Off</div>
                    <div class="value" style="color: var(--blue);">3</div>
                    <div class="note">Controls with cross-functional impact requiring leadership acknowledgment.</div>
                </div>
            </section>

            <section class="section">
                <h2>Control Assurance Attestation Answer</h2>
                <p>
                    This console answers whether the control layer behind CITrust™ is strong enough to rely on.
                </p>

                <div class="answer">
                    <strong>Current attestation interpretation:</strong>
                    CITrust™ controls should only be attested when the control has a clear owner, defined evidence requirement, measurable effectiveness signal, review cadence, exception pathway, and decision-ledger rationale. A control that exists but does not reduce repeated failures should not be treated as operating effectively.
                </div>
            </section>

            <section class="section">
                <h2>Control Assurance Domains</h2>
                <p>
                    CITrust™ separates control attestation into the assurance domains needed to defend the governance model.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Evidence Assurance</h3>
                        <p>Confirms control evidence exists, is current, is reviewable, and supports the control claim.</p>
                    </div>

                    <div class="card">
                        <h3>Operating Assurance</h3>
                        <p>Confirms the control is reducing exceptions, improving readiness, or preventing trust decay.</p>
                    </div>

                    <div class="card">
                        <h3>Owner Assurance</h3>
                        <p>Confirms control owner, reviewer, escalation owner, and accountability model are clear.</p>
                    </div>

                    <div class="card">
                        <h3>Continuity Assurance</h3>
                        <p>Confirms cadence, monitoring, drift detection, renewal, and exception pathways keep the control active.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Control Assurance Attestation Matrix</h2>
                <p>
                    This matrix shows whether each systemic CITrust™ control can be formally attested.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Control</th>
                            <th>Control Purpose</th>
                            <th>Evidence Basis</th>
                            <th>Effectiveness Signal</th>
                            <th>Reviewer</th>
                            <th>Attestation Decision</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Lifecycle Closure Evidence Gate</strong></td>
                            <td>Prevents OOS, retired, or closed CIs from being restored without closure and access-removal proof.</td>
                            <td>Closure evidence, access deactivation proof, lifecycle decision, decision-ledger update.</td>
                            <td>OOS gaps remain blocked instead of being hidden.</td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td><span class="badge green">Attestable</span></td>
                            <td>Maintain as mandatory gate.</td>
                        </tr>

                        <tr>
                            <td><strong>Strong Control Benchmark Model</strong></td>
                            <td>Uses mature CI evidence patterns as a reusable readiness template.</td>
                            <td>Owner, support, access, lifecycle, evidence, cadence, and trust decision alignment.</td>
                            <td>Provides repeatable model for certificate-ready CIs.</td>
                            <td>Application Governance / CMDB Governance</td>
                            <td><span class="badge green">Attestable</span></td>
                            <td>Replicate as minimum readiness template.</td>
                        </tr>

                        <tr>
                            <td><strong>Privileged Access Evidence Bundle</strong></td>
                            <td>Ensures MyAccess, admin, vendor, jump path, and access review evidence support trust decisions.</td>
                            <td>MyAccess role, approver group, admin/vendor procedure, access review proof, post-access verification.</td>
                            <td>Access evidence improved but still inconsistent for jump/vendor procedure evidence.</td>
                            <td>Access Governance / Infrastructure</td>
                            <td><span class="badge yellow">Conditionally Attestable</span></td>
                            <td>Block renewal when access procedure or review proof is missing.</td>
                        </tr>

                        <tr>
                            <td><strong>Cutover Evidence Pack Requirement</strong></td>
                            <td>Bundles support, access, vendor, rollback, and post-cutover evidence into one trust chain.</td>
                            <td>Support group, MyAccess role, jump path, vendor handoff, rollback readiness, post-cutover verification.</td>
                            <td>Cutover trust remains conditional until evidence chain closes.</td>
                            <td>Cutover Owner / Infrastructure / Access Governance</td>
                            <td><span class="badge yellow">Conditionally Attestable</span></td>
                            <td>Require recovery attestation before certificate-ready status.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception Expiry Escalation Rule</strong></td>
                            <td>Prevents stale certificate exceptions from becoming hidden governance debt.</td>
                            <td>Exception owner, expiry date, closure evidence, escalation owner, decision-ledger entry.</td>
                            <td>Overdue exceptions are visible, but escalation ownership needs stronger definition.</td>
                            <td>Governance Reviewer / Certificate Owner</td>
                            <td><span class="badge orange">Needs Reviewer Clarity</span></td>
                            <td>Require escalation owner before exception approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Support and LCM Confirmation Gate</strong></td>
                            <td>Confirms support group, resolver path, LCM, and escalation owner before trust decisions.</td>
                            <td>Support group evidence, resolver path, LCM assignment, escalation owner, evidence location.</td>
                            <td>Support gaps still recur for operational equipment and local dependencies.</td>
                            <td>CMDB Governance / Service Operations</td>
                            <td><span class="badge red">Not Yet Attestable</span></td>
                            <td>Redesign control with mandatory ownership evidence before candidate approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Hidden-Dependency Intake Trigger</strong></td>
                            <td>Forces operational dependencies into governed CI candidate review.</td>
                            <td>Candidate record, owner, support group, LCM, access path, evidence, cadence, verification model.</td>
                            <td>Some dependencies are identified, but candidate creation remains manual.</td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td><span class="badge yellow">Conditionally Attestable</span></td>
                            <td>Force candidate creation before exception, certificate, or trust review.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Control Attestation Decision Logic</h2>
                <p>
                    A control should be attested only when it can be defended with evidence and outcomes.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Control Can Be Attested</h3>
                        <ul>
                            <li>Control owner is assigned.</li>
                            <li>Evidence requirement is defined.</li>
                            <li>Evidence is current and reviewable.</li>
                            <li>Control reduces recurrence or prevents trust decay.</li>
                            <li>Exception and escalation path are clear.</li>
                            <li>Decision ledger records attestation rationale.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Control Cannot Be Attested</h3>
                        <ul>
                            <li>Control exists only as an idea or informal practice.</li>
                            <li>Evidence is missing, stale, or not tied to outcome.</li>
                            <li>Repeated failures continue after control uplift.</li>
                            <li>Owner, reviewer, or escalation path is unclear.</li>
                            <li>Control lacks measurable closure criteria.</li>
                            <li>Attestation would create false confidence.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Control Attestation Closure Queue</h2>
                <p>
                    These actions must close before weak controls can be attested.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Attestation Gap</th>
                            <th>Why It Matters</th>
                            <th>Closure Requirement</th>
                            <th>Expected Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Support and LCM gate is not yet attestable.</td>
                            <td>Support-routing ambiguity weakens ServiceNow-readiness and operational trust.</td>
                            <td>Require support group, resolver path, LCM, escalation owner, and evidence location before candidate approval.</td>
                            <td>Not Attestable → Conditionally Attestable</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">2</span></td>
                            <td>Exception expiry rule lacks escalation owner clarity.</td>
                            <td>Expired exceptions become governance debt if no one owns closure.</td>
                            <td>Require exception owner, expiry date, escalation owner, closure evidence, and decision-ledger update.</td>
                            <td>Needs Reviewer Clarity → Attestable</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">3</span></td>
                            <td>Access evidence bundle remains inconsistent.</td>
                            <td>Privileged access assurance cannot be defended with missing procedure or review proof.</td>
                            <td>Block renewal if MyAccess mapping, admin/vendor procedure, and access review proof are missing.</td>
                            <td>Conditionally Attestable → Attestable</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Hidden-dependency intake still allows manual delay.</td>
                            <td>Unmanaged dependencies can bypass candidate review and create invisible risk.</td>
                            <td>Force candidate record creation before exception, certificate, or trust review.</td>
                            <td>Conditional → Attestable Intake Control</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This control assurance attestation console is a governance assurance overlay for attesting control effectiveness, evidence sufficiency, reviewer accountability, operating effectiveness, control maturity, certificate support, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_CONTROL_ASSURANCE_ATTESTATION_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Control Assurance Attestation installed.")
