from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CONTROL_DEFICIENCY_REMEDIATION_BOARD_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/control-deficiency-remediation-board")'
ROUTE_ALIAS = '@app.route("/citrust/control-deficiency-board")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Control Deficiency Remediation Board already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CONTROL_DEFICIENCY_REMEDIATION_BOARD_V1_ACTIVE
# ============================================================

@app.route("/citrust/control-deficiency-remediation-board")
@app.route("/citrust/control-deficiency-board")
def citrust_control_deficiency_remediation_board():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Control Deficiency Remediation Board</title>
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
                    radial-gradient(circle at top left, rgba(255,92,112,0.16), transparent 30%),
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
                border: 1px solid rgba(255,92,112,0.38);
                background: rgba(255,92,112,0.10);
                color: #ffe5e9;
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
                <h1>CITrust™ Control Deficiency Remediation Board</h1>

                <div class="subtitle">
                    Tracks weak, conditional, or non-defensible CITrust™ controls and converts them into governed remediation actions with owners, closure evidence, escalation rules, and expected assurance outcomes.
                </div>

                <div class="positioning">
                    <strong>Remediation boundary:</strong>
                    CITrust™ does not update ServiceNow, approve access, close audit findings, or replace human governance in this demo. This board organizes control deficiencies so governance teams can remediate weak evidence, unclear ownership, failed controls, and recurring exception patterns before they damage certificate readiness or CMDB trust.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/control-audit-defense-pack">Control Defense Pack</a>
                    <a href="/citrust/control-assurance-evidence-pack">Control Evidence Pack</a>
                    <a href="/citrust/control-assurance-attestation">Control Attestation</a>
                    <a href="/citrust/control-effectiveness-monitor">Control Effectiveness</a>
                    <a href="/citrust/systemic-control-uplift-board">Control Uplift</a>
                    <a href="/citrust/remediation-board">General Remediation</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Control Deficiencies</div>
                    <div class="value">11</div>
                    <div class="note">Weak controls requiring remediation, redesign, evidence closure, or escalation.</div>
                </div>

                <div class="metric">
                    <div class="label">Critical</div>
                    <div class="value" style="color: var(--red);">3</div>
                    <div class="note">Deficiencies that can block certificate, passport, or audit defense claims.</div>
                </div>

                <div class="metric">
                    <div class="label">High Priority</div>
                    <div class="value" style="color: var(--orange);">4</div>
                    <div class="note">Deficiencies affecting access, support, lifecycle, or exception control strength.</div>
                </div>

                <div class="metric">
                    <div class="label">In Remediation</div>
                    <div class="value" style="color: var(--yellow);">5</div>
                    <div class="note">Deficiencies with owners assigned and closure evidence in progress.</div>
                </div>

                <div class="metric">
                    <div class="label">Closure Ready</div>
                    <div class="value" style="color: var(--green);">2</div>
                    <div class="note">Deficiencies ready for reviewer acceptance and decision-ledger closure.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Escalation</div>
                    <div class="value" style="color: var(--blue);">3</div>
                    <div class="note">Deficiencies requiring leadership decision due to cross-team ownership gaps.</div>
                </div>
            </section>

            <section class="section">
                <h2>Control Deficiency Answer</h2>
                <p>
                    This board answers which weak controls must be remediated before the CITrust™ assurance story is defensible.
                </p>

                <div class="answer">
                    <strong>Current remediation interpretation:</strong>
                    A weak control should not remain as a dashboard concern. It must become a governed remediation item with a named owner, evidence requirement, closure condition, escalation path, review cadence, and target assurance state. If the same deficiency repeats after remediation, the control should be redesigned as a stricter gate.
                </div>
            </section>

            <section class="section">
                <h2>Control Deficiency Domains</h2>
                <p>
                    CITrust™ groups deficiencies by the trust domain they weaken.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Evidence Deficiency</h3>
                        <p>Required proof is missing, stale, informal, incomplete, or not tied to control operation.</p>
                    </div>

                    <div class="card">
                        <h3>Ownership Deficiency</h3>
                        <p>Control owner, reviewer, escalation owner, support owner, LCM, or access owner is unclear.</p>
                    </div>

                    <div class="card">
                        <h3>Operating Deficiency</h3>
                        <p>Control exists but does not reduce exceptions, prevent trust decay, or improve readiness outcomes.</p>
                    </div>

                    <div class="card">
                        <h3>Closure Deficiency</h3>
                        <p>Exceptions, OOS items, hidden dependencies, or access gaps do not close with defensible evidence.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Control Deficiency Remediation Matrix</h2>
                <p>
                    This matrix converts control gaps into assigned remediation actions.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Control Deficiency</th>
                            <th>Impacted Assurance Area</th>
                            <th>Deficiency Type</th>
                            <th>Risk If Unresolved</th>
                            <th>Owner Needed</th>
                            <th>Remediation Decision</th>
                            <th>Closure Evidence</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Support and LCM Confirmation Gate Weakness</strong></td>
                            <td>ServiceNow-readiness, incident routing, candidate approval, certificate readiness.</td>
                            <td><span class="badge red">Ownership / Evidence</span></td>
                            <td>Support-routing ambiguity weakens operational response and audit defense.</td>
                            <td>CMDB Governance / Service Operations</td>
                            <td><span class="badge red">Redesign As Mandatory Gate</span></td>
                            <td>Support group, resolver path, LCM, escalation owner, evidence location, and review cadence.</td>
                        </tr>

                        <tr>
                            <td><strong>Privileged Access Evidence Gap</strong></td>
                            <td>MyAccess routing, admin/vendor access, jump server assurance, certificate renewal.</td>
                            <td><span class="badge orange">Evidence</span></td>
                            <td>Access assurance cannot be defended with stale procedure or review proof.</td>
                            <td>Access Governance / Infrastructure</td>
                            <td><span class="badge orange">Close Evidence Gap</span></td>
                            <td>MyAccess mapping, approver group, admin/vendor procedure, access review proof, post-access verification.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception Expiry Escalation Weakness</strong></td>
                            <td>Exception governance, certificate suspension prevention, audit defense.</td>
                            <td><span class="badge orange">Escalation</span></td>
                            <td>Expired exceptions become hidden governance debt if no escalation owner exists.</td>
                            <td>Governance Reviewer / Certificate Owner</td>
                            <td><span class="badge orange">Assign Escalation Owner</span></td>
                            <td>Exception owner, expiry date, escalation owner, closure evidence, residual-risk statement, decision-ledger update.</td>
                        </tr>

                        <tr>
                            <td><strong>Hidden Dependency Intake Weakness</strong></td>
                            <td>Candidate intake, hidden dependency control, certificate eligibility.</td>
                            <td><span class="badge red">Intake Control</span></td>
                            <td>Operational dependencies can bypass candidate review and remain invisible.</td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td><span class="badge red">Force Candidate Creation</span></td>
                            <td>Candidate record, owner, support, LCM, access path, evidence model, cadence, and verification model.</td>
                        </tr>

                        <tr>
                            <td><strong>Cutover Evidence Chain Partiality</strong></td>
                            <td>Cutover trust, BMS readiness, rollback, vendor handoff, post-change verification.</td>
                            <td><span class="badge yellow">Evidence Chain</span></td>
                            <td>Cutover-sensitive trust remains conditional and cannot be fully defended.</td>
                            <td>Cutover Owner / Infrastructure / Access Governance</td>
                            <td><span class="badge yellow">Complete Evidence Chain</span></td>
                            <td>Support group, MyAccess role, jump path, vendor handoff, rollback readiness, post-cutover verification.</td>
                        </tr>

                        <tr>
                            <td><strong>Lifecycle Closure Gate Strength</strong></td>
                            <td>OOS closure, retired CI trust, access deactivation, certificate suspension.</td>
                            <td><span class="badge green">Effective Control</span></td>
                            <td>Low if gate remains mandatory and cannot be bypassed.</td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td><span class="badge green">Maintain Control</span></td>
                            <td>Closure evidence, access deactivation proof, lifecycle decision, decision-ledger update.</td>
                        </tr>

                        <tr>
                            <td><strong>Strong Control Benchmark Replication Gap</strong></td>
                            <td>Readiness template, certificate consistency, control maturity.</td>
                            <td><span class="badge blue">Standardization</span></td>
                            <td>Mature evidence model remains isolated instead of becoming reusable standard.</td>
                            <td>Application Governance / CMDB Governance</td>
                            <td><span class="badge blue">Replicate Template</span></td>
                            <td>Minimum evidence model applied to candidate factory, certificate board, and passport review.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Deficiency Remediation Decision Logic</h2>
                <p>
                    Deficiencies must either close with evidence or become stronger controls.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Deficiency Can Be Closed</h3>
                        <ul>
                            <li>Owner is assigned.</li>
                            <li>Evidence requirement is clear.</li>
                            <li>Closure proof is attached and reviewable.</li>
                            <li>Reviewer accepts closure.</li>
                            <li>Decision ledger records closure rationale.</li>
                            <li>Control outcome improves after remediation.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Deficiency Requires Redesign</h3>
                        <ul>
                            <li>Same failure repeats after remediation.</li>
                            <li>Ownership remains unclear.</li>
                            <li>Evidence remains manual or optional.</li>
                            <li>Control does not prevent trust decay.</li>
                            <li>Exception keeps aging without closure.</li>
                            <li>Control weakness affects multiple CIs.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Control Deficiency Closure Queue</h2>
                <p>
                    These items should be closed first because they materially affect CITrust™ defensibility.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Deficiency</th>
                            <th>Why It Matters</th>
                            <th>Required Remediation</th>
                            <th>Expected Assurance Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Support and LCM control is not defensible yet.</td>
                            <td>Support-routing ambiguity weakens ServiceNow-readiness and operational response defense.</td>
                            <td>Make support group, resolver path, LCM, escalation owner, and evidence location mandatory before candidate approval.</td>
                            <td>Not Defensible → Conditionally Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Hidden dependency intake remains partly manual.</td>
                            <td>Unmanaged dependencies can bypass CI candidate review and create invisible trust debt.</td>
                            <td>Force candidate creation before exception, certificate, or trust review.</td>
                            <td>Manual Intake → Governed Candidate Intake</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Privileged access evidence remains incomplete.</td>
                            <td>Admin, vendor, jump path, and MyAccess assurance cannot be defended without current proof.</td>
                            <td>Attach MyAccess mapping, approver group, admin/vendor procedure, access review proof, and post-access verification.</td>
                            <td>Conditional Access Control → Attestable Access Control</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Cutover evidence chain remains partial.</td>
                            <td>Cutover-sensitive CI trust cannot become fully certificate-ready without complete evidence chain.</td>
                            <td>Complete support, access, vendor, rollback, and post-change verification evidence.</td>
                            <td>Conditional Cutover Trust → Certificate-Ready Defense</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This control deficiency remediation board is a governance assurance overlay for control weakness tracking, remediation ownership, closure evidence, escalation paths, control redesign, audit defense, certificate readiness, CMDB-readiness, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_CONTROL_DEFICIENCY_REMEDIATION_BOARD_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Control Deficiency Remediation Board installed.")
