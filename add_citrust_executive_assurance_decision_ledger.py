from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_EXECUTIVE_ASSURANCE_DECISION_LEDGER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/executive-assurance-decision-ledger")'
ROUTE_ALIAS = '@app.route("/citrust/assurance-decision-ledger")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Executive Assurance Decision Ledger already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_EXECUTIVE_ASSURANCE_DECISION_LEDGER_V1_ACTIVE
# ============================================================

@app.route("/citrust/executive-assurance-decision-ledger")
@app.route("/citrust/assurance-decision-ledger")
def citrust_executive_assurance_decision_ledger():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Executive Assurance Decision Ledger</title>
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
                <h1>CITrust™ Executive Assurance Decision Ledger</h1>

                <div class="subtitle">
                    Executive decision ledger documenting why leadership relied, relied conditionally, refused reliance, escalated, or blocked closure for CITrust™ controls based on evidence, maturity, remediation status, residual risk, and audit-defense strength.
                </div>

                <div class="positioning">
                    <strong>Decision-ledger boundary:</strong>
                    CITrust™ does not make final governance decisions, approve access, update ServiceNow, or replace accountable human owners in this demo. This ledger preserves the rationale behind executive assurance decisions so reliance is explainable, reviewable, and defensible.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/executive-control-action-closure-board">Action Closure Board</a>
                    <a href="/citrust/executive-control-action-tracker">Executive Action Tracker</a>
                    <a href="/citrust/executive-control-assurance-briefing">Executive Briefing</a>
                    <a href="/citrust/executive-control-assurance-register">Control Register</a>
                    <a href="/citrust/control-assurance-attestation">Control Attestation</a>
                    <a href="/citrust/control-audit-defense-pack">Control Defense Pack</a>
                    <a href="/citrust/decision-ledger">General Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Decisions Logged</div>
                    <div class="value">18</div>
                    <div class="note">Executive assurance decisions captured for review and traceability.</div>
                </div>

                <div class="metric">
                    <div class="label">Rely Decisions</div>
                    <div class="value" style="color: var(--green);">5</div>
                    <div class="note">Controls accepted for executive reliance with supporting evidence.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Reliance</div>
                    <div class="value" style="color: var(--yellow);">6</div>
                    <div class="note">Controls accepted only with limitation language or monitoring.</div>
                </div>

                <div class="metric">
                    <div class="label">Do Not Rely</div>
                    <div class="value" style="color: var(--red);">3</div>
                    <div class="note">Controls not mature or evidenced enough for reliance.</div>
                </div>

                <div class="metric">
                    <div class="label">Escalated</div>
                    <div class="value" style="color: var(--orange);">4</div>
                    <div class="note">Decisions requiring cross-functional ownership or leadership resolution.</div>
                </div>

                <div class="metric">
                    <div class="label">Audit Defensible</div>
                    <div class="value" style="color: var(--blue);">9</div>
                    <div class="note">Decisions with evidence and rationale strong enough for audit-style review.</div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Decision Ledger Answer</h2>
                <p>
                    This ledger answers why leadership made each assurance decision.
                </p>

                <div class="answer">
                    <strong>Current ledger interpretation:</strong>
                    Every executive reliance decision should explain the evidence basis, control maturity, open limitation, residual risk, owner accountability, and next action. A control should not be accepted simply because a dashboard looks green; it should be accepted only when the decision rationale can survive operational, audit, and governance review.
                </div>
            </section>

            <section class="section">
                <h2>Decision Rationale Domains</h2>
                <p>
                    CITrust™ separates executive decision rationale into the evidence elements needed to defend reliance.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Evidence Basis</h3>
                        <p>What proof supported the decision, including closure evidence, access proof, lifecycle evidence, or certificate evidence.</p>
                    </div>

                    <div class="card">
                        <h3>Reliance Boundary</h3>
                        <p>Whether leadership can rely, rely conditionally, refuse reliance, or escalate because proof is incomplete.</p>
                    </div>

                    <div class="card">
                        <h3>Residual Risk</h3>
                        <p>What risk remains after the decision, including manual controls, stale proof, weak ownership, or open exceptions.</p>
                    </div>

                    <div class="card">
                        <h3>Next Action</h3>
                        <p>What must happen next to close, strengthen, monitor, redesign, or re-attest the control.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Assurance Decision Matrix</h2>
                <p>
                    This matrix preserves the rationale behind key executive assurance decisions.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Decision Topic</th>
                            <th>Executive Decision</th>
                            <th>Evidence Basis</th>
                            <th>Decision Rationale</th>
                            <th>Residual Risk</th>
                            <th>Decision Status</th>
                            <th>Next Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Lifecycle Closure Evidence Gate</strong></td>
                            <td>Leadership can rely on the gate where closure and access-removal evidence are mandatory.</td>
                            <td>Closure evidence, access deactivation proof, lifecycle decision, decision-ledger update.</td>
                            <td>Control blocks unsupported OOS or retired CI restoration.</td>
                            <td>Low if gate remains mandatory and cannot be bypassed.</td>
                            <td><span class="badge green">Rely</span></td>
                            <td>Maintain trend review and periodic closure monitoring.</td>
                        </tr>

                        <tr>
                            <td><strong>Strong Control Benchmark Model</strong></td>
                            <td>Leadership can scale the benchmark model as a readiness standard.</td>
                            <td>Owner, support, access, lifecycle, evidence, cadence, and trust-decision alignment.</td>
                            <td>Model is mature enough to serve as a repeatable evidence template.</td>
                            <td>Risk remains if not applied consistently across new candidates.</td>
                            <td><span class="badge blue">Scale Approved</span></td>
                            <td>Apply to candidate factory, certificate board, and passport review.</td>
                        </tr>

                        <tr>
                            <td><strong>Certificate Lifecycle Governance</strong></td>
                            <td>Leadership can rely with monitoring on certificate lifecycle visibility.</td>
                            <td>Issuance, registry, renewal, suspension, restoration, exception, and passport linkage views.</td>
                            <td>Certificate state is visible and can support executive governance review.</td>
                            <td>Must continue linking certificate status to evidence freshness.</td>
                            <td><span class="badge green">Rely With Monitoring</span></td>
                            <td>Connect certificate outcomes into quarterly executive trust reporting.</td>
                        </tr>

                        <tr>
                            <td><strong>Privileged Access Evidence Bundle</strong></td>
                            <td>Leadership should rely conditionally until access procedure and review proof are current.</td>
                            <td>MyAccess mapping, approver group, admin/vendor procedure, access review proof, post-access verification.</td>
                            <td>Access assurance is improving, but full proof bundle is not always current.</td>
                            <td>Stale access procedure or missing review proof weakens defensibility.</td>
                            <td><span class="badge yellow">Conditional Reliance</span></td>
                            <td>Block renewal when full access bundle is incomplete.</td>
                        </tr>

                        <tr>
                            <td><strong>Cutover Evidence Assurance</strong></td>
                            <td>Leadership should treat cutover-sensitive CIs as conditional until recovery evidence closes.</td>
                            <td>Support group, MyAccess role, jump path, vendor handoff, rollback readiness, post-cutover verification.</td>
                            <td>Cutover visibility exists, but final readiness depends on recovery and verification proof.</td>
                            <td>Unsupported readiness claim if post-cutover verification is incomplete.</td>
                            <td><span class="badge yellow">Conditional Reliance</span></td>
                            <td>Require recovery attestation before certificate-ready status.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception Expiry Escalation Rule</strong></td>
                            <td>Leadership must escalate until exception escalation ownership is mandatory.</td>
                            <td>Exception owner, expiry date, escalation owner, closure evidence, residual-risk statement.</td>
                            <td>Exception visibility improved, but escalation owner is not consistently enforced.</td>
                            <td>Expired exceptions may become governance debt.</td>
                            <td><span class="badge orange">Escalated</span></td>
                            <td>Make escalation owner mandatory before exception approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Support and LCM Confirmation Gate</strong></td>
                            <td>Leadership should not rely until support and LCM evidence become mandatory.</td>
                            <td>Support group, resolver path, LCM, escalation owner, evidence location, cadence.</td>
                            <td>Evidence requirement exists but is not consistently enforced.</td>
                            <td>Support-routing ambiguity weakens ServiceNow-readiness and incident defense.</td>
                            <td><span class="badge red">Do Not Rely</span></td>
                            <td>Approve mandatory support and LCM evidence gate before candidate approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Hidden Dependency Intake Trigger</strong></td>
                            <td>Leadership should strengthen before reliance because intake is still partly manual.</td>
                            <td>Candidate record, owner, support, LCM, access path, evidence model, cadence, verification model.</td>
                            <td>Hidden dependencies are identified but not always forced into candidate review.</td>
                            <td>Operational dependencies can still bypass governance.</td>
                            <td><span class="badge orange">Strengthen Before Reliance</span></td>
                            <td>Force candidate creation before exception, certificate, or trust review.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Decision Ledger Logic</h2>
                <p>
                    The ledger prevents undocumented reliance and unsupported executive confidence.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Decision Is Defensible</h3>
                        <ul>
                            <li>Evidence basis is clear.</li>
                            <li>Decision owner and reviewer are identified.</li>
                            <li>Reliance boundary is stated.</li>
                            <li>Residual risk is documented.</li>
                            <li>Next action is assigned where needed.</li>
                            <li>Decision does not overstate control maturity.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Decision Is Not Defensible</h3>
                        <ul>
                            <li>Evidence is missing, stale, or informal.</li>
                            <li>Decision rationale is not recorded.</li>
                            <li>Control remains optional or manual.</li>
                            <li>Residual risk is hidden or unclear.</li>
                            <li>Reliance claim exceeds control maturity.</li>
                            <li>Leadership cannot explain why the decision was made.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Decision Follow-Up Queue</h2>
                <p>
                    These follow-up actions strengthen the weakest executive decisions first.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Decision Gap</th>
                            <th>Why It Matters</th>
                            <th>Required Follow-Up</th>
                            <th>Expected Decision Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Support and LCM decision remains not reliable.</td>
                            <td>ServiceNow-readiness cannot be defended without support ownership evidence.</td>
                            <td>Record executive approval for mandatory support group, resolver path, LCM, escalation owner, and evidence location.</td>
                            <td>Do Not Rely → Conditional Reliance</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">2</span></td>
                            <td>Hidden-dependency intake decision needs enforcement.</td>
                            <td>Manual intake can still allow invisible operational dependencies.</td>
                            <td>Record decision that all backup, audit, access, support, or review dependencies require candidate creation.</td>
                            <td>Strengthen Before Reliance → Reliable Intake</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Exception escalation decision needs mandatory owner rule.</td>
                            <td>Expired exceptions create governance debt when no escalation owner is accountable.</td>
                            <td>Record decision requiring owner, expiry date, escalation owner, closure evidence, and decision-ledger entry.</td>
                            <td>Escalated → Effective Exception Control</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Privileged access reliance is conditional.</td>
                            <td>Access trust cannot be fully defended without current access procedure and review proof.</td>
                            <td>Record renewal-blocking decision for incomplete access evidence bundle.</td>
                            <td>Conditional Reliance → Reliable Access Assurance</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This executive assurance decision ledger is a governance assurance overlay for explainable leadership reliance, conditional reliance, refusal-to-rely decisions, evidence rationale, residual-risk documentation, decision traceability, certificate readiness, CMDB-readiness, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_EXECUTIVE_ASSURANCE_DECISION_LEDGER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Executive Assurance Decision Ledger installed.")
