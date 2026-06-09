from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CONTROL_ASSURANCE_EVIDENCE_PACK_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/control-assurance-evidence-pack")'
ROUTE_ALIAS = '@app.route("/citrust/control-evidence-pack")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Control Assurance Evidence Pack already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CONTROL_ASSURANCE_EVIDENCE_PACK_V1_ACTIVE
# ============================================================

@app.route("/citrust/control-assurance-evidence-pack")
@app.route("/citrust/control-evidence-pack")
def citrust_control_assurance_evidence_pack():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Control Assurance Evidence Pack</title>
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
                    radial-gradient(circle at top right, rgba(180,156,255,0.13), transparent 28%),
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
                <h1>CITrust™ Control Assurance Evidence Pack</h1>

                <div class="subtitle">
                    Evidence-pack layer for CITrust™ control assurance, showing the proof required to support control attestation, operating effectiveness, exception closure, certificate readiness, CMDB-readiness, access governance, lifecycle trust, and audit defensibility.
                </div>

                <div class="positioning">
                    <strong>Evidence-pack boundary:</strong>
                    CITrust™ does not store official records, update ServiceNow, approve access, or replace controlled repositories in this demo. This page defines the evidence required to support a defensible control assurance statement before leadership relies on the control layer.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/control-assurance-attestation">Control Attestation</a>
                    <a href="/citrust/control-effectiveness-monitor">Control Effectiveness</a>
                    <a href="/citrust/systemic-control-uplift-board">Control Uplift</a>
                    <a href="/citrust/evidence-pack-builder">CI Evidence Pack</a>
                    <a href="/citrust/evidence-lineage">Evidence Lineage</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Evidence Packs</div>
                    <div class="value">12</div>
                    <div class="note">Control evidence packs required for assurance attestation.</div>
                </div>

                <div class="metric">
                    <div class="label">Complete</div>
                    <div class="value" style="color: var(--green);">5</div>
                    <div class="note">Evidence packs with sufficient proof for attestation.</div>
                </div>

                <div class="metric">
                    <div class="label">Partial</div>
                    <div class="value" style="color: var(--yellow);">4</div>
                    <div class="note">Evidence packs requiring additional proof or reviewer acceptance.</div>
                </div>

                <div class="metric">
                    <div class="label">Missing Critical Proof</div>
                    <div class="value" style="color: var(--red);">2</div>
                    <div class="note">Evidence packs that cannot support control assurance.</div>
                </div>

                <div class="metric">
                    <div class="label">Reviewer Needed</div>
                    <div class="value" style="color: var(--orange);">6</div>
                    <div class="note">Evidence requiring owner, access, lifecycle, or governance review.</div>
                </div>

                <div class="metric">
                    <div class="label">Audit-Ready Packs</div>
                    <div class="value" style="color: var(--blue);">4</div>
                    <div class="note">Evidence packs that can support inspection-style questioning.</div>
                </div>
            </section>

            <section class="section">
                <h2>Control Evidence Pack Answer</h2>
                <p>
                    This page answers what evidence must exist before a CITrust™ control can be trusted.
                </p>

                <div class="answer">
                    <strong>Current evidence-pack interpretation:</strong>
                    A control cannot be attested because it is documented. It can be attested only when the evidence proves the control exists, has an accountable owner, is operating on schedule, reduces the intended exception pattern, supports certificate decisions, and has a clear escalation path when it fails.
                </div>
            </section>

            <section class="section">
                <h2>Evidence Pack Domains</h2>
                <p>
                    CITrust™ organizes control evidence into domains that support both operational and audit defensibility.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Control Design Evidence</h3>
                        <p>Defines the purpose, scope, owner, trigger, frequency, and required proof for the control.</p>
                    </div>

                    <div class="card">
                        <h3>Operating Evidence</h3>
                        <p>Shows the control was performed, reviewed, and used in certificate or trust decisions.</p>
                    </div>

                    <div class="card">
                        <h3>Outcome Evidence</h3>
                        <p>Shows whether the control reduced exceptions, improved readiness, or prevented trust decay.</p>
                    </div>

                    <div class="card">
                        <h3>Exception Evidence</h3>
                        <p>Shows how control failures, exceptions, overdue actions, and escalations were handled.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Control Assurance Evidence Matrix</h2>
                <p>
                    This matrix defines the minimum evidence required to support control assurance attestation.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Control</th>
                            <th>Required Evidence</th>
                            <th>Evidence Status</th>
                            <th>Reviewer</th>
                            <th>Assurance Value</th>
                            <th>Evidence Decision</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Lifecycle Closure Evidence Gate</strong></td>
                            <td>Closure evidence, access deactivation proof, lifecycle owner, closure decision, decision-ledger update.</td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td>Prevents false closure and unsupported certificate restoration.</td>
                            <td><span class="badge green">Evidence Pack Accepted</span></td>
                            <td>Maintain as mandatory closure gate.</td>
                        </tr>

                        <tr>
                            <td><strong>Strong Control Benchmark Model</strong></td>
                            <td>Owner, support group, access route, lifecycle status, evidence pack, cadence, trust decision, monitoring proof.</td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td>Application Governance / CMDB Governance</td>
                            <td>Provides repeatable model for certificate-ready CIs.</td>
                            <td><span class="badge green">Use As Template</span></td>
                            <td>Replicate across candidate review and certificate readiness.</td>
                        </tr>

                        <tr>
                            <td><strong>Privileged Access Evidence Bundle</strong></td>
                            <td>MyAccess role, approver group, admin/vendor procedure, jump path, access review proof, post-access verification.</td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td>Access Governance / Infrastructure</td>
                            <td>Supports access defensibility before certificate renewal or passport linkage.</td>
                            <td><span class="badge yellow">Evidence Pack Conditional</span></td>
                            <td>Attach current admin/vendor procedure and access review proof.</td>
                        </tr>

                        <tr>
                            <td><strong>Cutover Evidence Pack Requirement</strong></td>
                            <td>Support group, MyAccess role, jump path, vendor handoff, rollback readiness, post-cutover verification.</td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td>Cutover Owner / Infrastructure / Access Governance</td>
                            <td>Supports BMS and cutover-sensitive certificate readiness.</td>
                            <td><span class="badge yellow">Evidence Pack Conditional</span></td>
                            <td>Complete cutover evidence chain and recovery attestation.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception Expiry Escalation Rule</strong></td>
                            <td>Exception owner, expiry date, escalation owner, closure evidence, residual-risk statement, decision-ledger update.</td>
                            <td><span class="badge soft-orange">Reviewer Gap</span></td>
                            <td>Governance Reviewer / Certificate Owner</td>
                            <td>Prevents stale exceptions becoming hidden governance debt.</td>
                            <td><span class="badge orange">Evidence Owner Needed</span></td>
                            <td>Assign escalation owner before exception approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Support and LCM Confirmation Gate</strong></td>
                            <td>Support group, resolver path, LCM assignment, escalation owner, evidence location, review cadence.</td>
                            <td><span class="badge soft-red">Missing Critical Proof</span></td>
                            <td>CMDB Governance / Service Operations</td>
                            <td>Supports ServiceNow-readiness and incident-routing confidence.</td>
                            <td><span class="badge red">Evidence Pack Not Accepted</span></td>
                            <td>Require support and LCM evidence before candidate approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Hidden-Dependency Intake Trigger</strong></td>
                            <td>Candidate record, owner, support group, LCM, access path, evidence model, cadence, verification model.</td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td>Prevents unmanaged operational dependencies bypassing trust review.</td>
                            <td><span class="badge yellow">Evidence Pack Conditional</span></td>
                            <td>Force candidate record creation before exception or certificate review.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Evidence Pack Decision Logic</h2>
                <p>
                    Evidence must prove both design and operation.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Evidence Pack Can Support Attestation</h3>
                        <ul>
                            <li>Control purpose and trigger are defined.</li>
                            <li>Control owner and reviewer are named.</li>
                            <li>Required evidence is current and reviewable.</li>
                            <li>Operating result is visible.</li>
                            <li>Exception pathway is documented.</li>
                            <li>Decision ledger captures the assurance rationale.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Evidence Pack Cannot Support Attestation</h3>
                        <ul>
                            <li>Evidence is missing, stale, or informal.</li>
                            <li>Control owner is unclear.</li>
                            <li>Proof does not show the control operated.</li>
                            <li>Outcome is not measurable.</li>
                            <li>Exception handling is undefined.</li>
                            <li>Attestation would rely on assumption instead of evidence.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Evidence Pack Closure Queue</h2>
                <p>
                    These evidence gaps must close before control attestation can be defended.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Evidence Gap</th>
                            <th>Why It Matters</th>
                            <th>Required Evidence</th>
                            <th>Expected Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Support and LCM confirmation gate lacks critical proof.</td>
                            <td>Support-routing ambiguity weakens ServiceNow-readiness and operational trust.</td>
                            <td>Support group, resolver path, LCM, escalation owner, evidence location, and cadence.</td>
                            <td>Evidence Pack Not Accepted → Conditional Acceptance</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">2</span></td>
                            <td>Exception expiry escalation rule lacks escalation owner evidence.</td>
                            <td>Expired exceptions become governance debt when ownership is unclear.</td>
                            <td>Exception owner, expiry date, escalation owner, closure evidence, and decision-ledger update.</td>
                            <td>Reviewer Gap → Evidence Accepted</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">3</span></td>
                            <td>Privileged access evidence bundle is incomplete.</td>
                            <td>Access assurance cannot support renewal without current procedure and review proof.</td>
                            <td>MyAccess mapping, approver group, admin/vendor procedure, access review proof, and post-access verification.</td>
                            <td>Conditional → Evidence Pack Accepted</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Hidden-dependency intake evidence remains partial.</td>
                            <td>Unmanaged dependencies can bypass trust review without candidate evidence.</td>
                            <td>Candidate record, owner, support, access, evidence, cadence, and verification model.</td>
                            <td>Partial → Candidate Review Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This control assurance evidence pack is a governance assurance overlay for control evidence, operating proof, owner accountability, control effectiveness, exception evidence, certificate support, audit readiness, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_CONTROL_ASSURANCE_EVIDENCE_PACK_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Control Assurance Evidence Pack installed.")
