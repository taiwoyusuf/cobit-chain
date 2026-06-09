from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_POST_REMEDIATION_EFFECTIVENESS_REVIEW_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/post-remediation-effectiveness-review")'
ROUTE_ALIAS = '@app.route("/citrust/control-post-remediation-review")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Post-Remediation Effectiveness Review already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_POST_REMEDIATION_EFFECTIVENESS_REVIEW_V1_ACTIVE
# ============================================================

@app.route("/citrust/post-remediation-effectiveness-review")
@app.route("/citrust/control-post-remediation-review")
def citrust_post_remediation_effectiveness_review():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Post-Remediation Effectiveness Review</title>
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
                    radial-gradient(circle at top right, rgba(49,208,125,0.15), transparent 28%),
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
                <h1>CITrust™ Post-Remediation Effectiveness Review</h1>

                <div class="subtitle">
                    Reviews closed CITrust™ control remediation actions after implementation to confirm whether the fix stayed effective, reduced recurrence, improved evidence quality, prevented trust decay, and supports renewed control assurance.
                </div>

                <div class="positioning">
                    <strong>Post-remediation boundary:</strong>
                    CITrust™ does not close ServiceNow records, approve access, or replace human governance in this demo. This review validates whether a previously remediated control weakness remains fixed or whether the control must be reopened, redesigned, escalated, or converted into a mandatory gate.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/control-remediation-closure-attestation">Closure Attestation</a>
                    <a href="/citrust/control-deficiency-remediation-board">Deficiency Remediation</a>
                    <a href="/citrust/control-effectiveness-monitor">Control Effectiveness</a>
                    <a href="/citrust/control-assurance-attestation">Control Attestation</a>
                    <a href="/citrust/exception-pattern-intelligence">Exception Patterns</a>
                    <a href="/citrust/continuous-trust-monitor">Continuous Trust</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Post-Closure Reviews</div>
                    <div class="value">9</div>
                    <div class="note">Closed remediation actions under effectiveness review.</div>
                </div>

                <div class="metric">
                    <div class="label">Sustained Effective</div>
                    <div class="value" style="color: var(--green);">3</div>
                    <div class="note">Controls remained effective after remediation closure.</div>
                </div>

                <div class="metric">
                    <div class="label">Partially Sustained</div>
                    <div class="value" style="color: var(--yellow);">4</div>
                    <div class="note">Controls improved but still require monitoring or stronger cadence.</div>
                </div>

                <div class="metric">
                    <div class="label">Recurrence Detected</div>
                    <div class="value" style="color: var(--red);">2</div>
                    <div class="note">Same weakness reappeared after closure.</div>
                </div>

                <div class="metric">
                    <div class="label">Redesign Needed</div>
                    <div class="value" style="color: var(--orange);">3</div>
                    <div class="note">Controls need stricter gates, clearer ownership, or mandatory evidence.</div>
                </div>

                <div class="metric">
                    <div class="label">Re-Attestation Ready</div>
                    <div class="value" style="color: var(--blue);">4</div>
                    <div class="note">Controls ready to return to assurance attestation review.</div>
                </div>
            </section>

            <section class="section">
                <h2>Post-Remediation Effectiveness Answer</h2>
                <p>
                    This page answers whether remediation actually worked after closure.
                </p>

                <div class="answer">
                    <strong>Current review interpretation:</strong>
                    A remediation should not be considered successful only because the action was closed. It is successful when the same deficiency does not recur, the control operates consistently, required evidence appears earlier in the lifecycle, exceptions reduce, and certificate or passport readiness improves without creating new hidden risk.
                </div>
            </section>

            <section class="section">
                <h2>Post-Remediation Review Domains</h2>
                <p>
                    CITrust™ separates post-remediation review into the outcomes that prove whether remediation was durable.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Recurrence Check</h3>
                        <p>Confirms whether the same deficiency has reappeared in active exceptions, certificate reviews, or readiness gates.</p>
                    </div>

                    <div class="card">
                        <h3>Operating Proof</h3>
                        <p>Confirms the remediated control is now operating, evidenced, reviewed, and linked to trust decisions.</p>
                    </div>

                    <div class="card">
                        <h3>Outcome Improvement</h3>
                        <p>Confirms exceptions reduced, evidence quality improved, renewal became cleaner, or trust decay reduced.</p>
                    </div>

                    <div class="card">
                        <h3>Re-Attestation</h3>
                        <p>Determines whether the control can return to attestable status or must be redesigned and escalated.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Post-Remediation Effectiveness Matrix</h2>
                <p>
                    This matrix shows whether closed remediation actions stayed effective.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Remediated Control</th>
                            <th>Original Deficiency</th>
                            <th>Post-Closure Evidence</th>
                            <th>Recurrence Signal</th>
                            <th>Effectiveness Result</th>
                            <th>Review Decision</th>
                            <th>Next Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Lifecycle Closure Evidence Gate</strong></td>
                            <td>OOS and retired CI closure lacked consistent proof.</td>
                            <td>Closure evidence, access deactivation proof, lifecycle decision, and decision-ledger entry are enforced.</td>
                            <td><span class="badge soft-green">No Recurrence</span></td>
                            <td>OOS restoration remains blocked without closure proof.</td>
                            <td><span class="badge green">Sustained Effective</span></td>
                            <td>Return to control attestation as effective.</td>
                        </tr>

                        <tr>
                            <td><strong>Strong Control Benchmark Model</strong></td>
                            <td>Mature evidence model was not reused across candidate review.</td>
                            <td>Minimum readiness model now defined for owner, support, access, lifecycle, evidence, cadence, and monitoring.</td>
                            <td><span class="badge soft-green">No Recurrence</span></td>
                            <td>Benchmark can guide certificate-ready CI review.</td>
                            <td><span class="badge green">Re-Attestation Ready</span></td>
                            <td>Apply benchmark to new CI candidate reviews.</td>
                        </tr>

                        <tr>
                            <td><strong>Privileged Access Evidence Bundle</strong></td>
                            <td>Admin, vendor, jump path, and MyAccess evidence was incomplete or stale.</td>
                            <td>MyAccess mapping improved; procedure and access review proof still require refresh.</td>
                            <td><span class="badge soft-yellow">Partial Recurrence</span></td>
                            <td>Access evidence improved but remains conditional for renewal.</td>
                            <td><span class="badge yellow">Partially Sustained</span></td>
                            <td>Block renewal until current access procedure and review proof are attached.</td>
                        </tr>

                        <tr>
                            <td><strong>Cutover Evidence Pack Requirement</strong></td>
                            <td>Support, access, vendor, rollback, and post-change evidence were scattered.</td>
                            <td>Evidence pack structure exists, but BMS-style cutover evidence still needs final closure.</td>
                            <td><span class="badge soft-yellow">Watch Required</span></td>
                            <td>Improved visibility but certificate readiness remains conditional.</td>
                            <td><span class="badge yellow">Monitor After Cutover</span></td>
                            <td>Complete recovery attestation and post-cutover verification.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception Expiry Escalation Rule</strong></td>
                            <td>Expired exceptions lacked escalation-owner clarity.</td>
                            <td>Exception owner and expiry date are visible; escalation owner remains inconsistent.</td>
                            <td><span class="badge soft-orange">Recurrence Risk</span></td>
                            <td>Overdue exception visibility improved but ownership weakness remains.</td>
                            <td><span class="badge orange">Redesign Needed</span></td>
                            <td>Make escalation owner mandatory before exception approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Support and LCM Confirmation Gate</strong></td>
                            <td>Support group, resolver path, LCM, and escalation evidence remained incomplete.</td>
                            <td>Evidence requirement proposed but not consistently enforced.</td>
                            <td><span class="badge soft-red">Recurrence Detected</span></td>
                            <td>Support-routing ambiguity still appears in operational CI reviews.</td>
                            <td><span class="badge red">Reopen / Redesign</span></td>
                            <td>Convert into mandatory candidate-review gate.</td>
                        </tr>

                        <tr>
                            <td><strong>Hidden Dependency Intake Trigger</strong></td>
                            <td>Operational dependencies could bypass governed candidate review.</td>
                            <td>Candidate creation requirement identified, but some intake remains manual.</td>
                            <td><span class="badge soft-orange">Recurrence Risk</span></td>
                            <td>Hidden dependency risk reduced but not eliminated.</td>
                            <td><span class="badge orange">Strengthen Gate</span></td>
                            <td>Force candidate creation before exception or certificate review.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Post-Remediation Decision Logic</h2>
                <p>
                    Closed remediation must prove durability.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Remediation Stayed Effective</h3>
                        <ul>
                            <li>Original deficiency has not recurred.</li>
                            <li>Control evidence appears earlier and consistently.</li>
                            <li>Owner and reviewer remain clear.</li>
                            <li>Exceptions reduce or close faster.</li>
                            <li>Certificate readiness improves with stronger proof.</li>
                            <li>Decision ledger supports re-attestation.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Remediation Must Reopen</h3>
                        <ul>
                            <li>Same deficiency reappears after closure.</li>
                            <li>Evidence remains optional, manual, or late.</li>
                            <li>Support, access, lifecycle, or escalation ownership remains unclear.</li>
                            <li>Exceptions continue to age or expire.</li>
                            <li>Certificate status improves without stronger evidence.</li>
                            <li>Control closure created false assurance.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Post-Remediation Action Queue</h2>
                <p>
                    These actions decide whether controls return to attestation or reopen for redesign.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Post-Closure Finding</th>
                            <th>Why It Matters</th>
                            <th>Required Action</th>
                            <th>Expected Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Support and LCM weakness recurred after closure.</td>
                            <td>ServiceNow-readiness and incident routing remain weak if support evidence is not mandatory.</td>
                            <td>Reopen and redesign as mandatory candidate-review gate.</td>
                            <td>Recurring Weakness → Mandatory Gate</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">2</span></td>
                            <td>Exception expiry escalation still lacks owner clarity.</td>
                            <td>Expired exceptions can still become hidden governance debt.</td>
                            <td>Make escalation owner mandatory before exception approval.</td>
                            <td>Redesign Needed → Attestable Escalation Rule</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Hidden dependency intake remains partly manual.</td>
                            <td>Operational dependencies can still bypass governed CI candidate review.</td>
                            <td>Force candidate creation before trust review.</td>
                            <td>Strengthened Intake → Candidate Review Ready</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Privileged access evidence improved but remains conditional.</td>
                            <td>Access trust cannot be renewed cleanly without current procedure and review proof.</td>
                            <td>Attach current admin/vendor procedure, access review proof, approver mapping, and post-access verification.</td>
                            <td>Partially Sustained → Fully Attestable</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This post-remediation effectiveness review is a governance assurance overlay for validating remediation durability, recurrence detection, operating-effectiveness retest, control redesign, assurance re-attestation, certificate readiness, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_POST_REMEDIATION_EFFECTIVENESS_REVIEW_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Post-Remediation Effectiveness Review installed.")
