from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_SYSTEMIC_CONTROL_UPLIFT_BOARD_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/systemic-control-uplift-board")'
ROUTE_ALIAS = '@app.route("/citrust/control-uplift")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Systemic Control Uplift Board already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_SYSTEMIC_CONTROL_UPLIFT_BOARD_V1_ACTIVE
# ============================================================

@app.route("/citrust/systemic-control-uplift-board")
@app.route("/citrust/control-uplift")
def citrust_systemic_control_uplift_board():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Systemic Control Uplift Board</title>
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
                <h1>CITrust™ Systemic Control Uplift Board</h1>

                <div class="subtitle">
                    Converts recurring certificate-exception patterns into permanent upstream governance controls, reducing repeated CITrust™ failures across CMDB readiness, CI ownership, support routing, MyAccess mapping, lifecycle closure, evidence completeness, and continuous trust.
                </div>

                <div class="positioning">
                    <strong>Control uplift boundary:</strong>
                    CITrust™ does not update ServiceNow, approve access, create CMDB records, or replace human governance in this demo. This board identifies which repeated CI governance failures require stronger intake rules, mandatory evidence bundles, escalation gates, review cadence, and certificate-control upgrades.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/exception-pattern-intelligence">Exception Patterns</a>
                    <a href="/citrust/certificate-lifecycle-command-center">Certificate Command Center</a>
                    <a href="/citrust/governance-debt-register">Governance Debt</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                    <a href="/citrust/continuous-trust-monitor">Continuous Trust</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Uplift Candidates</div>
                    <div class="value">16</div>
                    <div class="note">Recurring patterns requiring stronger upstream governance controls.</div>
                </div>

                <div class="metric">
                    <div class="label">Control Upgrades</div>
                    <div class="value" style="color: var(--green);">7</div>
                    <div class="note">Reusable controls ready to become standard CITrust™ governance requirements.</div>
                </div>

                <div class="metric">
                    <div class="label">Access Control Gaps</div>
                    <div class="value" style="color: var(--orange);">4</div>
                    <div class="note">Patterns requiring stronger MyAccess, admin, vendor, or jump-path evidence rules.</div>
                </div>

                <div class="metric">
                    <div class="label">Lifecycle Control Gaps</div>
                    <div class="value" style="color: var(--red);">3</div>
                    <div class="note">Patterns requiring stronger OOS, retirement, closure, and access-removal controls.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Gate Gaps</div>
                    <div class="value" style="color: var(--yellow);">5</div>
                    <div class="note">Patterns requiring mandatory proof before certificate or passport review.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Escalations</div>
                    <div class="value" style="color: var(--blue);">4</div>
                    <div class="note">Systemic control gaps requiring leadership visibility and prioritization.</div>
                </div>
            </section>

            <section class="section">
                <h2>Systemic Control Uplift Answer</h2>
                <p>
                    This board answers which recurring CITrust™ failures should become permanent upstream controls.
                </p>

                <div class="answer">
                    <strong>Current uplift interpretation:</strong>
                    If the same exception appears repeatedly, the fix should not remain manual remediation. CITrust™ should convert the pattern into an upstream control: mandatory evidence bundle, intake gate, support confirmation rule, MyAccess validation rule, lifecycle closure gate, hidden-dependency intake trigger, or certificate suspension trigger.
                </div>
            </section>

            <section class="section">
                <h2>Control Uplift Domains</h2>
                <p>
                    CITrust™ groups systemic control upgrades into the domains most likely to prevent recurring trust decay.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Intake Control Uplift</h3>
                        <p>Strengthens CI candidate intake so hidden dependencies, unmanaged assets, and incomplete records are captured earlier.</p>
                    </div>

                    <div class="card">
                        <h3>Access Control Uplift</h3>
                        <p>Requires MyAccess, approver, admin, vendor, jump path, and access-removal evidence before trust decisions.</p>
                    </div>

                    <div class="card">
                        <h3>Lifecycle Control Uplift</h3>
                        <p>Adds mandatory proof gates for active, cutover, OOS, retired, closed, rollback, and post-change lifecycle states.</p>
                    </div>

                    <div class="card">
                        <h3>Certificate Control Uplift</h3>
                        <p>Improves certificate issuance, renewal, exception, suspension, restoration, and continuous trust requirements.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Systemic Control Uplift Matrix</h2>
                <p>
                    This matrix maps recurring exception patterns to permanent control upgrades.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Recurring Pattern</th>
                            <th>Control Weakness</th>
                            <th>Required Uplift</th>
                            <th>Applies To</th>
                            <th>Control Owner</th>
                            <th>Uplift Decision</th>
                            <th>Expected Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Hidden Dependency Pattern</strong></td>
                            <td>Operational dependencies can exist without governed CI candidate identity.</td>
                            <td>Create mandatory hidden-dependency intake trigger.</td>
                            <td>Backup review workstations, local lab dependencies, unmanaged support paths.</td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td><span class="badge red">Mandatory Uplift</span></td>
                            <td>Hidden dependencies become CI candidates before exception or certificate review.</td>
                        </tr>

                        <tr>
                            <td><strong>Access Evidence Pattern</strong></td>
                            <td>Access proof is not consistently attached to CI trust decisions.</td>
                            <td>Create required access evidence bundle.</td>
                            <td>MyAccess roles, approver groups, admin paths, vendor access, jump server routes.</td>
                            <td>Access Governance / Infrastructure</td>
                            <td><span class="badge orange">Control Upgrade Required</span></td>
                            <td>Fewer access exceptions and stronger audit readiness.</td>
                        </tr>

                        <tr>
                            <td><strong>Support Routing Pattern</strong></td>
                            <td>Support group, resolver path, escalation owner, or LCM is discovered too late.</td>
                            <td>Add support confirmation gate before certificate or passport review.</td>
                            <td>Operational systems, cutover systems, lab systems, local infrastructure dependencies.</td>
                            <td>CMDB Governance / Service Operations</td>
                            <td><span class="badge yellow">Gate Upgrade</span></td>
                            <td>Reduced support-routing ambiguity and faster incident defensibility.</td>
                        </tr>

                        <tr>
                            <td><strong>Lifecycle Closure Pattern</strong></td>
                            <td>OOS and retired CIs lack closure, access-removal, and lifecycle-owner proof.</td>
                            <td>Add lifecycle closure evidence gate.</td>
                            <td>OOS equipment, retired systems, decommissioned assets, orphaned records.</td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td><span class="badge red">Mandatory Gate</span></td>
                            <td>Suspended certificates can only restore after closure proof exists.</td>
                        </tr>

                        <tr>
                            <td><strong>Cutover Evidence Pattern</strong></td>
                            <td>Cutover evidence is distributed across owners and not managed as one trust chain.</td>
                            <td>Create cutover evidence pack requirement.</td>
                            <td>BMS, migration-sensitive CIs, vendor-supported systems, jump-path dependencies.</td>
                            <td>Cutover Owner / Infrastructure / Access Governance</td>
                            <td><span class="badge orange">Evidence Pack Upgrade</span></td>
                            <td>Cleaner post-cutover attestation and lower trust decay.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception Aging Pattern</strong></td>
                            <td>Exceptions can remain open without timely escalation or closure proof.</td>
                            <td>Create exception expiry escalation rule.</td>
                            <td>Conditional certificates, access exceptions, lifecycle exceptions, support exceptions.</td>
                            <td>Governance Reviewer / Certificate Owner</td>
                            <td><span class="badge yellow">Cadence Upgrade</span></td>
                            <td>Fewer stale exceptions and fewer hidden governance debts.</td>
                        </tr>

                        <tr>
                            <td><strong>Strong Control Benchmark</strong></td>
                            <td>Some CIs show mature governance that can be reused.</td>
                            <td>Use strong records as template for certificate-ready evidence model.</td>
                            <td>Blue Mountain-style mature CIs and known governed systems.</td>
                            <td>Application Governance / CMDB Governance</td>
                            <td><span class="badge green">Replicate Model</span></td>
                            <td>Standardized certificate-readiness pattern across CIs.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Control Uplift Decision Logic</h2>
                <p>
                    A recurring exception should become a governed control, not another manual follow-up.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Promote To Upstream Control</h3>
                        <ul>
                            <li>Same gap appears across multiple CIs.</li>
                            <li>Manual remediation keeps repeating.</li>
                            <li>Pattern affects certificate readiness, renewal, suspension, or trust decay.</li>
                            <li>Evidence requirement can be standardized.</li>
                            <li>Control owner can be assigned.</li>
                            <li>Decision can prevent future exceptions.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Keep As Local Remediation</h3>
                        <ul>
                            <li>Gap is isolated to one CI.</li>
                            <li>Cause is unique and not process-driven.</li>
                            <li>Closure evidence is already defined.</li>
                            <li>Pattern does not repeat across certificate population.</li>
                            <li>No reusable control would reduce future risk.</li>
                            <li>Owner-level action is sufficient.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Systemic Uplift Action Queue</h2>
                <p>
                    These upgrades reduce repeated certificate exceptions and strengthen the CITrust™ operating model.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Systemic Upgrade</th>
                            <th>Why It Matters</th>
                            <th>Implementation Rule</th>
                            <th>Expected Governance Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden-dependency intake trigger.</td>
                            <td>Unmanaged dependencies cannot be trusted, certified, or exception-managed.</td>
                            <td>Any operational dependency used for backup, audit, access, support, or review must become a CI candidate.</td>
                            <td>Hidden dependencies enter candidate review before they create trust debt.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Lifecycle closure evidence gate.</td>
                            <td>OOS and retired records create audit and access-removal exposure without closure proof.</td>
                            <td>No lifecycle restoration, certificate renewal, or closure attestation without closure evidence and access deactivation proof.</td>
                            <td>Lifecycle ambiguity and suspended certificates decrease.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Privileged access evidence bundle.</td>
                            <td>Access trust decays when admin, vendor, jump path, or MyAccess evidence is incomplete.</td>
                            <td>Certificate review requires MyAccess mapping, approver group, admin/vendor procedure, and access review proof.</td>
                            <td>Access exceptions reduce and audit readiness improves.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Support and LCM confirmation gate.</td>
                            <td>Late support discovery weakens CI trust and ServiceNow-readiness.</td>
                            <td>No certificate-ready status without support group, resolver path, LCM, escalation owner, and evidence location.</td>
                            <td>Support-routing exceptions decrease.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This systemic control uplift board is a governance assurance overlay for converting recurring CI exceptions into permanent controls, mandatory evidence bundles, intake gates, lifecycle gates, access governance upgrades, support routing upgrades, exception expiry rules, certificate-strengthening actions, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_SYSTEMIC_CONTROL_UPLIFT_BOARD_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Systemic Control Uplift Board installed.")
