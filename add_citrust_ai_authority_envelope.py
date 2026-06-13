from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AI_AUTHORITY_ENVELOPE_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/ai-authority-envelope")'
ROUTE_ALIAS = '@app.route("/citrust/autonomous-authority-envelope")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust AI Authority Envelope already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AI_AUTHORITY_ENVELOPE_V1_ACTIVE
# ============================================================

@app.route("/citrust/ai-authority-envelope")
@app.route("/citrust/autonomous-authority-envelope")
def citrust_ai_authority_envelope():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ AI Authority Envelope</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <style>
            :root {
                --bg: #040b14;
                --panel: rgba(14, 27, 44, 0.92);
                --line: rgba(255,255,255,0.12);
                --text: #eef5ff;
                --muted: #a8bbd4;
                --green: #31d07d;
                --yellow: #f7c948;
                --red: #ff5c70;
                --blue: #5cc8ff;
                --purple: #b49cff;
                --orange: #ffb86b;
                --cyan: #7efcff;
            }

            * { box-sizing: border-box; }

            body {
                margin: 0;
                font-family: Arial, Helvetica, sans-serif;
                background:
                    radial-gradient(circle at top left, rgba(92,200,255,0.22), transparent 30%),
                    radial-gradient(circle at top right, rgba(255,92,112,0.16), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(49,208,125,0.12), transparent 30%),
                    var(--bg);
                color: var(--text);
            }

            .page {
                max-width: 1460px;
                margin: 0 auto;
                padding: 28px;
            }

            .hero {
                border: 1px solid var(--line);
                background:
                    linear-gradient(135deg, rgba(16,29,47,0.98), rgba(20,40,66,0.92)),
                    radial-gradient(circle at right, rgba(92,200,255,0.16), transparent 40%);
                border-radius: 26px;
                padding: 30px;
                box-shadow: 0 24px 80px rgba(0,0,0,0.42);
            }

            .eyebrow {
                color: var(--cyan);
                font-size: 13px;
                text-transform: uppercase;
                letter-spacing: 1.9px;
                font-weight: 900;
                margin-bottom: 10px;
            }

            h1 {
                margin: 0;
                font-size: 42px;
                line-height: 1.08;
            }

            .subtitle {
                color: var(--muted);
                font-size: 16px;
                line-height: 1.65;
                max-width: 1180px;
                margin-top: 14px;
            }

            .positioning {
                margin-top: 18px;
                padding: 17px 19px;
                border: 1px solid rgba(92,200,255,0.38);
                background: rgba(92,200,255,0.10);
                border-radius: 18px;
                color: #d9f3ff;
                line-height: 1.6;
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
                background: var(--panel);
                border-radius: 18px;
                padding: 18px;
            }

            .metric .label {
                color: var(--muted);
                font-size: 13px;
                margin-bottom: 8px;
            }

            .metric .value {
                font-size: 29px;
                font-weight: 900;
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
                background: var(--panel);
                border-radius: 24px;
                padding: 23px;
            }

            .section h2 {
                margin: 0 0 8px 0;
                font-size: 23px;
            }

            .section p {
                color: var(--muted);
                line-height: 1.56;
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
                font-weight: 900;
                white-space: nowrap;
            }

            .green { color: #04140b; background: var(--green); }
            .yellow { color: #1d1600; background: var(--yellow); }
            .red { color: #fff; background: var(--red); }
            .blue { color: #06101d; background: var(--blue); }
            .purple { color: #120b24; background: var(--purple); }
            .orange { color: #211100; background: var(--orange); }

            .envelope-grid {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 18px;
                margin-top: 16px;
            }

            .envelope-card {
                border: 1px solid rgba(92,200,255,0.32);
                background:
                    linear-gradient(135deg, rgba(255,255,255,0.06), rgba(92,200,255,0.07)),
                    rgba(255,255,255,0.035);
                border-radius: 22px;
                padding: 22px;
                min-height: 285px;
            }

            .envelope-card h3 {
                margin: 0 0 12px 0;
                font-size: 21px;
            }

            .envelope-card ul {
                margin: 0;
                padding-left: 20px;
                color: var(--muted);
                font-size: 14px;
                line-height: 1.85;
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

            .footer {
                color: var(--muted);
                font-size: 12px;
                margin-top: 22px;
                line-height: 1.6;
            }

            @media (max-width: 1180px) {
                .kpis, .cards, .envelope-grid {
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
                <div class="eyebrow">CITrust™ / ServiceNow AI / Human-Governed Autonomy Boundary</div>
                <h1>CITrust™ AI Authority Envelope</h1>

                <div class="subtitle">
                    Defines the governed boundary around ServiceNow AI agents, separating actions that may be autonomous, actions that require human approval, and actions that are forbidden in regulated operations because they affect validation, lifecycle, certificate trust, CAPA, access, or audit evidence.
                </div>

                <div class="positioning">
                    <strong>ServiceNow-focused positioning:</strong>
                    ServiceNow AI enables action. CITrust™ AI Authority Envelope determines whether the agent is allowed to act, must ask for human approval, or must be blocked because the action exceeds its governed authority.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/executive-confidence-index">Executive Confidence</a>
                    <a href="/citrust/governance-entropy">Governance Entropy</a>
                    <a href="/citrust/trust-market">Trust Market</a>
                    <a href="/citrust/trust-dna">Trust DNA</a>
                    <a href="/citrust/autonomous-agent-governance-passport">Agent Passport</a>
                    <a href="/citrust/governance-black-box">Governance Black Box</a>
                    <a href="/citrust/assurance-claim-firewall">Claim Firewall</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Envelope Status</div>
                    <div class="value" style="color: var(--green);">Active</div>
                    <div class="note">All ServiceNow AI actions must pass authority boundary checks.</div>
                </div>

                <div class="metric">
                    <div class="label">Allowed Actions</div>
                    <div class="value" style="color: var(--green);">14</div>
                    <div class="note">Low-risk actions approved for autonomous or assisted execution.</div>
                </div>

                <div class="metric">
                    <div class="label">Human-Gated Actions</div>
                    <div class="value" style="color: var(--yellow);">21</div>
                    <div class="note">Actions requiring accountable human approval.</div>
                </div>

                <div class="metric">
                    <div class="label">Forbidden Actions</div>
                    <div class="value" style="color: var(--red);">9</div>
                    <div class="note">Actions blocked regardless of agent confidence.</div>
                </div>

                <div class="metric">
                    <div class="label">Authority Breaches</div>
                    <div class="value" style="color: var(--red);">0</div>
                    <div class="note">No active breach after Black Box enforcement.</div>
                </div>

                <div class="metric">
                    <div class="label">Execution Decision</div>
                    <div class="value" style="color: var(--blue);">Bounded</div>
                    <div class="note">Autonomy allowed only inside approved ServiceNow scope.</div>
                </div>
            </section>

            <section class="section">
                <h2>AI Authority Envelope Answer</h2>
                <p>
                    This page answers what a ServiceNow AI agent is allowed to do without creating regulated governance risk.
                </p>

                <div class="answer">
                    <strong>Current authority interpretation:</strong>
                    The ServiceNow CMDB Update Agent may draft records, recommend corrections, prepare evidence, and flag trust gaps. It must obtain human approval for lifecycle, certificate, access, readiness, support ownership, or residual-risk decisions. It is forbidden from deleting records, removing evidence, overriding validation, closing CAPA, or bypassing human governance.
                </div>
            </section>

            <section class="section">
                <h2>Authority Envelope Zones</h2>

                <div class="envelope-grid">
                    <div class="envelope-card">
                        <h3><span class="badge green">Autonomous / Allowed</span></h3>
                        <ul>
                            <li>Draft CI candidate record</li>
                            <li>Prepare CMDB evidence checklist</li>
                            <li>Flag stale owner or support evidence</li>
                            <li>Recommend support group correction</li>
                            <li>Prepare certificate evidence pack</li>
                            <li>Identify hidden dependency candidate</li>
                            <li>Create governance review recommendation</li>
                            <li>Generate Claim Firewall language</li>
                        </ul>
                    </div>

                    <div class="envelope-card">
                        <h3><span class="badge yellow">Human Approval Required</span></h3>
                        <ul>
                            <li>Change CI lifecycle state</li>
                            <li>Modify certificate status</li>
                            <li>Change LCM or accountable owner</li>
                            <li>Accept residual risk</li>
                            <li>Close governance exception</li>
                            <li>Approve readiness claim</li>
                            <li>Modify support group of regulated CI</li>
                            <li>Trigger access-impacting update</li>
                        </ul>
                    </div>

                    <div class="envelope-card">
                        <h3><span class="badge red">Forbidden</span></h3>
                        <ul>
                            <li>Delete CI</li>
                            <li>Remove audit evidence</li>
                            <li>Close CAPA</li>
                            <li>Override validation</li>
                            <li>Bypass QA approval</li>
                            <li>Change trust score directly</li>
                            <li>Suppress exception</li>
                            <li>Erase Black Box replay</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Authority Decision Engines</h2>

                <div class="cards">
                    <div class="card">
                        <h3>Scope Boundary Engine</h3>
                        <p>Checks whether the ServiceNow AI action is within approved CMDB, support, evidence, or documentation scope.</p>
                    </div>

                    <div class="card">
                        <h3>Human Gate Resolver</h3>
                        <p>Determines when the action crosses into lifecycle, certificate, validation, access, readiness, or residual-risk impact.</p>
                    </div>

                    <div class="card">
                        <h3>Forbidden Action Blocker</h3>
                        <p>Blocks actions that would delete, override, suppress, remove, bypass, or falsify regulated governance evidence.</p>
                    </div>

                    <div class="card">
                        <h3>Authority Drift Monitor</h3>
                        <p>Detects when agent behavior begins expanding beyond its approved ServiceNow governance role.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Authority Envelope Matrix</h2>

                <table>
                    <thead>
                        <tr>
                            <th>Agent Action</th>
                            <th>ServiceNow Area</th>
                            <th>Authority Decision</th>
                            <th>Why</th>
                            <th>Required Control</th>
                            <th>Black Box Requirement</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Draft CI candidate record</strong></td>
                            <td>CMDB / CSDM</td>
                            <td><span class="badge green">Allowed</span></td>
                            <td>Low-risk draft action; does not finalize regulated trust state.</td>
                            <td>Evidence checklist and owner placeholder required.</td>
                            <td>Record trigger and evidence basis.</td>
                        </tr>

                        <tr>
                            <td><strong>Recommend support group correction</strong></td>
                            <td>CMDB / ITSM</td>
                            <td><span class="badge yellow">Human Approval</span></td>
                            <td>Support group affects incident routing and operational accountability.</td>
                            <td>Support owner, LCM, resolver path, escalation owner.</td>
                            <td>Capture recommendation and reviewer decision.</td>
                        </tr>

                        <tr>
                            <td><strong>Change lifecycle status</strong></td>
                            <td>CMDB Lifecycle</td>
                            <td><span class="badge yellow">Human Approval</span></td>
                            <td>Lifecycle state affects certificate, audit, access, and operational trust.</td>
                            <td>Lifecycle owner approval and closure evidence.</td>
                            <td>Preserve before/after state and rationale.</td>
                        </tr>

                        <tr>
                            <td><strong>Approve certificate readiness</strong></td>
                            <td>CITrust Certificate</td>
                            <td><span class="badge yellow">Human Approval</span></td>
                            <td>Certificate status is an executive reliance decision.</td>
                            <td>Evidence freshness, exception state, owner acceptance.</td>
                            <td>Capture decision-ledger rationale.</td>
                        </tr>

                        <tr>
                            <td><strong>Approve privileged access</strong></td>
                            <td>MyAccess / IAM</td>
                            <td><span class="badge red">Forbidden For Agent</span></td>
                            <td>Privileged access approval must remain human-governed.</td>
                            <td>Access reviewer and approver group acceptance.</td>
                            <td>Capture denial and required human route.</td>
                        </tr>

                        <tr>
                            <td><strong>Close CAPA</strong></td>
                            <td>Quality / Validation</td>
                            <td><span class="badge red">Forbidden</span></td>
                            <td>CAPA closure is a quality-owned regulated decision.</td>
                            <td>QA approval and quality record closure.</td>
                            <td>Block and record attempted action.</td>
                        </tr>

                        <tr>
                            <td><strong>Remove evidence</strong></td>
                            <td>Evidence Repository</td>
                            <td><span class="badge red">Forbidden</span></td>
                            <td>Evidence removal destroys audit defensibility.</td>
                            <td>Evidence retention and deletion governance.</td>
                            <td>Quarantine and escalate.</td>
                        </tr>

                        <tr>
                            <td><strong>Generate readiness limitation language</strong></td>
                            <td>Executive Reporting</td>
                            <td><span class="badge green">Allowed</span></td>
                            <td>Advisory language does not alter system-of-record state.</td>
                            <td>Claim Firewall evidence check.</td>
                            <td>Capture claim basis and limitation.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Authority Escalation Rules</h2>

                <table>
                    <thead>
                        <tr>
                            <th>Trigger</th>
                            <th>Authority Response</th>
                            <th>Human Reviewer</th>
                            <th>Required Evidence</th>
                            <th>Execution Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td>Action affects regulated lifecycle state.</td>
                            <td><span class="badge yellow">Escalate</span></td>
                            <td>QA / Lifecycle Owner</td>
                            <td>Closure proof, access deactivation, lifecycle decision.</td>
                            <td>Blocked until approval.</td>
                        </tr>

                        <tr>
                            <td>Action affects support ownership.</td>
                            <td><span class="badge yellow">Escalate</span></td>
                            <td>CMDB Governance / Service Operations</td>
                            <td>Support group, resolver path, LCM, escalation owner.</td>
                            <td>Recommendation only.</td>
                        </tr>

                        <tr>
                            <td>Action affects privileged access.</td>
                            <td><span class="badge red">Block</span></td>
                            <td>Access Governance</td>
                            <td>MyAccess, approver group, review proof, admin/vendor procedure.</td>
                            <td>Agent cannot approve.</td>
                        </tr>

                        <tr>
                            <td>Action lacks rollback or replay path.</td>
                            <td><span class="badge red">Block</span></td>
                            <td>Governance Owner</td>
                            <td>Previous state, rollback owner, replay trace.</td>
                            <td>Execution denied.</td>
                        </tr>

                        <tr>
                            <td>Action is low-risk documentation update.</td>
                            <td><span class="badge green">Allow</span></td>
                            <td>Post-action reviewer optional.</td>
                            <td>Trigger, evidence, before/after text, rollback state.</td>
                            <td>Allowed with Black Box capture.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, ServiceNow AI agents, AI Control Tower, CMDB, CSDM, ITSM, ITOM, MyAccess, validation systems, quality systems, audit systems, or accountable human governance. AI Authority Envelope™ is a governance assurance overlay for ServiceNow AI and autonomous operations, defining what agents may do, what requires human approval, what is forbidden, when actions are blocked, when trust is quarantined, and when execution must be preserved in the Governance Black Box™.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AI_AUTHORITY_ENVELOPE_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust AI Authority Envelope installed.")
