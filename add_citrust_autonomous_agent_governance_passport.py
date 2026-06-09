from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AUTONOMOUS_AGENT_GOVERNANCE_PASSPORT_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/autonomous-agent-governance-passport")'
ROUTE_ALIAS = '@app.route("/citrust/agent-governance-passport")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Autonomous Agent Governance Passport already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AUTONOMOUS_AGENT_GOVERNANCE_PASSPORT_V1_ACTIVE
# ============================================================

@app.route("/citrust/autonomous-agent-governance-passport")
@app.route("/citrust/agent-governance-passport")
def citrust_autonomous_agent_governance_passport():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Autonomous Agent Governance Passport</title>
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
                    radial-gradient(circle at top right, rgba(49,208,125,0.16), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(180,156,255,0.14), transparent 30%),
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
                    radial-gradient(circle at right, rgba(49,208,125,0.16), transparent 40%);
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
                border: 1px solid rgba(49,208,125,0.38);
                background: rgba(49,208,125,0.10);
                border-radius: 18px;
                color: #dfffea;
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

            .passport-grid {
                display: grid;
                grid-template-columns: 1.1fr 0.9fr;
                gap: 18px;
                margin-top: 16px;
            }

            .passport-card {
                border: 1px solid rgba(126,252,255,0.32);
                background:
                    linear-gradient(135deg, rgba(255,255,255,0.06), rgba(92,200,255,0.07)),
                    rgba(255,255,255,0.035);
                border-radius: 22px;
                padding: 22px;
                min-height: 300px;
                position: relative;
                overflow: hidden;
            }

            .passport-card:after {
                content: "CERTIFIED";
                position: absolute;
                right: -18px;
                top: 34px;
                transform: rotate(28deg);
                color: rgba(49,208,125,0.18);
                font-size: 42px;
                font-weight: 900;
                letter-spacing: 4px;
            }

            .passport-card h3 {
                margin: 0 0 12px 0;
                font-size: 22px;
            }

            .passport-row {
                display: grid;
                grid-template-columns: 180px 1fr;
                gap: 12px;
                padding: 10px 0;
                border-bottom: 1px solid rgba(255,255,255,0.08);
                font-size: 14px;
            }

            .passport-row .key {
                color: var(--muted);
            }

            .passport-row .val {
                color: var(--text);
                font-weight: 800;
            }

            .gauge {
                width: 230px;
                height: 230px;
                border-radius: 50%;
                margin: 20px auto 14px auto;
                background:
                    conic-gradient(var(--green) 0deg 346deg, rgba(255,255,255,0.10) 346deg 360deg);
                display: flex;
                align-items: center;
                justify-content: center;
                box-shadow: 0 0 38px rgba(49,208,125,0.20);
            }

            .gauge-inner {
                width: 168px;
                height: 168px;
                border-radius: 50%;
                background: #07111f;
                border: 1px solid rgba(255,255,255,0.12);
                display: flex;
                align-items: center;
                justify-content: center;
                flex-direction: column;
            }

            .gauge-inner .big {
                font-size: 44px;
                font-weight: 900;
                color: var(--green);
            }

            .gauge-inner .small {
                color: var(--muted);
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 1px;
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

            .three-col {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 16px;
                margin-top: 16px;
            }

            .authority-box {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 18px;
            }

            .authority-box h3 {
                margin: 0 0 12px 0;
                font-size: 17px;
            }

            .authority-box ul {
                margin: 0;
                padding-left: 18px;
                color: var(--muted);
                line-height: 1.8;
                font-size: 14px;
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
                .kpis, .cards, .three-col, .passport-grid {
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
                <div class="eyebrow">CITrust™ / ServiceNow AI / Autonomous Operations Governance</div>
                <h1>CITrust™ Autonomous Agent Governance Passport</h1>

                <div class="subtitle">
                    Governance assurance passport for ServiceNow AI and autonomous enterprise agents, certifying whether agent actions are authorized, evidence-backed, human-governed, reversible, inspection-ready, and safe to rely on before they affect CI trust, access governance, lifecycle state, or executive readiness claims.
                </div>

                <div class="positioning">
                    <strong>ServiceNow-focused positioning:</strong>
                    ServiceNow and NVIDIA help autonomous agents act across enterprise workflows. CITrust™ certifies whether those ServiceNow AI actions can be trusted, governed, explained, replayed, reversed, and defended in regulated operations.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/assurance-claim-firewall">Claim Firewall</a>
                    <a href="/citrust/causal-assurance-graph">Causal Assurance Graph</a>
                    <a href="/citrust/trust-failure-premortem-engine">Trust Failure Pre-Mortem</a>
                    <a href="/citrust/executive-assurance-digital-twin">Assurance Digital Twin</a>
                    <a href="/citrust/executive-assurance-decision-ledger">Decision Ledger</a>
                    <a href="/citrust/control-audit-defense-pack">Control Defense Pack</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Agent Trust Status</div>
                    <div class="value" style="color: var(--green);">Certified</div>
                    <div class="note">Agent is inside governed ServiceNow authority envelope.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Sufficiency</div>
                    <div class="value" style="color: var(--green);">96%</div>
                    <div class="note">Evidence supports current autonomous-action scope.</div>
                </div>

                <div class="metric">
                    <div class="label">Human Oversight</div>
                    <div class="value" style="color: var(--blue);">Enabled</div>
                    <div class="note">Human approval required for high-impact trust actions.</div>
                </div>

                <div class="metric">
                    <div class="label">Rollback Readiness</div>
                    <div class="value" style="color: var(--green);">Ready</div>
                    <div class="note">Action reversal path is documented and reviewable.</div>
                </div>

                <div class="metric">
                    <div class="label">Inspection Replay</div>
                    <div class="value" style="color: var(--green);">Ready</div>
                    <div class="note">Prompt, evidence, decision, approval, and execution are replayable.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Reliance</div>
                    <div class="value" style="color: var(--yellow);">Conditional</div>
                    <div class="note">Safe for approved scope; blocked outside authority envelope.</div>
                </div>
            </section>

            <section class="section">
                <h2>Autonomous Agent Governance Passport Answer</h2>
                <p>
                    This passport answers whether a ServiceNow AI agent can be trusted before, during, and after an autonomous action.
                </p>

                <div class="answer">
                    <strong>Current passport interpretation:</strong>
                    The CMDB Update Agent may draft CI records, update documentation, recommend support-group changes, and prepare readiness evidence. It cannot delete CIs, override validation, close CAPA, remove evidence, modify certificate status, or change lifecycle state without human-governed approval.
                </div>
            </section>

            <section class="section">
                <h2>Agent Trust Certificate</h2>

                <div class="passport-grid">
                    <div class="passport-card">
                        <h3>ServiceNow CMDB Update Agent</h3>

                        <div class="passport-row">
                            <div class="key">Certificate ID</div>
                            <div class="val">CIAGP-SNOW-CMDB-0001</div>
                        </div>

                        <div class="passport-row">
                            <div class="key">Agent Scope</div>
                            <div class="val">CMDB / CSDM / Support Group / CI Documentation</div>
                        </div>

                        <div class="passport-row">
                            <div class="key">Governance Status</div>
                            <div class="val"><span class="badge green">Certified Within Envelope</span></div>
                        </div>

                        <div class="passport-row">
                            <div class="key">Human Oversight</div>
                            <div class="val">Required for lifecycle, certificate, trust, and readiness impact</div>
                        </div>

                        <div class="passport-row">
                            <div class="key">Regulatory Replay</div>
                            <div class="val">Prompt, evidence, decision, approval, execution, and rollback preserved</div>
                        </div>

                        <div class="passport-row">
                            <div class="key">Passport Expiry</div>
                            <div class="val">30 days or earlier if evidence freshness drops below threshold</div>
                        </div>

                        <div class="passport-row">
                            <div class="key">Current Decision</div>
                            <div class="val">Allow low-risk ServiceNow CI governance actions; block high-risk actions pending human approval</div>
                        </div>
                    </div>

                    <div class="passport-card">
                        <h3>Evidence Sufficiency Index</h3>

                        <div class="gauge">
                            <div class="gauge-inner">
                                <div class="big">96%</div>
                                <div class="small">Sufficient</div>
                            </div>
                        </div>

                        <p style="text-align:center; color:#dfffea; margin:0;">
                            Evidence is sufficient for low-risk ServiceNow CMDB governance actions but does not authorize autonomous lifecycle, certificate, or validation-impacting changes.
                        </p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>AI Authority Envelope™</h2>
                <p>
                    This envelope governs what the ServiceNow AI agent may do, what requires human approval, and what is forbidden.
                </p>

                <div class="three-col">
                    <div class="authority-box">
                        <h3><span class="badge green">Allowed</span></h3>
                        <ul>
                            <li>Draft CI candidate record</li>
                            <li>Update non-regulated CI documentation</li>
                            <li>Recommend support group correction</li>
                            <li>Prepare evidence checklist</li>
                            <li>Flag stale ownership evidence</li>
                            <li>Create governance review recommendation</li>
                        </ul>
                    </div>

                    <div class="authority-box">
                        <h3><span class="badge yellow">Human Approval Required</span></h3>
                        <ul>
                            <li>Change lifecycle state</li>
                            <li>Modify certificate status</li>
                            <li>Approve readiness claim</li>
                            <li>Change LCM or accountable owner</li>
                            <li>Accept residual risk</li>
                            <li>Close governance exception</li>
                        </ul>
                    </div>

                    <div class="authority-box">
                        <h3><span class="badge red">Forbidden</span></h3>
                        <ul>
                            <li>Delete CI</li>
                            <li>Remove evidence</li>
                            <li>Close CAPA</li>
                            <li>Override validation</li>
                            <li>Bypass human approval</li>
                            <li>Directly override Trust DNA</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Passport Evidence Matrix</h2>
                <p>
                    Evidence required before the ServiceNow AI agent can be trusted inside its approved scope.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Evidence Domain</th>
                            <th>Required Proof</th>
                            <th>Status</th>
                            <th>Governance Meaning</th>
                            <th>Agent Permission Impact</th>
                            <th>Human Gate</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>CMDB Identity</strong></td>
                            <td>CI name, class, owner, environment, criticality, and system relationship basis.</td>
                            <td><span class="badge green">Complete</span></td>
                            <td>Agent can reason against correct CI identity.</td>
                            <td>Draft and recommend allowed.</td>
                            <td>Required for final approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Support Group</strong></td>
                            <td>Support group, resolver path, LCM, escalation owner, evidence location, and review cadence.</td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Support assurance is not fully reliable until ownership proof is current.</td>
                            <td>Recommend only; no autonomous final change.</td>
                            <td>Required.</td>
                        </tr>

                        <tr>
                            <td><strong>MyAccess / Access Governance</strong></td>
                            <td>Role mapping, approver group, admin/vendor procedure, access review proof, and post-access verification.</td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Access action cannot be fully trusted without current proof.</td>
                            <td>Flag and prepare evidence pack only.</td>
                            <td>Required for access-impacting action.</td>
                        </tr>

                        <tr>
                            <td><strong>Lifecycle State</strong></td>
                            <td>Active/OOS/retired status, closure proof, access deactivation proof, lifecycle decision.</td>
                            <td><span class="badge green">Governed</span></td>
                            <td>Lifecycle changes are high-impact and must remain human-governed.</td>
                            <td>Autonomous lifecycle change blocked.</td>
                            <td>Mandatory.</td>
                        </tr>

                        <tr>
                            <td><strong>Certificate Readiness</strong></td>
                            <td>Certificate state, evidence freshness, exception status, owner acceptance, and decision-ledger rationale.</td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Agent may prepare readiness recommendation but cannot certify trust.</td>
                            <td>Recommend only.</td>
                            <td>Mandatory.</td>
                        </tr>

                        <tr>
                            <td><strong>Rollback / Reversibility</strong></td>
                            <td>Previous state, changed field, rollback owner, recovery path, and verification instruction.</td>
                            <td><span class="badge green">Ready</span></td>
                            <td>Low-risk documentation changes are reversible.</td>
                            <td>Low-risk execution allowed.</td>
                            <td>Required if regulated state changes.</td>
                        </tr>

                        <tr>
                            <td><strong>Regulatory Replay</strong></td>
                            <td>Prompt, trigger, evidence used, policies evaluated, human approval, execution, outcome, and final trust state.</td>
                            <td><span class="badge green">Replay Ready</span></td>
                            <td>Action can be reconstructed during inspection or governance review.</td>
                            <td>Required for all autonomous actions.</td>
                            <td>Reviewer can audit after execution.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Executive Reliance Matrix</h2>
                <p>
                    Different stakeholders can rely on the agent only within the approved governance boundary.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Stakeholder</th>
                            <th>Reliance Decision</th>
                            <th>Allowed Reliance</th>
                            <th>Blocked Reliance</th>
                            <th>Reason</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>CIO</strong></td>
                            <td><span class="badge green">Rely Within Scope</span></td>
                            <td>Low-risk CI documentation and evidence-preparation actions.</td>
                            <td>Autonomous lifecycle or certificate decision.</td>
                            <td>Agent is certified for ServiceNow CMDB governance support, not final regulated decisions.</td>
                        </tr>

                        <tr>
                            <td><strong>QA</strong></td>
                            <td><span class="badge yellow">Conditional Reliance</span></td>
                            <td>Evidence package preparation and inspection replay.</td>
                            <td>Automated validation, CAPA closure, or readiness certification.</td>
                            <td>Human governance remains authoritative for regulated conclusions.</td>
                        </tr>

                        <tr>
                            <td><strong>Cyber / Access Governance</strong></td>
                            <td><span class="badge yellow">Conditional Reliance</span></td>
                            <td>Access evidence gap detection.</td>
                            <td>Autonomous privileged access approval.</td>
                            <td>Access-impacting actions require owner and reviewer approval.</td>
                        </tr>

                        <tr>
                            <td><strong>Audit</strong></td>
                            <td><span class="badge green">Replay Reliable</span></td>
                            <td>Action reconstruction, evidence lineage, authority envelope, approval trace.</td>
                            <td>Claims that agent replaced accountable human owner.</td>
                            <td>CITrust™ preserves the governance explanation, not just the execution log.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Passport Control Decision Logic</h2>

                <div class="cards">
                    <div class="card">
                        <h3>Allow Action</h3>
                        <p>Evidence is sufficient, action is low-risk, authority envelope permits it, rollback exists, and regulatory replay is active.</p>
                    </div>

                    <div class="card">
                        <h3>Require Approval</h3>
                        <p>Action affects lifecycle, certificate status, access governance, support ownership, validation, readiness, or residual risk.</p>
                    </div>

                    <div class="card">
                        <h3>Block Action</h3>
                        <p>Evidence is missing, claim is unsupported, action is outside envelope, human gate is bypassed, or rollback is unavailable.</p>
                    </div>

                    <div class="card">
                        <h3>Quarantine Trust</h3>
                        <p>Agent action creates governance debt, trust mutation, exception aging, unsupported certificate change, or audit-defense weakness.</p>
                    </div>
                </div>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, ServiceNow AI agents, AI Control Tower, CMDB, CSDM, ITSM, ITOM, MyAccess, validation systems, quality systems, audit systems, or accountable human governance. This Autonomous Agent Governance Passport™ is a governance assurance overlay for ServiceNow AI and autonomous operations, validating authority boundaries, evidence sufficiency, human oversight, rollback readiness, regulatory replay, inspection readiness, executive reliance, and trust defensibility before autonomous actions are treated as trusted.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AUTONOMOUS_AGENT_GOVERNANCE_PASSPORT_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Autonomous Agent Governance Passport installed.")
