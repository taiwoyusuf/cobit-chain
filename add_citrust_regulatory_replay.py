from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_REGULATORY_REPLAY_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/regulatory-replay")'
ROUTE_ALIAS = '@app.route("/citrust/inspection-replay")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Regulatory Replay already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_REGULATORY_REPLAY_V1_ACTIVE
# ============================================================

@app.route("/citrust/regulatory-replay")
@app.route("/citrust/inspection-replay")
def citrust_regulatory_replay():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Regulatory Replay</title>
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
                    radial-gradient(circle at top left, rgba(49,208,125,0.20), transparent 30%),
                    radial-gradient(circle at top right, rgba(92,200,255,0.18), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(180,156,255,0.13), transparent 30%),
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

            .replay-grid {
                display: grid;
                grid-template-columns: 1.05fr 0.95fr;
                gap: 18px;
                margin-top: 16px;
            }

            .replay-card {
                border: 1px solid rgba(49,208,125,0.32);
                background:
                    linear-gradient(135deg, rgba(255,255,255,0.06), rgba(49,208,125,0.07)),
                    rgba(255,255,255,0.035);
                border-radius: 22px;
                padding: 22px;
                min-height: 300px;
                position: relative;
                overflow: hidden;
            }

            .replay-card:after {
                content: "REPLAY";
                position: absolute;
                right: -22px;
                top: 42px;
                transform: rotate(28deg);
                color: rgba(49,208,125,0.16);
                font-size: 39px;
                font-weight: 900;
                letter-spacing: 4px;
            }

            .replay-card h3 {
                margin: 0 0 12px 0;
                font-size: 22px;
            }

            .replay-row {
                display: grid;
                grid-template-columns: 190px 1fr;
                gap: 12px;
                padding: 10px 0;
                border-bottom: 1px solid rgba(255,255,255,0.08);
                font-size: 14px;
            }

            .replay-row .key {
                color: var(--muted);
            }

            .replay-row .val {
                color: var(--text);
                font-weight: 800;
            }

            .timeline {
                margin-top: 16px;
                display: grid;
                gap: 12px;
            }

            .event {
                border: 1px solid rgba(92,200,255,0.26);
                background: rgba(92,200,255,0.07);
                border-radius: 16px;
                padding: 15px;
                display: grid;
                grid-template-columns: 130px 1fr 170px;
                gap: 14px;
                align-items: center;
            }

            .event .time {
                color: var(--cyan);
                font-weight: 900;
                font-size: 13px;
            }

            .event .desc {
                color: var(--text);
                line-height: 1.45;
                font-size: 14px;
            }

            .event .state {
                text-align: right;
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
                .kpis, .cards, .replay-grid {
                    grid-template-columns: 1fr;
                }

                .event {
                    grid-template-columns: 1fr;
                }

                .event .state {
                    text-align: left;
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
                <div class="eyebrow">CITrust™ / ServiceNow AI / FDA-Style Inspection Replay</div>
                <h1>CITrust™ Regulatory Replay</h1>

                <div class="subtitle">
                    Inspection-ready replay layer for ServiceNow AI and CMDB governance, reconstructing every AI-assisted or autonomous action from trigger to evidence, policy check, authority decision, human approval, execution, rollback, verification, and final trust state.
                </div>

                <div class="positioning">
                    <strong>ServiceNow-focused positioning:</strong>
                    When an inspector asks why a ServiceNow AI action was trusted, CITrust™ replays the full governed story — not just the transaction log, but the evidence, human oversight, authority boundary, decision rationale, rollback, and inspection defense.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/ai-authority-envelope">AI Authority Envelope</a>
                    <a href="/citrust/executive-confidence-index">Executive Confidence</a>
                    <a href="/citrust/governance-entropy">Governance Entropy</a>
                    <a href="/citrust/trust-dna">Trust DNA</a>
                    <a href="/citrust/autonomous-agent-governance-passport">Agent Passport</a>
                    <a href="/citrust/governance-black-box">Governance Black Box</a>
                    <a href="/citrust/assurance-claim-firewall">Claim Firewall</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Replay Status</div>
                    <div class="value" style="color: var(--green);">Ready</div>
                    <div class="note">Latest ServiceNow AI action can be reconstructed end-to-end.</div>
                </div>

                <div class="metric">
                    <div class="label">Replay Completeness</div>
                    <div class="value" style="color: var(--green);">97%</div>
                    <div class="note">Prompt, evidence, policy, approval, execution, and outcome captured.</div>
                </div>

                <div class="metric">
                    <div class="label">Inspection Questions Answered</div>
                    <div class="value" style="color: var(--blue);">18</div>
                    <div class="note">Pre-built answers for audit and inspection challenge questions.</div>
                </div>

                <div class="metric">
                    <div class="label">Human Approvals Linked</div>
                    <div class="value" style="color: var(--green);">Yes</div>
                    <div class="note">Human governance remains visible and accountable.</div>
                </div>

                <div class="metric">
                    <div class="label">Replay Gaps</div>
                    <div class="value" style="color: var(--yellow);">2</div>
                    <div class="note">Minor evidence freshness gaps require follow-up.</div>
                </div>

                <div class="metric">
                    <div class="label">Inspection Defense</div>
                    <div class="value" style="color: var(--green);">Strong</div>
                    <div class="note">Replay package supports regulated review defense.</div>
                </div>
            </section>

            <section class="section">
                <h2>Regulatory Replay Answer</h2>
                <p>
                    This page answers whether a ServiceNow AI action can be reconstructed and defended months later.
                </p>

                <div class="answer">
                    <strong>Current replay interpretation:</strong>
                    The latest ServiceNow AI governance action is inspection-ready because the action trigger, evidence basis, authority-envelope decision, human approval requirement, rollback state, and final trust impact are preserved. The replay does not claim the AI replaced governance; it proves human-governed AI execution.
                </div>
            </section>

            <section class="section">
                <h2>Inspection Replay Package</h2>

                <div class="replay-grid">
                    <div class="replay-card">
                        <h3>Replay Case: CMDB Support Governance Action</h3>

                        <div class="replay-row">
                            <div class="key">Replay ID</div>
                            <div class="val">CIRR-SNOW-INSPECT-0001</div>
                        </div>

                        <div class="replay-row">
                            <div class="key">ServiceNow Area</div>
                            <div class="val">CMDB / CSDM / ITSM Support Routing</div>
                        </div>

                        <div class="replay-row">
                            <div class="key">AI Agent</div>
                            <div class="val">ServiceNow CMDB Update Agent</div>
                        </div>

                        <div class="replay-row">
                            <div class="key">Action Type</div>
                            <div class="val">Recommendation with Human-Gated Update</div>
                        </div>

                        <div class="replay-row">
                            <div class="key">Human Governance</div>
                            <div class="val"><span class="badge green">Preserved</span></div>
                        </div>

                        <div class="replay-row">
                            <div class="key">Authority Envelope</div>
                            <div class="val"><span class="badge yellow">Approval Required</span></div>
                        </div>

                        <div class="replay-row">
                            <div class="key">Inspection Decision</div>
                            <div class="val">Replay supports inspection review with limitation language</div>
                        </div>
                    </div>

                    <div class="replay-card">
                        <h3>Inspection Challenge Response</h3>

                        <div class="replay-row">
                            <div class="key">Why did AI act?</div>
                            <div class="val">Detected support evidence inconsistency in CMDB governance state.</div>
                        </div>

                        <div class="replay-row">
                            <div class="key">What evidence was used?</div>
                            <div class="val">CI record, owner, support group, LCM evidence, and prior support state.</div>
                        </div>

                        <div class="replay-row">
                            <div class="key">Was AI authorized?</div>
                            <div class="val">Authorized to recommend, not authorized to finalize without human approval.</div>
                        </div>

                        <div class="replay-row">
                            <div class="key">Was action reversible?</div>
                            <div class="val">Yes, previous state and rollback owner were recorded.</div>
                        </div>

                        <div class="replay-row">
                            <div class="key">Can QA defend it?</div>
                            <div class="val">Yes, as human-governed AI recommendation, not autonomous final approval.</div>
                        </div>

                        <div class="replay-row">
                            <div class="key">Final claim</div>
                            <div class="val">Conditionally defensible pending reviewer acceptance.</div>
                        </div>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Regulatory Replay Timeline</h2>

                <div class="timeline">
                    <div class="event">
                        <div class="time">01 Trigger</div>
                        <div class="desc"><strong>Signal detected:</strong> ServiceNow CI support evidence did not fully align with current support/LCM readiness expectations.</div>
                        <div class="state"><span class="badge blue">Captured</span></div>
                    </div>

                    <div class="event">
                        <div class="time">02 Evidence</div>
                        <div class="desc"><strong>Evidence loaded:</strong> CI identity, owner, support group, LCM field, escalation path, and historical support state.</div>
                        <div class="state"><span class="badge green">Complete</span></div>
                    </div>

                    <div class="event">
                        <div class="time">03 Policy</div>
                        <div class="desc"><strong>Policy evaluated:</strong> Support-impacting changes require human approval because they affect operational accountability.</div>
                        <div class="state"><span class="badge yellow">Human Gate</span></div>
                    </div>

                    <div class="event">
                        <div class="time">04 Authority</div>
                        <div class="desc"><strong>Authority envelope checked:</strong> Agent permitted to recommend correction, but blocked from final update without reviewer acceptance.</div>
                        <div class="state"><span class="badge green">Bounded</span></div>
                    </div>

                    <div class="event">
                        <div class="time">05 Output</div>
                        <div class="desc"><strong>Governance output:</strong> Recommendation created with evidence references, limitation language, and rollback path.</div>
                        <div class="state"><span class="badge blue">Replay Ready</span></div>
                    </div>

                    <div class="event">
                        <div class="time">06 Trust</div>
                        <div class="desc"><strong>Final trust state:</strong> Conditional reliance until human reviewer accepts support correction and evidence gate closes.</div>
                        <div class="state"><span class="badge yellow">Conditional</span></div>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Inspection Replay Evidence Matrix</h2>

                <table>
                    <thead>
                        <tr>
                            <th>Inspection Question</th>
                            <th>Replay Evidence</th>
                            <th>Status</th>
                            <th>Defensible Answer</th>
                            <th>Limitation</th>
                            <th>Next Control</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Why did the AI action occur?</strong></td>
                            <td>Trigger record and support evidence inconsistency.</td>
                            <td><span class="badge green">Available</span></td>
                            <td>AI acted because a governed evidence inconsistency was detected.</td>
                            <td>AI created recommendation only.</td>
                            <td>Maintain Black Box trigger capture.</td>
                        </tr>

                        <tr>
                            <td><strong>What evidence did the AI use?</strong></td>
                            <td>CI record, owner, support group, LCM, prior state, evidence references.</td>
                            <td><span class="badge green">Available</span></td>
                            <td>Evidence basis can be reconstructed.</td>
                            <td>Access evidence freshness still requires monitoring.</td>
                            <td>Link evidence freshness to replay package.</td>
                        </tr>

                        <tr>
                            <td><strong>Was the AI authorized?</strong></td>
                            <td>Agent Governance Passport and AI Authority Envelope decision.</td>
                            <td><span class="badge green">Available</span></td>
                            <td>Agent was authorized to recommend, not to finalize high-impact update.</td>
                            <td>Final approval remained human-gated.</td>
                            <td>Maintain authority-envelope validation.</td>
                        </tr>

                        <tr>
                            <td><strong>Who approved the action?</strong></td>
                            <td>Human reviewer requirement and approval status.</td>
                            <td><span class="badge yellow">Pending</span></td>
                            <td>Final action cannot be claimed complete until reviewer accepts.</td>
                            <td>Current state is conditional.</td>
                            <td>Capture reviewer acceptance in decision ledger.</td>
                        </tr>

                        <tr>
                            <td><strong>Could the action be reversed?</strong></td>
                            <td>Previous state, rollback owner, recovery instruction.</td>
                            <td><span class="badge green">Available</span></td>
                            <td>Rollback path exists and can be executed if reviewer rejects action.</td>
                            <td>Rollback must remain linked to Black Box record.</td>
                            <td>Retest rollback after approved change.</td>
                        </tr>

                        <tr>
                            <td><strong>Can QA defend the action?</strong></td>
                            <td>Human governance boundary, evidence basis, limitation language, replay package.</td>
                            <td><span class="badge green">Strong</span></td>
                            <td>QA can defend it as human-governed AI assistance, not autonomous QA decision-making.</td>
                            <td>Must not claim AI replaced accountable owner.</td>
                            <td>Use Claim Firewall language in leadership summary.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Regulatory Replay Engines</h2>

                <div class="cards">
                    <div class="card">
                        <h3>Prompt-to-Outcome Reconstruction</h3>
                        <p>Replays why the ServiceNow AI action started, what it used, what it decided, and what state resulted.</p>
                    </div>

                    <div class="card">
                        <h3>Human Governance Proof</h3>
                        <p>Shows where humans approved, rejected, limited, or were required before final regulated action.</p>
                    </div>

                    <div class="card">
                        <h3>Inspection Challenge Builder</h3>
                        <p>Generates defensible answers to audit-style questions about AI authority, evidence, approval, and reversibility.</p>
                    </div>

                    <div class="card">
                        <h3>Replay Limitation Language</h3>
                        <p>Prevents overclaiming by showing which parts are fully defensible and which remain conditional.</p>
                    </div>
                </div>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, ServiceNow AI agents, AI Control Tower, CMDB, CSDM, ITSM, ITOM, MyAccess, validation systems, quality systems, audit systems, or accountable human governance. Regulatory Replay™ is a governance assurance overlay for ServiceNow AI and autonomous operations, reconstructing trigger, evidence, policy, authority, human approval, execution, rollback, verification, decision rationale, trust impact, and inspection defense so regulated organizations can explain why AI-assisted actions were trusted.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_REGULATORY_REPLAY_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Regulatory Replay installed.")
