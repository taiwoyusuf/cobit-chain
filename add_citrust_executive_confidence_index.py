from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_EXECUTIVE_CONFIDENCE_INDEX_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/executive-confidence-index")'
ROUTE_ALIAS = '@app.route("/citrust/executive-confidence")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Executive Confidence Index already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_EXECUTIVE_CONFIDENCE_INDEX_V1_ACTIVE
# ============================================================

@app.route("/citrust/executive-confidence-index")
@app.route("/citrust/executive-confidence")
def citrust_executive_confidence_index():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Executive Confidence Index</title>
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
                    radial-gradient(circle at top right, rgba(180,156,255,0.18), transparent 28%),
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

            .confidence-grid {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 18px;
                margin-top: 16px;
            }

            .confidence-card {
                border: 1px solid rgba(92,200,255,0.32);
                background:
                    linear-gradient(135deg, rgba(255,255,255,0.06), rgba(92,200,255,0.07)),
                    rgba(255,255,255,0.035);
                border-radius: 22px;
                padding: 22px;
                min-height: 260px;
                position: relative;
                overflow: hidden;
            }

            .confidence-card h3 {
                margin: 0 0 8px 0;
                font-size: 20px;
            }

            .big-score {
                font-size: 48px;
                font-weight: 900;
                margin: 8px 0;
            }

            .confidence-row {
                display: grid;
                grid-template-columns: 150px 1fr 60px;
                gap: 12px;
                align-items: center;
                padding: 10px 0;
                border-bottom: 1px solid rgba(255,255,255,0.08);
                font-size: 14px;
            }

            .confidence-row .key {
                color: var(--muted);
            }

            .bar {
                height: 11px;
                border-radius: 999px;
                background: rgba(255,255,255,0.10);
                overflow: hidden;
            }

            .fill {
                height: 100%;
                border-radius: 999px;
            }

            .score {
                text-align: right;
                color: var(--text);
                font-weight: 900;
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
                .kpis, .cards, .confidence-grid {
                    grid-template-columns: 1fr;
                }

                .confidence-row {
                    grid-template-columns: 1fr;
                }

                .score {
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
                <div class="eyebrow">CITrust™ / ServiceNow AI / Persona-Based Trust Confidence</div>
                <h1>CITrust™ Executive Confidence Index</h1>

                <div class="subtitle">
                    Persona-specific confidence layer for ServiceNow AI and CMDB governance, translating evidence, ownership, support, access, lifecycle, certificate, exception, AI authority, and inspection readiness into confidence scores for executives, QA, cyber, audit, and operations.
                </div>

                <div class="positioning">
                    <strong>ServiceNow-focused positioning:</strong>
                    ServiceNow shows system status. CITrust™ tells each leadership persona how confident they should be in the ServiceNow-controlled state, what they can safely claim, and what must remain conditional.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/governance-entropy">Governance Entropy</a>
                    <a href="/citrust/trust-market">Trust Market</a>
                    <a href="/citrust/trust-dna">Trust DNA</a>
                    <a href="/citrust/autonomous-agent-governance-passport">Agent Passport</a>
                    <a href="/citrust/governance-black-box">Governance Black Box</a>
                    <a href="/citrust/assurance-claim-firewall">Claim Firewall</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Executive Confidence</div>
                    <div class="value" style="color: var(--blue);">84%</div>
                    <div class="note">Overall confidence in ServiceNow CI governance assurance.</div>
                </div>

                <div class="metric">
                    <div class="label">QA Confidence</div>
                    <div class="value" style="color: var(--green);">92%</div>
                    <div class="note">Highest confidence due to strong lifecycle and evidence controls.</div>
                </div>

                <div class="metric">
                    <div class="label">Cyber Confidence</div>
                    <div class="value" style="color: var(--yellow);">78%</div>
                    <div class="note">Access proof remains conditional pending full bundle refresh.</div>
                </div>

                <div class="metric">
                    <div class="label">Audit Confidence</div>
                    <div class="value" style="color: var(--blue);">86%</div>
                    <div class="note">Replay and evidence lineage support inspection-style review.</div>
                </div>

                <div class="metric">
                    <div class="label">Operations Confidence</div>
                    <div class="value" style="color: var(--orange);">74%</div>
                    <div class="note">Support and LCM ambiguity still limits operational reliance.</div>
                </div>

                <div class="metric">
                    <div class="label">Confidence Direction</div>
                    <div class="value" style="color: var(--green);">Improving</div>
                    <div class="note">Top Trust Market interventions are expected to lift confidence.</div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Confidence Answer</h2>
                <p>
                    This page answers how confident each leadership persona should be in the ServiceNow AI and CI governance state.
                </p>

                <div class="answer">
                    <strong>Current confidence interpretation:</strong>
                    QA and audit confidence are strong because lifecycle closure, replay, and evidence lineage are defensible. Operations and cyber confidence remain conditional because support/LCM and privileged access evidence need stronger mandatory gates before leadership can claim full reliability.
                </div>
            </section>

            <section class="section">
                <h2>Persona Confidence Profiles</h2>

                <div class="confidence-grid">
                    <div class="confidence-card">
                        <h3>CIO Confidence</h3>
                        <div class="big-score" style="color: var(--blue);">84%</div>
                        <p>Strong enough for strategic reliance, conditional for autonomous high-impact actions.</p>

                        <div class="confidence-row">
                            <div class="key">CMDB Trust</div>
                            <div class="bar"><div class="fill" style="width:88%; background:var(--green);"></div></div>
                            <div class="score">88</div>
                        </div>
                        <div class="confidence-row">
                            <div class="key">AI Control</div>
                            <div class="bar"><div class="fill" style="width:81%; background:var(--blue);"></div></div>
                            <div class="score">81</div>
                        </div>
                        <div class="confidence-row">
                            <div class="key">Support Readiness</div>
                            <div class="bar"><div class="fill" style="width:73%; background:var(--yellow);"></div></div>
                            <div class="score">73</div>
                        </div>
                    </div>

                    <div class="confidence-card">
                        <h3>QA Confidence</h3>
                        <div class="big-score" style="color: var(--green);">92%</div>
                        <p>High confidence where human governance, lifecycle closure, evidence lineage, and replay are preserved.</p>

                        <div class="confidence-row">
                            <div class="key">Lifecycle</div>
                            <div class="bar"><div class="fill" style="width:95%; background:var(--green);"></div></div>
                            <div class="score">95</div>
                        </div>
                        <div class="confidence-row">
                            <div class="key">Evidence</div>
                            <div class="bar"><div class="fill" style="width:91%; background:var(--green);"></div></div>
                            <div class="score">91</div>
                        </div>
                        <div class="confidence-row">
                            <div class="key">Replay</div>
                            <div class="bar"><div class="fill" style="width:90%; background:var(--green);"></div></div>
                            <div class="score">90</div>
                        </div>
                    </div>

                    <div class="confidence-card">
                        <h3>Cyber Confidence</h3>
                        <div class="big-score" style="color: var(--yellow);">78%</div>
                        <p>Conditional confidence due to access evidence freshness and privileged-access review limitations.</p>

                        <div class="confidence-row">
                            <div class="key">MyAccess</div>
                            <div class="bar"><div class="fill" style="width:84%; background:var(--green);"></div></div>
                            <div class="score">84</div>
                        </div>
                        <div class="confidence-row">
                            <div class="key">Vendor Access</div>
                            <div class="bar"><div class="fill" style="width:72%; background:var(--yellow);"></div></div>
                            <div class="score">72</div>
                        </div>
                        <div class="confidence-row">
                            <div class="key">Review Proof</div>
                            <div class="bar"><div class="fill" style="width:69%; background:var(--orange);"></div></div>
                            <div class="score">69</div>
                        </div>
                    </div>

                    <div class="confidence-card">
                        <h3>Audit Confidence</h3>
                        <div class="big-score" style="color: var(--blue);">86%</div>
                        <p>Replay-ready, evidence-backed, and decision-ledger supported, with limitations on conditional claims.</p>

                        <div class="confidence-row">
                            <div class="key">Replay</div>
                            <div class="bar"><div class="fill" style="width:94%; background:var(--green);"></div></div>
                            <div class="score">94</div>
                        </div>
                        <div class="confidence-row">
                            <div class="key">Claims</div>
                            <div class="bar"><div class="fill" style="width:82%; background:var(--blue);"></div></div>
                            <div class="score">82</div>
                        </div>
                        <div class="confidence-row">
                            <div class="key">Exceptions</div>
                            <div class="bar"><div class="fill" style="width:76%; background:var(--yellow);"></div></div>
                            <div class="score">76</div>
                        </div>
                    </div>

                    <div class="confidence-card">
                        <h3>Operations Confidence</h3>
                        <div class="big-score" style="color: var(--orange);">74%</div>
                        <p>Operational trust is limited by support-routing and LCM ownership evidence gaps.</p>

                        <div class="confidence-row">
                            <div class="key">Support</div>
                            <div class="bar"><div class="fill" style="width:68%; background:var(--orange);"></div></div>
                            <div class="score">68</div>
                        </div>
                        <div class="confidence-row">
                            <div class="key">Incident Path</div>
                            <div class="bar"><div class="fill" style="width:71%; background:var(--yellow);"></div></div>
                            <div class="score">71</div>
                        </div>
                        <div class="confidence-row">
                            <div class="key">Continuity</div>
                            <div class="bar"><div class="fill" style="width:83%; background:var(--green);"></div></div>
                            <div class="score">83</div>
                        </div>
                    </div>

                    <div class="confidence-card">
                        <h3>Executive Claim Confidence</h3>
                        <div class="big-score" style="color: var(--purple);">81%</div>
                        <p>Leadership may rely with limitation language until support, access, and exception gates fully close.</p>

                        <div class="confidence-row">
                            <div class="key">Safe Claims</div>
                            <div class="bar"><div class="fill" style="width:83%; background:var(--green);"></div></div>
                            <div class="score">83</div>
                        </div>
                        <div class="confidence-row">
                            <div class="key">Conditional</div>
                            <div class="bar"><div class="fill" style="width:78%; background:var(--yellow);"></div></div>
                            <div class="score">78</div>
                        </div>
                        <div class="confidence-row">
                            <div class="key">Blocked</div>
                            <div class="bar"><div class="fill" style="width:35%; background:var(--red);"></div></div>
                            <div class="score">35</div>
                        </div>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Confidence Engines</h2>

                <div class="cards">
                    <div class="card">
                        <h3>Persona Confidence Model</h3>
                        <p>Calculates different confidence levels for CIO, QA, cyber, audit, operations, and executive stakeholders.</p>
                    </div>

                    <div class="card">
                        <h3>Claim Confidence Filter</h3>
                        <p>Maps confidence scores to allowed, conditional, or blocked executive statements.</p>
                    </div>

                    <div class="card">
                        <h3>Confidence Driver Analysis</h3>
                        <p>Identifies which evidence domain is lifting or reducing confidence for each stakeholder.</p>
                    </div>

                    <div class="card">
                        <h3>Confidence Recovery Path</h3>
                        <p>Links confidence gaps to Trust Market investments and minimum control interventions.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Confidence Decision Matrix</h2>

                <table>
                    <thead>
                        <tr>
                            <th>Persona</th>
                            <th>Confidence</th>
                            <th>Can Safely Rely On</th>
                            <th>Must Treat As Conditional</th>
                            <th>Blocked Claim</th>
                            <th>Confidence Recovery Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>CIO</strong></td>
                            <td><span class="badge blue">84%</span></td>
                            <td>ServiceNow AI governance architecture and low-risk agent actions.</td>
                            <td>High-impact lifecycle, certificate, support, and access changes.</td>
                            <td>AI can autonomously govern all ServiceNow trust states.</td>
                            <td>Maintain Agent Passport and Black Box replay for every AI action.</td>
                        </tr>

                        <tr>
                            <td><strong>QA</strong></td>
                            <td><span class="badge green">92%</span></td>
                            <td>Lifecycle closure evidence, human oversight, replay, and inspection traceability.</td>
                            <td>AI-prepared readiness recommendations.</td>
                            <td>AI replaces QA or validation ownership.</td>
                            <td>Keep human approval mandatory for regulated conclusions.</td>
                        </tr>

                        <tr>
                            <td><strong>Cyber</strong></td>
                            <td><span class="badge yellow">78%</span></td>
                            <td>Access gap detection and access evidence packaging.</td>
                            <td>Privileged access assurance while review proof is stale.</td>
                            <td>Agent can approve privileged access autonomously.</td>
                            <td>Enforce full access evidence bundle before renewal or reliance.</td>
                        </tr>

                        <tr>
                            <td><strong>Audit</strong></td>
                            <td><span class="badge blue">86%</span></td>
                            <td>Prompt-to-outcome replay and evidence lineage.</td>
                            <td>Claims where support or access evidence is incomplete.</td>
                            <td>All AI actions are fully inspection-ready regardless of evidence.</td>
                            <td>Run Claim Firewall before leadership statements.</td>
                        </tr>

                        <tr>
                            <td><strong>Operations</strong></td>
                            <td><span class="badge orange">74%</span></td>
                            <td>Operational continuity where support and lifecycle are clear.</td>
                            <td>Support routing until LCM and resolver evidence are mandatory.</td>
                            <td>Support ownership is fully reliable.</td>
                            <td>Make support and LCM evidence gate mandatory.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Confidence Recovery Queue</h2>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Confidence Gap</th>
                            <th>Persona Affected</th>
                            <th>Required Control</th>
                            <th>Expected Confidence Lift</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Support and LCM ambiguity limits operational and executive reliance.</td>
                            <td>Operations / CIO / Audit</td>
                            <td>Mandatory support group, resolver path, LCM, escalation owner, evidence location, and cadence gate.</td>
                            <td>+14%</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">2</span></td>
                            <td>Access evidence freshness limits cyber confidence.</td>
                            <td>Cyber / QA / Audit</td>
                            <td>Full MyAccess, approver, admin/vendor, jump path, review proof, and post-access verification bundle.</td>
                            <td>+11%</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Hidden dependencies reduce inspection confidence.</td>
                            <td>Audit / QA / CIO</td>
                            <td>Force candidate creation for backup, audit, access, support, workstation, or review dependencies.</td>
                            <td>+10%</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Exception escalation remains partially enforced.</td>
                            <td>QA / Audit / Executive</td>
                            <td>Require escalation owner, expiry date, closure evidence, residual-risk statement, and decision-ledger entry.</td>
                            <td>+7%</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, ServiceNow AI agents, AI Control Tower, CMDB, CSDM, ITSM, ITOM, MyAccess, validation systems, quality systems, audit systems, or accountable human governance. Executive Confidence Index™ is a governance assurance overlay that translates ServiceNow AI and CMDB trust evidence into persona-specific confidence for CIOs, QA, cyber, audit, operations, and executive leadership, making reliance explainable, conditional, blocked, or defensible.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_EXECUTIVE_CONFIDENCE_INDEX_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Executive Confidence Index installed.")
