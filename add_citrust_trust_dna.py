from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_TRUST_DNA_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/trust-dna")'
ROUTE_ALIAS = '@app.route("/citrust/ci-trust-genome")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Trust DNA already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_TRUST_DNA_V1_ACTIVE
# ============================================================

@app.route("/citrust/trust-dna")
@app.route("/citrust/ci-trust-genome")
def citrust_trust_dna():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Trust DNA</title>
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
                    radial-gradient(circle at top left, rgba(180,156,255,0.20), transparent 30%),
                    radial-gradient(circle at top right, rgba(92,200,255,0.18), transparent 28%),
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
                    radial-gradient(circle at right, rgba(180,156,255,0.16), transparent 40%);
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
                border: 1px solid rgba(180,156,255,0.38);
                background: rgba(180,156,255,0.10);
                border-radius: 18px;
                color: #eee7ff;
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

            .dna-grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 18px;
                margin-top: 16px;
            }

            .dna-card {
                border: 1px solid rgba(180,156,255,0.32);
                background:
                    linear-gradient(135deg, rgba(255,255,255,0.06), rgba(180,156,255,0.07)),
                    rgba(255,255,255,0.035);
                border-radius: 22px;
                padding: 22px;
                min-height: 300px;
                position: relative;
                overflow: hidden;
            }

            .dna-card:after {
                content: "TRUST DNA";
                position: absolute;
                right: -24px;
                top: 42px;
                transform: rotate(28deg);
                color: rgba(180,156,255,0.16);
                font-size: 39px;
                font-weight: 900;
                letter-spacing: 4px;
            }

            .dna-card h3 {
                margin: 0 0 12px 0;
                font-size: 22px;
            }

            .dna-row {
                display: grid;
                grid-template-columns: 190px 1fr 70px;
                gap: 12px;
                align-items: center;
                padding: 11px 0;
                border-bottom: 1px solid rgba(255,255,255,0.08);
                font-size: 14px;
            }

            .dna-row .key {
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

            .helix {
                display: grid;
                gap: 10px;
                margin-top: 16px;
            }

            .helix-line {
                border: 1px solid rgba(92,200,255,0.25);
                background: rgba(92,200,255,0.07);
                border-radius: 15px;
                padding: 14px;
                display: grid;
                grid-template-columns: 180px 1fr 160px;
                gap: 12px;
                align-items: center;
                font-size: 14px;
            }

            .helix-line .gene {
                color: var(--cyan);
                font-weight: 900;
            }

            .helix-line .meaning {
                color: var(--text);
            }

            .helix-line .mutation {
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
                .kpis, .cards, .dna-grid {
                    grid-template-columns: 1fr;
                }

                .dna-row, .helix-line {
                    grid-template-columns: 1fr;
                }

                .helix-line .mutation, .score {
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
                <div class="eyebrow">CITrust™ / ServiceNow AI / Living Governance Genome</div>
                <h1>CITrust™ Trust DNA</h1>

                <div class="subtitle">
                    A living governance genome for every ServiceNow CI and autonomous AI action, converting ownership, evidence, access, lifecycle, support, certificate, exception, change, rollback, and replay signals into a unique Trust DNA profile that detects abnormal trust mutations before failure.
                </div>

                <div class="positioning">
                    <strong>ServiceNow-focused positioning:</strong>
                    ServiceNow shows CI data. CITrust™ creates a living Trust DNA fingerprint that explains whether the CI’s governance genome is stable, mutating, decaying, or safe for autonomous operations.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/autonomous-agent-governance-passport">Agent Passport</a>
                    <a href="/citrust/governance-black-box">Governance Black Box</a>
                    <a href="/citrust/assurance-claim-firewall">Claim Firewall</a>
                    <a href="/citrust/causal-assurance-graph">Causal Assurance Graph</a>
                    <a href="/citrust/trust-failure-premortem-engine">Trust Failure Pre-Mortem</a>
                    <a href="/citrust/executive-assurance-digital-twin">Assurance Digital Twin</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Trust Genome</div>
                    <div class="value" style="color: var(--purple);">Stable</div>
                    <div class="note">Current CI governance genome is stable with monitored mutations.</div>
                </div>

                <div class="metric">
                    <div class="label">Trust DNA Score</div>
                    <div class="value" style="color: var(--green);">88</div>
                    <div class="note">Composite governance genome score across trust markers.</div>
                </div>

                <div class="metric">
                    <div class="label">Active Mutations</div>
                    <div class="value" style="color: var(--yellow);">3</div>
                    <div class="note">Detected governance changes requiring monitoring.</div>
                </div>

                <div class="metric">
                    <div class="label">High-Risk Mutations</div>
                    <div class="value" style="color: var(--red);">1</div>
                    <div class="note">Mutation could affect support or executive reliance if unresolved.</div>
                </div>

                <div class="metric">
                    <div class="label">Autonomous Ready</div>
                    <div class="value" style="color: var(--blue);">Partial</div>
                    <div class="note">Low-risk actions allowed; high-impact actions human-gated.</div>
                </div>

                <div class="metric">
                    <div class="label">Genome Drift</div>
                    <div class="value" style="color: var(--orange);">+7%</div>
                    <div class="note">Trust profile shifted due to support and access evidence changes.</div>
                </div>
            </section>

            <section class="section">
                <h2>Trust DNA Answer</h2>
                <p>
                    This page answers whether a ServiceNow CI’s governance identity is stable enough to trust.
                </p>

                <div class="answer">
                    <strong>Current genome interpretation:</strong>
                    The CI’s Trust DNA remains generally stable, but support continuity and access integrity show mutation signals. CITrust™ should allow low-risk AI recommendations while blocking autonomous trust, certificate, lifecycle, or support-ownership changes until the mutation is reviewed.
                </div>
            </section>

            <section class="section">
                <h2>Living Trust DNA Profile</h2>

                <div class="dna-grid">
                    <div class="dna-card">
                        <h3>CI Governance Genome: Niagara BMS</h3>

                        <div class="dna-row">
                            <div class="key">Owner Stability</div>
                            <div class="bar"><div class="fill" style="width:92%; background:var(--green);"></div></div>
                            <div class="score">92</div>
                        </div>

                        <div class="dna-row">
                            <div class="key">Evidence Freshness</div>
                            <div class="bar"><div class="fill" style="width:86%; background:var(--green);"></div></div>
                            <div class="score">86</div>
                        </div>

                        <div class="dna-row">
                            <div class="key">Access Integrity</div>
                            <div class="bar"><div class="fill" style="width:74%; background:var(--yellow);"></div></div>
                            <div class="score">74</div>
                        </div>

                        <div class="dna-row">
                            <div class="key">Support Continuity</div>
                            <div class="bar"><div class="fill" style="width:68%; background:var(--orange);"></div></div>
                            <div class="score">68</div>
                        </div>

                        <div class="dna-row">
                            <div class="key">Lifecycle Stability</div>
                            <div class="bar"><div class="fill" style="width:91%; background:var(--green);"></div></div>
                            <div class="score">91</div>
                        </div>

                        <div class="dna-row">
                            <div class="key">Certificate Confidence</div>
                            <div class="bar"><div class="fill" style="width:83%; background:var(--green);"></div></div>
                            <div class="score">83</div>
                        </div>

                        <div class="dna-row">
                            <div class="key">AI Action Readiness</div>
                            <div class="bar"><div class="fill" style="width:79%; background:var(--yellow);"></div></div>
                            <div class="score">79</div>
                        </div>
                    </div>

                    <div class="dna-card">
                        <h3>Trust Mutation Summary</h3>

                        <div class="helix">
                            <div class="helix-line">
                                <div class="gene">GENE-SUP-01</div>
                                <div class="meaning">Support group evidence changed without full LCM confirmation.</div>
                                <div class="mutation"><span class="badge orange">Watch</span></div>
                            </div>

                            <div class="helix-line">
                                <div class="gene">GENE-ACC-04</div>
                                <div class="meaning">Admin/vendor access procedure requires freshness review.</div>
                                <div class="mutation"><span class="badge yellow">Conditional</span></div>
                            </div>

                            <div class="helix-line">
                                <div class="gene">GENE-CERT-02</div>
                                <div class="meaning">Certificate confidence remains valid but should be linked to evidence freshness.</div>
                                <div class="mutation"><span class="badge blue">Monitor</span></div>
                            </div>

                            <div class="helix-line">
                                <div class="gene">GENE-AI-07</div>
                                <div class="meaning">Autonomous action scope is safe only for draft and recommendation activity.</div>
                                <div class="mutation"><span class="badge green">Controlled</span></div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Trust DNA Engines</h2>
                <p>
                    CITrust™ creates a living governance genome from ServiceNow and evidence-based trust markers.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Governance Genome Builder</h3>
                        <p>Creates a unique CI fingerprint from owner, support, access, lifecycle, evidence, certificate, exception, and change markers.</p>
                    </div>

                    <div class="card">
                        <h3>Trust Mutation Detector</h3>
                        <p>Detects abnormal governance shifts such as support owner change, stale access evidence, certificate drift, or hidden dependency emergence.</p>
                    </div>

                    <div class="card">
                        <h3>Genome Drift Monitor</h3>
                        <p>Tracks whether CI trust is improving, decaying, or mutating based on evidence freshness and control maturity over time.</p>
                    </div>

                    <div class="card">
                        <h3>Autonomous Readiness Gate</h3>
                        <p>Determines whether ServiceNow AI actions can proceed based on Trust DNA stability and authority-envelope limits.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Trust DNA Marker Matrix</h2>

                <table>
                    <thead>
                        <tr>
                            <th>Trust Gene</th>
                            <th>Marker Meaning</th>
                            <th>Current Signal</th>
                            <th>Mutation Risk</th>
                            <th>ServiceNow AI Impact</th>
                            <th>Required Control</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>GENE-OWN-01</strong></td>
                            <td>Owner stability and accountable governance ownership.</td>
                            <td><span class="badge green">Stable</span></td>
                            <td>Low.</td>
                            <td>AI may prepare ownership evidence but not change owner autonomously.</td>
                            <td>Human approval for owner change.</td>
                        </tr>

                        <tr>
                            <td><strong>GENE-SUP-01</strong></td>
                            <td>Support group, resolver path, LCM, and escalation ownership continuity.</td>
                            <td><span class="badge orange">Mutating</span></td>
                            <td>High if support gate remains non-mandatory.</td>
                            <td>AI can recommend correction only.</td>
                            <td>Mandatory support and LCM evidence gate.</td>
                        </tr>

                        <tr>
                            <td><strong>GENE-ACC-04</strong></td>
                            <td>Privileged access proof, MyAccess mapping, admin/vendor procedure, and access review freshness.</td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Medium.</td>
                            <td>AI cannot approve access-impacting updates.</td>
                            <td>Full access evidence bundle before reliance.</td>
                        </tr>

                        <tr>
                            <td><strong>GENE-LIFE-03</strong></td>
                            <td>Lifecycle state stability, OOS closure evidence, access deactivation, and restoration control.</td>
                            <td><span class="badge green">Stable</span></td>
                            <td>Low if closure evidence remains mandatory.</td>
                            <td>AI cannot change lifecycle state.</td>
                            <td>Lifecycle human gate remains mandatory.</td>
                        </tr>

                        <tr>
                            <td><strong>GENE-CERT-02</strong></td>
                            <td>Certificate confidence, evidence freshness, exception state, and renewal defensibility.</td>
                            <td><span class="badge blue">Monitored</span></td>
                            <td>Medium if evidence freshness decays.</td>
                            <td>AI can prepare certificate evidence pack only.</td>
                            <td>Certificate state linked to evidence freshness.</td>
                        </tr>

                        <tr>
                            <td><strong>GENE-AI-07</strong></td>
                            <td>Autonomous action authority, replayability, rollback readiness, and human oversight.</td>
                            <td><span class="badge green">Controlled</span></td>
                            <td>Low inside envelope; high outside envelope.</td>
                            <td>Low-risk recommendation allowed.</td>
                            <td>Agent Governance Passport and Black Box required.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Trust DNA Control Decision</h2>

                <div class="cards">
                    <div class="card">
                        <h3>Allow AI Recommendation</h3>
                        <p>Trust DNA is stable enough for draft CI, evidence prep, support recommendation, and non-final governance guidance.</p>
                    </div>

                    <div class="card">
                        <h3>Require Human Approval</h3>
                        <p>Mutation affects support, access, lifecycle, certificate, exception, trust score, or regulated readiness status.</p>
                    </div>

                    <div class="card">
                        <h3>Quarantine Mutation</h3>
                        <p>Mutation creates unsupported certificate change, owner ambiguity, evidence decay, hidden dependency, or audit-defense weakness.</p>
                    </div>

                    <div class="card">
                        <h3>Recompute Passport</h3>
                        <p>Agent Governance Passport must refresh when Trust DNA changes beyond approved mutation threshold.</p>
                    </div>
                </div>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, ServiceNow AI agents, AI Control Tower, CMDB, CSDM, ITSM, ITOM, MyAccess, validation systems, quality systems, audit systems, or accountable human governance. Trust DNA™ is a governance assurance overlay that converts ServiceNow CI signals and evidence markers into a living governance genome for trust stability, mutation detection, evidence decay monitoring, autonomous action readiness, certificate defensibility, and executive reliance control.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_TRUST_DNA_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Trust DNA installed.")
