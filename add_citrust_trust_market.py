from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_TRUST_MARKET_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/trust-market")'
ROUTE_ALIAS = '@app.route("/citrust/governance-roi-market")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Trust Market already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_TRUST_MARKET_V1_ACTIVE
# ============================================================

@app.route("/citrust/trust-market")
@app.route("/citrust/governance-roi-market")
def citrust_trust_market():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Trust Market</title>
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
                    radial-gradient(circle at bottom right, rgba(247,201,72,0.12), transparent 30%),
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

            .market-grid {
                display: grid;
                grid-template-columns: 1.1fr 0.9fr;
                gap: 18px;
                margin-top: 16px;
            }

            .market-card {
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

            .market-card:after {
                content: "TRUST ROI";
                position: absolute;
                right: -24px;
                top: 42px;
                transform: rotate(28deg);
                color: rgba(49,208,125,0.16);
                font-size: 39px;
                font-weight: 900;
                letter-spacing: 4px;
            }

            .market-card h3 {
                margin: 0 0 12px 0;
                font-size: 22px;
            }

            .investment-row {
                display: grid;
                grid-template-columns: 1fr 90px 90px 110px;
                gap: 12px;
                align-items: center;
                padding: 12px 0;
                border-bottom: 1px solid rgba(255,255,255,0.08);
                font-size: 14px;
            }

            .investment-row .name {
                color: var(--text);
                font-weight: 800;
            }

            .investment-row .num {
                color: var(--cyan);
                font-weight: 900;
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
                .kpis, .cards, .market-grid {
                    grid-template-columns: 1fr;
                }

                .investment-row {
                    grid-template-columns: 1fr;
                }

                .investment-row .num {
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
                <div class="eyebrow">CITrust™ / ServiceNow AI / Governance Return-on-Investment</div>
                <h1>CITrust™ Trust Market</h1>

                <div class="subtitle">
                    Executive governance market for ServiceNow AI and CMDB assurance, ranking which control investments generate the highest increase in trust, readiness, audit defensibility, inspection survivability, and autonomous-action safety.
                </div>

                <div class="positioning">
                    <strong>ServiceNow-focused positioning:</strong>
                    ServiceNow helps teams execute work. CITrust™ Trust Market tells leaders where to invest limited governance effort to gain the largest measurable trust improvement across ServiceNow CMDB, access, support, certificate, and AI-agent operations.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/trust-dna">Trust DNA</a>
                    <a href="/citrust/autonomous-agent-governance-passport">Agent Passport</a>
                    <a href="/citrust/governance-black-box">Governance Black Box</a>
                    <a href="/citrust/assurance-claim-firewall">Claim Firewall</a>
                    <a href="/citrust/causal-assurance-graph">Causal Assurance Graph</a>
                    <a href="/citrust/executive-assurance-digital-twin">Assurance Digital Twin</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Available Governance Hours</div>
                    <div class="value" style="color: var(--blue);">40h</div>
                    <div class="note">Leadership capacity available for trust improvement this cycle.</div>
                </div>

                <div class="metric">
                    <div class="label">Best Trust Gain</div>
                    <div class="value" style="color: var(--green);">+31</div>
                    <div class="note">Highest modeled confidence gain from one control investment.</div>
                </div>

                <div class="metric">
                    <div class="label">Top ROI Control</div>
                    <div class="value" style="color: var(--green);">Hidden Intake</div>
                    <div class="note">Best trust return per governance hour invested.</div>
                </div>

                <div class="metric">
                    <div class="label">Wasted Effort Avoided</div>
                    <div class="value" style="color: var(--orange);">18h</div>
                    <div class="note">Effort redirected away from low-leverage dashboard work.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Confidence Lift</div>
                    <div class="value" style="color: var(--purple);">+24%</div>
                    <div class="note">Projected gain after top three investments close.</div>
                </div>

                <div class="metric">
                    <div class="label">Market Decision</div>
                    <div class="value" style="color: var(--yellow);">Invest</div>
                    <div class="note">Invest in support gate, hidden intake, and access evidence first.</div>
                </div>
            </section>

            <section class="section">
                <h2>Trust Market Answer</h2>
                <p>
                    This page answers where leadership should invest limited governance effort for maximum trust return.
                </p>

                <div class="answer">
                    <strong>Current market interpretation:</strong>
                    The best return is not another dashboard. The highest value comes from forcing hidden-dependency candidate creation, making support and LCM evidence mandatory, and blocking renewal when access evidence is incomplete. These three investments produce the largest downstream trust lift for ServiceNow AI and CMDB governance.
                </div>
            </section>

            <section class="section">
                <h2>Governance Investment Portfolio</h2>

                <div class="market-grid">
                    <div class="market-card">
                        <h3>Top Trust Investments</h3>

                        <div class="investment-row">
                            <div class="name">Hidden Dependency Candidate Creation</div>
                            <div class="num">+31</div>
                            <div class="num">8h</div>
                            <div><span class="badge green">Very High ROI</span></div>
                        </div>

                        <div class="investment-row">
                            <div class="name">Mandatory Support and LCM Gate</div>
                            <div class="num">+24</div>
                            <div class="num">6h</div>
                            <div><span class="badge green">Very High ROI</span></div>
                        </div>

                        <div class="investment-row">
                            <div class="name">Access Evidence Bundle Enforcement</div>
                            <div class="num">+16</div>
                            <div class="num">5h</div>
                            <div><span class="badge yellow">High ROI</span></div>
                        </div>

                        <div class="investment-row">
                            <div class="name">Exception Escalation Owner Rule</div>
                            <div class="num">+14</div>
                            <div class="num">4h</div>
                            <div><span class="badge yellow">High ROI</span></div>
                        </div>

                        <div class="investment-row">
                            <div class="name">Certificate Freshness Linkage</div>
                            <div class="num">+9</div>
                            <div class="num">7h</div>
                            <div><span class="badge orange">Medium ROI</span></div>
                        </div>
                    </div>

                    <div class="market-card">
                        <h3>Market Allocation Recommendation</h3>

                        <p style="color:#dfffea; line-height:1.7;">
                            Allocate the next 40 governance hours toward high-leverage controls that improve multiple downstream assurance areas at once.
                        </p>

                        <table>
                            <thead>
                                <tr>
                                    <th>Allocation</th>
                                    <th>Hours</th>
                                    <th>Expected Lift</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>Hidden Intake</td>
                                    <td>8h</td>
                                    <td>+31</td>
                                </tr>
                                <tr>
                                    <td>Support Gate</td>
                                    <td>6h</td>
                                    <td>+24</td>
                                </tr>
                                <tr>
                                    <td>Access Bundle</td>
                                    <td>5h</td>
                                    <td>+16</td>
                                </tr>
                                <tr>
                                    <td>Exception Rule</td>
                                    <td>4h</td>
                                    <td>+14</td>
                                </tr>
                                <tr>
                                    <td>Remaining Reserve</td>
                                    <td>17h</td>
                                    <td>Used for closure/retest</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Trust Market Engines</h2>

                <div class="cards">
                    <div class="card">
                        <h3>Governance ROI Engine</h3>
                        <p>Calculates which control action creates the greatest trust increase per hour of governance effort.</p>
                    </div>

                    <div class="card">
                        <h3>Trust Yield Curve</h3>
                        <p>Shows whether an investment produces immediate readiness gain, medium-term risk reduction, or long-term audit survivability.</p>
                    </div>

                    <div class="card">
                        <h3>Downstream Value Model</h3>
                        <p>Models how one control improvement increases support trust, certificate confidence, access defensibility, and AI safety.</p>
                    </div>

                    <div class="card">
                        <h3>Executive Allocation Optimizer</h3>
                        <p>Turns limited leadership, QA, IT, and governance capacity into the highest-value trust investment portfolio.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Trust Investment Matrix</h2>

                <table>
                    <thead>
                        <tr>
                            <th>Investment</th>
                            <th>Trust Gain</th>
                            <th>Effort</th>
                            <th>ROI Tier</th>
                            <th>Improves</th>
                            <th>ServiceNow AI Impact</th>
                            <th>Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Hidden Dependency Candidate Creation</strong></td>
                            <td>+31</td>
                            <td>8 hours</td>
                            <td><span class="badge green">Very High</span></td>
                            <td>Candidate intake, audit readiness, access review, support dependency, certificate confidence.</td>
                            <td>Prevents AI agents from relying on invisible dependencies.</td>
                            <td>Invest first.</td>
                        </tr>

                        <tr>
                            <td><strong>Mandatory Support and LCM Gate</strong></td>
                            <td>+24</td>
                            <td>6 hours</td>
                            <td><span class="badge green">Very High</span></td>
                            <td>Support trust, incident routing, CMDB readiness, executive reliance, audit defense.</td>
                            <td>Prevents AI from recommending unsupported CI trust.</td>
                            <td>Invest immediately.</td>
                        </tr>

                        <tr>
                            <td><strong>Access Evidence Bundle Enforcement</strong></td>
                            <td>+16</td>
                            <td>5 hours</td>
                            <td><span class="badge yellow">High</span></td>
                            <td>MyAccess, privileged access, vendor access, jump path, certificate renewal.</td>
                            <td>Blocks autonomous access-related recommendations without proof.</td>
                            <td>Invest this cycle.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception Escalation Owner Rule</strong></td>
                            <td>+14</td>
                            <td>4 hours</td>
                            <td><span class="badge yellow">High</span></td>
                            <td>Exception closure, residual risk, decision ledger, audit defense.</td>
                            <td>Prevents agents from normalizing unresolved exceptions.</td>
                            <td>Invest this cycle.</td>
                        </tr>

                        <tr>
                            <td><strong>Certificate Freshness Linkage</strong></td>
                            <td>+9</td>
                            <td>7 hours</td>
                            <td><span class="badge orange">Medium</span></td>
                            <td>Certificate readiness, evidence age, access review, lifecycle state.</td>
                            <td>Prevents agents from treating stale certificates as current trust.</td>
                            <td>Invest after top four.</td>
                        </tr>

                        <tr>
                            <td><strong>Visual Dashboard Enhancement</strong></td>
                            <td>+4</td>
                            <td>12 hours</td>
                            <td><span class="badge red">Low</span></td>
                            <td>Presentation only.</td>
                            <td>Does not materially improve agent trust safety.</td>
                            <td>Defer.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Market Decision Rules</h2>

                <div class="cards">
                    <div class="card">
                        <h3>Buy Trust</h3>
                        <p>Invest when one governance action improves multiple downstream controls, certificates, claims, and AI-action boundaries.</p>
                    </div>

                    <div class="card">
                        <h3>Hold Trust</h3>
                        <p>Monitor when evidence is stable, risk is controlled, and improvement produces limited marginal gain.</p>
                    </div>

                    <div class="card">
                        <h3>Sell / Defer Work</h3>
                        <p>Defer visual or cosmetic changes that do not improve evidence, ownership, access, readiness, or audit defensibility.</p>
                    </div>

                    <div class="card">
                        <h3>Rebalance Portfolio</h3>
                        <p>Reallocate effort when Trust DNA mutation, entropy, or AI action risk changes the return profile.</p>
                    </div>
                </div>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, ServiceNow AI agents, AI Control Tower, CMDB, CSDM, ITSM, ITOM, MyAccess, validation systems, quality systems, audit systems, or accountable human governance. Trust Market™ is a governance assurance overlay that calculates Governance Return on Investment for ServiceNow AI and CMDB operations, ranking which controls generate the largest trust gain, audit defensibility, inspection readiness, certificate confidence, and autonomous-action safety per governance hour invested.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_TRUST_MARKET_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Trust Market installed.")
