from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CAUSAL_ASSURANCE_GRAPH_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/causal-assurance-graph")'
ROUTE_ALIAS = '@app.route("/citrust/trust-causality-engine")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Causal Assurance Graph already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CAUSAL_ASSURANCE_GRAPH_V1_ACTIVE
# ============================================================

@app.route("/citrust/causal-assurance-graph")
@app.route("/citrust/trust-causality-engine")
def citrust_causal_assurance_graph():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Causal Assurance Graph</title>
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
                    radial-gradient(circle at top left, rgba(180,156,255,0.18), transparent 30%),
                    radial-gradient(circle at top right, rgba(92,200,255,0.18), transparent 28%),
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
                max-width: 1160px;
                margin-top: 14px;
            }

            .positioning {
                margin-top: 18px;
                padding: 16px 18px;
                border: 1px solid rgba(180,156,255,0.38);
                background: rgba(180,156,255,0.10);
                border-radius: 16px;
                color: #eee7ff;
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
                min-height: 155px;
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

            .causal-map {
                display: grid;
                grid-template-columns: 1fr 1fr 1fr;
                gap: 16px;
                margin-top: 16px;
            }

            .node {
                border: 1px solid rgba(92,200,255,0.30);
                background: rgba(92,200,255,0.08);
                border-radius: 18px;
                padding: 18px;
                min-height: 150px;
            }

            .node h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .node p {
                margin: 0;
                color: #d9f3ff;
                font-size: 14px;
                line-height: 1.6;
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
                .kpis, .cards, .two-col, .causal-map {
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
                <h1>CITrust™ Causal Assurance Graph</h1>

                <div class="subtitle">
                    A world-class causal reasoning layer that explains not only what CITrust™ risk exists, but what caused it, what it will break next, which controls are upstream, which evidence is decisive, and the smallest intervention that prevents trust collapse.
                </div>

                <div class="positioning">
                    <strong>Category-defining capability:</strong>
                    Dashboards show symptoms. The CITrust™ Causal Assurance Graph shows cause, effect, propagation, and prevention. It converts CI governance from “status reporting” into “root-cause trust reasoning” by mapping every assurance weakness to its causal chain, downstream blast radius, and minimum control intervention.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/assurance-claim-firewall">Claim Firewall</a>
                    <a href="/citrust/trust-failure-premortem-engine">Trust Failure Pre-Mortem</a>
                    <a href="/citrust/executive-assurance-digital-twin">Assurance Digital Twin</a>
                    <a href="/citrust/executive-assurance-decision-ledger">Assurance Decision Ledger</a>
                    <a href="/citrust/control-maturity-uplift-roadmap">Maturity Roadmap</a>
                    <a href="/citrust/trust-decay-forecast">Trust Decay Forecast</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Causal Chains Mapped</div>
                    <div class="value">29</div>
                    <div class="note">Linked cause-effect paths across controls, evidence, exceptions, and reliance.</div>
                </div>

                <div class="metric">
                    <div class="label">Root Causes Found</div>
                    <div class="value" style="color: var(--red);">8</div>
                    <div class="note">Upstream weaknesses driving multiple downstream assurance failures.</div>
                </div>

                <div class="metric">
                    <div class="label">Downstream Risks</div>
                    <div class="value" style="color: var(--orange);">17</div>
                    <div class="note">Risks expected to spread if root causes remain unresolved.</div>
                </div>

                <div class="metric">
                    <div class="label">Minimum Interventions</div>
                    <div class="value" style="color: var(--green);">5</div>
                    <div class="note">Smallest control actions predicted to prevent the widest failure spread.</div>
                </div>

                <div class="metric">
                    <div class="label">False Positives Reduced</div>
                    <div class="value" style="color: var(--blue);">38%</div>
                    <div class="note">Noise reduction by focusing on causal drivers instead of dashboard symptoms.</div>
                </div>

                <div class="metric">
                    <div class="label">Assurance Leverage</div>
                    <div class="value" style="color: var(--purple);">High</div>
                    <div class="note">Current opportunity to improve multiple controls by fixing shared root causes.</div>
                </div>
            </section>

            <section class="section">
                <h2>Causal Assurance Answer</h2>
                <p>
                    This page answers what is causing CITrust™ assurance weakness and what must be fixed first.
                </p>

                <div class="answer">
                    <strong>Current causal interpretation:</strong>
                    The largest trust weakness is not one isolated CI or one missing field. The causal graph shows that support/LCM ambiguity, hidden-dependency bypass, incomplete access evidence, weak exception escalation, and conditional cutover proof are upstream causes. If those upstream causes are fixed, multiple downstream failures disappear at once.
                </div>
            </section>

            <section class="section">
                <h2>Causal Reasoning Engines</h2>
                <p>
                    CITrust™ uses causal reasoning to identify high-leverage governance actions.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Root-Cause Trust Mapper</h3>
                        <p>Finds the upstream control weakness that causes repeated evidence gaps, exceptions, conditional certificates, and blocked assurance claims.</p>
                    </div>

                    <div class="card">
                        <h3>Blast-Radius Predictor</h3>
                        <p>Shows which CIs, certificates, passports, access paths, support models, or executive claims will be affected if the cause remains unresolved.</p>
                    </div>

                    <div class="card">
                        <h3>Minimum Intervention Solver</h3>
                        <p>Identifies the smallest control change that prevents the largest number of downstream assurance failures.</p>
                    </div>

                    <div class="card">
                        <h3>Counterfactual Control Tester</h3>
                        <p>Tests whether the failure would still occur if a proposed gate, evidence bundle, reviewer rule, or escalation rule had already existed.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Causal Graph Snapshot</h2>
                <p>
                    This is the executive “what causes what?” view.
                </p>

                <div class="causal-map">
                    <div class="node">
                        <h3><span class="badge red">Root Cause</span> Support / LCM Ambiguity</h3>
                        <p>
                            Causes weak incident routing, unclear ownership, ServiceNow-readiness gaps, audit-defense weakness, and unreliable executive reliance language.
                        </p>
                    </div>

                    <div class="node">
                        <h3><span class="badge orange">Propagation</span> Hidden Dependency Bypass</h3>
                        <p>
                            Allows backup, audit, access, workstation, or review dependencies to support trusted CIs without becoming governed CI candidates.
                        </p>
                    </div>

                    <div class="node">
                        <h3><span class="badge green">Minimum Intervention</span> Mandatory Evidence Gates</h3>
                        <p>
                            Fixing support/LCM, access evidence, exception escalation, and hidden-dependency intake prevents the widest spread of future trust failure.
                        </p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Causal Assurance Matrix</h2>
                <p>
                    This matrix shows the cause, consequence, and minimum preventive control.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Upstream Cause</th>
                            <th>Immediate Symptom</th>
                            <th>Downstream Failure</th>
                            <th>Blast Radius</th>
                            <th>Minimum Intervention</th>
                            <th>Causal Confidence</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Support and LCM evidence is not mandatory</strong></td>
                            <td>Support-routing assurance remains inconsistent.</td>
                            <td>Incident response, ServiceNow-readiness, and audit defense cannot be fully defended.</td>
                            <td><span class="badge red">High</span></td>
                            <td>Mandatory Support and LCM Confirmation Gate.</td>
                            <td><span class="badge red">Strong Cause</span></td>
                            <td>Block candidate approval unless support group, resolver path, LCM, escalation owner, evidence location, and cadence are complete.</td>
                        </tr>

                        <tr>
                            <td><strong>Hidden dependency intake remains partly manual</strong></td>
                            <td>Dependencies may support trusted CIs without candidate records.</td>
                            <td>Governance debt remains invisible until audit, incident, backup, or access review exposes it.</td>
                            <td><span class="badge red">High</span></td>
                            <td>Hidden-Dependency Candidate Creation Trigger.</td>
                            <td><span class="badge orange">Likely Cause</span></td>
                            <td>Force CI candidate creation for backup, audit, access, support, workstation, or review dependencies.</td>
                        </tr>

                        <tr>
                            <td><strong>Privileged access proof is incomplete or stale</strong></td>
                            <td>Access assurance must remain conditional.</td>
                            <td>Executive claims about admin/vendor/jump path governance become weak or overstated.</td>
                            <td><span class="badge orange">Medium-High</span></td>
                            <td>Privileged Access Evidence Bundle Gate.</td>
                            <td><span class="badge yellow">Probable Cause</span></td>
                            <td>Block renewal unless MyAccess mapping, approver group, admin/vendor procedure, jump path, review proof, and post-access verification are current.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception escalation owner is not enforced</strong></td>
                            <td>Exceptions remain visible but can still age without closure discipline.</td>
                            <td>Overdue exceptions become governance debt and weaken audit defense.</td>
                            <td><span class="badge orange">Medium-High</span></td>
                            <td>Exception Expiry Escalation Rule.</td>
                            <td><span class="badge orange">Likely Cause</span></td>
                            <td>Require escalation owner, expiry date, closure evidence, residual-risk statement, and decision-ledger entry.</td>
                        </tr>

                        <tr>
                            <td><strong>Cutover evidence is bundled but not complete</strong></td>
                            <td>Cutover-sensitive readiness remains conditional.</td>
                            <td>Leadership may overstate readiness before rollback, recovery, vendor, and post-cutover verification proof exists.</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Cutover Recovery Attestation Gate.</td>
                            <td><span class="badge yellow">Probable Cause</span></td>
                            <td>Require support, access, vendor handoff, rollback readiness, recovery attestation, and post-cutover verification before certificate-ready status.</td>
                        </tr>

                        <tr>
                            <td><strong>Certificate state is treated as static</strong></td>
                            <td>Certificate may look valid while evidence freshness decays.</td>
                            <td>Certificate-ready language can become misleading if access review, exception, lifecycle, or support evidence changes.</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Evidence Freshness Linkage Gate.</td>
                            <td><span class="badge yellow">Emerging Cause</span></td>
                            <td>Link certificate state to evidence age, access review status, lifecycle closure, exception state, and continuous trust monitoring.</td>
                        </tr>

                        <tr>
                            <td><strong>Executive action closes without proof of control change</strong></td>
                            <td>Action appears closed but assurance does not improve.</td>
                            <td>Same weakness recurs and damages trust in the governance operating model.</td>
                            <td><span class="badge orange">Medium-High</span></td>
                            <td>Executive Action Closure Attestation.</td>
                            <td><span class="badge orange">Likely Cause</span></td>
                            <td>Require closure evidence, reviewer acceptance, assurance-state update, and decision-ledger rationale.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Causal Decision Logic</h2>
                <p>
                    CITrust™ prioritizes causes over symptoms.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Root Cause Is Confirmed When</h3>
                        <ul>
                            <li>One weakness creates multiple downstream assurance gaps.</li>
                            <li>Same pattern repeats across different CIs or controls.</li>
                            <li>Fixing the weakness would eliminate several exceptions.</li>
                            <li>Failure persists after local remediation.</li>
                            <li>Evidence shows owner, access, lifecycle, or escalation ambiguity.</li>
                            <li>Executive claim risk traces back to the same missing gate.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Only A Symptom When</h3>
                        <ul>
                            <li>The issue affects one CI only and does not recur.</li>
                            <li>Underlying owner, evidence, and escalation model are strong.</li>
                            <li>The gap closes without changing a reusable control.</li>
                            <li>There is no downstream reliance or audit impact.</li>
                            <li>Certificate state remains aligned with evidence freshness.</li>
                            <li>Decision ledger shows a clear one-time rationale.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Minimum Intervention Queue</h2>
                <p>
                    These are the smallest actions predicted to prevent the most downstream trust failures.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Minimum Intervention</th>
                            <th>Why It Has High Leverage</th>
                            <th>Control It Improves</th>
                            <th>Expected Downstream Prevention</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Make support and LCM evidence mandatory.</td>
                            <td>One rule prevents support-routing ambiguity, weak incident defense, CMDB-readiness gaps, and unsupported executive reliance.</td>
                            <td>Support and LCM Confirmation Gate.</td>
                            <td>Prevents multiple support, incident, audit, and ServiceNow-readiness failures.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Force hidden-dependency candidate creation.</td>
                            <td>One intake rule prevents invisible governance debt behind backup, audit, access, workstation, and review dependencies.</td>
                            <td>Hidden Dependency Intake Trigger.</td>
                            <td>Prevents hidden dependency bypass and future certificate blind spots.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Require escalation owner for every exception.</td>
                            <td>One owner rule prevents aging exceptions from becoming normalized governance debt.</td>
                            <td>Exception Expiry Escalation Rule.</td>
                            <td>Prevents overdue exception accumulation and weak audit defense.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Block renewal when access evidence is stale.</td>
                            <td>One renewal gate prevents overstated access assurance across admin, vendor, jump path, and MyAccess controls.</td>
                            <td>Privileged Access Evidence Bundle.</td>
                            <td>Prevents unsupported access reliance and conditional certificate renewal.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This causal assurance graph is a governance assurance overlay for causal trust reasoning, root-cause mapping, blast-radius prediction, counterfactual control testing, minimum intervention selection, certificate readiness defense, CMDB-readiness defense, audit survivability, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_CAUSAL_ASSURANCE_GRAPH_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Causal Assurance Graph installed.")
