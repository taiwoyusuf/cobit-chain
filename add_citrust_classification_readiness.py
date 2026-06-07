from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CLASSIFICATION_READINESS_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/classification-readiness")'
ROUTE_ALIAS = '@app.route("/citrust/ci-classification")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Classification Readiness Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CLASSIFICATION_READINESS_V1_ACTIVE
# ============================================================

@app.route("/citrust/classification-readiness")
@app.route("/citrust/ci-classification")
def citrust_classification_readiness():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ CI Classification Readiness Console</title>
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
                    radial-gradient(circle at top right, rgba(180,156,255,0.16), transparent 28%),
                    radial-gradient(circle at bottom left, rgba(49,208,125,0.08), transparent 30%),
                    var(--bg);
                color: var(--text);
            }

            .page {
                max-width: 1400px;
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
                font-size: 39px;
                line-height: 1.1;
            }

            .subtitle {
                color: var(--muted);
                font-size: 16px;
                line-height: 1.6;
                max-width: 1080px;
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

            .flow {
                display: grid;
                grid-template-columns: repeat(5, 1fr);
                gap: 12px;
                margin-top: 16px;
            }

            .flow-step {
                border: 1px solid rgba(180,156,255,0.28);
                background: rgba(180,156,255,0.07);
                border-radius: 18px;
                padding: 16px;
            }

            .flow-step h3 {
                margin: 0 0 8px 0;
                font-size: 15px;
            }

            .flow-step p {
                margin: 0;
                font-size: 13px;
                color: var(--muted);
                line-height: 1.5;
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
                .kpis, .flow, .cards, .two-col {
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
                <h1>CITrust™ CI Classification Readiness Console</h1>

                <div class="subtitle">
                    Validates whether each Configuration Item has the correct CI class, operational category, GMP/GxP impact, business function, environment, criticality, lifecycle classification, and ServiceNow-readiness profile before it is treated as operationally trustworthy.
                </div>

                <div class="positioning">
                    <strong>Classification boundary:</strong>
                    ServiceNow may store CI class and related fields. CITrust™ validates whether the classification is accurate, complete, evidence-backed, and aligned with ownership, support group, MyAccess, lifecycle, dependency, audit, and change-impact readiness. This page does not create or update ServiceNow CIs.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/servicenow-ci-readiness">ServiceNow CI Readiness</a>
                    <a href="/citrust/reconciliation">CMDB Reconciliation</a>
                    <a href="/citrust/change-impact-readiness">Change Impact</a>
                    <a href="/citrust/lifecycle-readiness">Lifecycle Readiness</a>
                    <a href="/citrust/support-group-readiness">Support Routing</a>
                    <a href="/citrust/evidence-lineage">Evidence Lineage</a>
                    <a href="/citrust/trust-score-model">Trust Score Model</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Classification Checks</div>
                    <div class="value">42</div>
                    <div class="note">CIs assessed for class, category, environment, criticality, and GMP impact.</div>
                </div>

                <div class="metric">
                    <div class="label">Correctly Classified</div>
                    <div class="value" style="color: var(--green);">23</div>
                    <div class="note">Classification is consistent and operationally usable.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Class</div>
                    <div class="value" style="color: var(--yellow);">11</div>
                    <div class="note">Classification exists but needs evidence, owner, or impact confirmation.</div>
                </div>

                <div class="metric">
                    <div class="label">Misclassified Risk</div>
                    <div class="value" style="color: var(--red);">5</div>
                    <div class="note">Record may be in the wrong class, category, or operational grouping.</div>
                </div>

                <div class="metric">
                    <div class="label">GMP Impact Pending</div>
                    <div class="value" style="color: var(--orange);">7</div>
                    <div class="note">GMP/GxP or business criticality requires confirmation.</div>
                </div>

                <div class="metric">
                    <div class="label">Submission Blockers</div>
                    <div class="value" style="color: var(--blue);">6</div>
                    <div class="note">Classification gaps blocking ServiceNow-style submission readiness.</div>
                </div>
            </section>

            <section class="section">
                <h2>Classification Readiness Answer</h2>
                <p>
                    This console answers whether a CI is classified correctly enough to support operational trust, support routing, access routing, lifecycle control, and audit response.
                </p>

                <div class="answer">
                    <strong>Current classification interpretation:</strong>
                    The CI estate is partially classification-ready. Core systems are mostly classified, but several discovered workstations, OOS equipment records, access-path dependencies, and operational equipment records still need final CI class, GMP impact, environment, and criticality confirmation before they should be considered ServiceNow-ready.
                </div>
            </section>

            <section class="section">
                <h2>CI Classification Chain</h2>
                <p>
                    CITrust™ validates classification as a governance chain, not only a CMDB dropdown value.
                </p>

                <div class="flow">
                    <div class="flow-step">
                        <h3>1. CI Class</h3>
                        <p>Application, server, workstation, equipment, infrastructure dependency, access path, or candidate record.</p>
                    </div>

                    <div class="flow-step">
                        <h3>2. Operational Role</h3>
                        <p>What the CI does in operations, lab, manufacturing, infrastructure, review, or access workflow.</p>
                    </div>

                    <div class="flow-step">
                        <h3>3. GMP / Business Impact</h3>
                        <p>Whether the CI supports regulated work, data integrity, facility monitoring, review activity, or production.</p>
                    </div>

                    <div class="flow-step">
                        <h3>4. Environment / Criticality</h3>
                        <p>Production, lab, local workstation, cutover, OOS, retired, candidate, or infrastructure dependency state.</p>
                    </div>

                    <div class="flow-step">
                        <h3>5. Governance Readiness</h3>
                        <p>Whether classification supports owner, support group, access, lifecycle, evidence, and audit decisions.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Classification Readiness Matrix</h2>
                <p>
                    This matrix shows whether each CI is classified accurately enough to support CMDB-readiness and operational trust.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Proposed CI Class</th>
                            <th>Operational Role</th>
                            <th>Environment</th>
                            <th>GMP / GxP Impact</th>
                            <th>Criticality</th>
                            <th>Classification Evidence</th>
                            <th>Classification Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">GMP Application</span></td>
                            <td>Asset / calibration governance</td>
                            <td><span class="badge soft-green">Production</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">High</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge green">Classification-Ready</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge soft-yellow">Server / Application Dependency</span></td>
                            <td>Facility monitoring and BMS support</td>
                            <td><span class="badge soft-yellow">Cutover</span></td>
                            <td><span class="badge soft-green">Likely GMP Support</span></td>
                            <td><span class="badge soft-yellow">Needs Confirmation</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge soft-green">Infrastructure Dependency</span></td>
                            <td>Admin and vendor access control</td>
                            <td><span class="badge soft-green">Controlled Access</span></td>
                            <td><span class="badge soft-yellow">Indirect GMP Support</span></td>
                            <td><span class="badge soft-yellow">Medium / High</span></td>
                            <td><span class="badge soft-yellow">Procedure Needed</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-green">Manufacturing Equipment</span></td>
                            <td>Operational production equipment</td>
                            <td><span class="badge soft-green">Operational</span></td>
                            <td><span class="badge soft-yellow">Needs Confirmation</span></td>
                            <td><span class="badge soft-yellow">Medium / High</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-yellow">Manufacturing Equipment / OOS</span></td>
                            <td>Out-of-service legacy equipment</td>
                            <td><span class="badge soft-red">OOS Not Closed</span></td>
                            <td><span class="badge soft-yellow">Closure Needed</span></td>
                            <td><span class="badge soft-yellow">Unknown</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Chromeleon Workstation</strong><br><span style="color: var(--muted);">Lab workstation dependency</span></td>
                            <td><span class="badge soft-green">Lab Workstation</span></td>
                            <td>Lab data / review workstation</td>
                            <td><span class="badge soft-green">Lab</span></td>
                            <td><span class="badge soft-green">Likely GxP</span></td>
                            <td><span class="badge soft-yellow">Needs Confirmation</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Unclassified</span></td>
                            <td>Backup review dependency</td>
                            <td><span class="badge soft-yellow">Discovered</span></td>
                            <td><span class="badge soft-yellow">Unknown</span></td>
                            <td><span class="badge soft-red">Unknown</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">GMP Application</span></td>
                            <td>Lab data system</td>
                            <td><span class="badge soft-green">Lab / Production Support</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">High</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge green">Classification-Ready</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Classification Governance Domains</h2>
                <p>
                    CITrust™ checks whether classification can support downstream governance decisions.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>CI Class Accuracy</h3>
                        <p>Validates whether the record is an application, server, workstation, manufacturing equipment, infrastructure dependency, or candidate.</p>
                    </div>

                    <div class="card">
                        <h3>GMP / GxP Impact</h3>
                        <p>Confirms whether the CI supports regulated operations, data integrity, production, lab review, or facility monitoring.</p>
                    </div>

                    <div class="card">
                        <h3>Criticality Mapping</h3>
                        <p>Checks whether business criticality aligns with ownership, support group, access routing, lifecycle, and evidence expectations.</p>
                    </div>

                    <div class="card">
                        <h3>Submission Readiness</h3>
                        <p>Ensures classification is mature enough for ServiceNow-style submission pack preparation and candidate review decisions.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Classification Decision Logic</h2>
                <p>
                    A CI cannot be trusted if its class, environment, impact, or criticality is wrong.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Classification-Ready CI</h3>
                        <ul>
                            <li>CI class is clear and appropriate.</li>
                            <li>Operational role is documented or explainable.</li>
                            <li>Environment is known.</li>
                            <li>GMP/GxP or business impact is confirmed.</li>
                            <li>Criticality supports access, support, lifecycle, and audit decisions.</li>
                            <li>Classification evidence is available or traceable.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Blocked Classification CI</h3>
                        <ul>
                            <li>CI class is missing, wrong, or disputed.</li>
                            <li>Operational role is unclear.</li>
                            <li>GMP/GxP impact is unknown.</li>
                            <li>Environment or lifecycle state is contradictory.</li>
                            <li>Criticality is not aligned with access, support, or evidence needs.</li>
                            <li>Record would create weak CMDB-readiness or audit exposure.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Classification Remediation Queue</h2>
                <p>
                    These classification gaps should be resolved before records move to ServiceNow-style submission, operational reliance, or audit-readiness.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Record</th>
                            <th>Classification Gap</th>
                            <th>Required Action</th>
                            <th>Target State</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Local Backup Review Workstation</td>
                            <td>Unclassified discovered dependency with unknown criticality and evidence.</td>
                            <td>Create governed candidate, classify as workstation or operational dependency, confirm owner, support group, LCM, and backup review evidence.</td>
                            <td>Classified governed CI candidate.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Speedy Glove 1802</td>
                            <td>OOS classification and closure state are not defensible.</td>
                            <td>Confirm OOS classification, attach closure evidence, verify access deactivation, and define lifecycle owner.</td>
                            <td>Closed or defensible OOS CI classification.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Niagara BMS Server</td>
                            <td>Server/application dependency classification and criticality require confirmation during cutover.</td>
                            <td>Confirm CI class, GMP support impact, support group, jump path dependency, and cutover evidence.</td>
                            <td>Classification-ready BMS dependency.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Speedy Glove 1803</td>
                            <td>GMP impact and criticality classification need confirmation.</td>
                            <td>Reconcile equipment classification with owner, support group, lifecycle state, and operational evidence.</td>
                            <td>Classification-ready operational equipment CI.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, update CI classes, or write directly into ServiceNow in this demo. This classification readiness console is a governance assurance overlay for CI class validation, GMP/GxP impact classification, environment readiness, criticality mapping, operational role definition, ServiceNow-readiness, audit readiness, change impact readiness, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_CLASSIFICATION_READINESS_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Classification Readiness Console installed.")
