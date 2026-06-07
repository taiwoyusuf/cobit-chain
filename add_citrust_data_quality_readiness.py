from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_DATA_QUALITY_READINESS_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/data-quality-readiness")'
ROUTE_ALIAS = '@app.route("/citrust/ci-data-quality")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Data Quality Readiness Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_DATA_QUALITY_READINESS_V1_ACTIVE
# ============================================================

@app.route("/citrust/data-quality-readiness")
@app.route("/citrust/ci-data-quality")
def citrust_data_quality_readiness():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ CI Data Quality Readiness Console</title>
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
                    radial-gradient(circle at bottom right, rgba(49,208,125,0.08), transparent 30%),
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
                border: 1px solid rgba(49,208,125,0.36);
                background: rgba(49,208,125,0.10);
                color: #dfffea;
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
                border: 1px solid rgba(49,208,125,0.28);
                background: rgba(49,208,125,0.07);
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
                <h1>CITrust™ CI Data Quality Readiness Console</h1>

                <div class="subtitle">
                    Validates whether each Configuration Item has complete, current, non-duplicated, consistent, and evidence-backed data fields before the CI is treated as ServiceNow-ready, MyAccess-ready, audit-ready, or operationally trusted.
                </div>

                <div class="positioning">
                    <strong>Data quality boundary:</strong>
                    ServiceNow may store CI fields. CITrust™ validates whether those fields are complete, consistent, current, reconciled, and operationally usable. This page does not create ServiceNow CIs, does not update CMDB data, and does not replace the system of record.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/servicenow-ci-readiness">ServiceNow CI Readiness</a>
                    <a href="/citrust/reconciliation">CMDB Reconciliation</a>
                    <a href="/citrust/classification-readiness">Classification Readiness</a>
                    <a href="/citrust/ownership-readiness">Ownership Readiness</a>
                    <a href="/citrust/support-group-readiness">Support Routing</a>
                    <a href="/citrust/evidence-lineage">Evidence Lineage</a>
                    <a href="/citrust/submission-board">Submission Board</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Data Quality Checks</div>
                    <div class="value">42</div>
                    <div class="note">CIs reviewed for completeness, duplication, consistency, currency, and field confidence.</div>
                </div>

                <div class="metric">
                    <div class="label">High-Quality Records</div>
                    <div class="value" style="color: var(--green);">19</div>
                    <div class="note">Core fields are complete, consistent, current, and evidence-backed.</div>
                </div>

                <div class="metric">
                    <div class="label">Partial Records</div>
                    <div class="value" style="color: var(--yellow);">14</div>
                    <div class="note">Records exist but need cleanup before trusted use.</div>
                </div>

                <div class="metric">
                    <div class="label">Data Blockers</div>
                    <div class="value" style="color: var(--red);">7</div>
                    <div class="note">Missing or conflicting fields prevent operational trust.</div>
                </div>

                <div class="metric">
                    <div class="label">Duplicate Risk</div>
                    <div class="value" style="color: var(--orange);">6</div>
                    <div class="note">Potential duplicate or near-duplicate CI records require reconciliation.</div>
                </div>

                <div class="metric">
                    <div class="label">Stale Field Risk</div>
                    <div class="value" style="color: var(--blue);">11</div>
                    <div class="note">Owner, support group, lifecycle, access, or evidence fields may not reflect current state.</div>
                </div>
            </section>

            <section class="section">
                <h2>Data Quality Readiness Answer</h2>
                <p>
                    This console answers whether CI data is strong enough to support governance decisions.
                </p>

                <div class="answer">
                    <strong>Current data quality interpretation:</strong>
                    The CI estate has mixed data quality readiness. Some records are complete enough for ServiceNow-style submission and operational reliance, while others still contain missing ownership, uncertain support group, partial MyAccess mapping, incomplete lifecycle state, missing evidence, duplicate risk, or stale operational context.
                </div>
            </section>

            <section class="section">
                <h2>CI Data Quality Chain</h2>
                <p>
                    CITrust™ evaluates CI data quality as a governance chain. A record may exist, but it is not trusted until the data can support action.
                </p>

                <div class="flow">
                    <div class="flow-step">
                        <h3>1. Complete</h3>
                        <p>Required fields exist: owner, support group, LCM, class, lifecycle, access, and evidence reference.</p>
                    </div>

                    <div class="flow-step">
                        <h3>2. Consistent</h3>
                        <p>Fields align across ServiceNow-style records, master list, MyAccess, Blue Mountain, and candidate intake.</p>
                    </div>

                    <div class="flow-step">
                        <h3>3. Current</h3>
                        <p>Ownership, support group, lifecycle, and access data reflect the current operational state.</p>
                    </div>

                    <div class="flow-step">
                        <h3>4. Unique</h3>
                        <p>Record is not duplicated, split across competing names, or confused with another CI candidate.</p>
                    </div>

                    <div class="flow-step">
                        <h3>5. Defensible</h3>
                        <p>Data can support audit, access routing, incident response, change impact, and ServiceNow-readiness.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Data Quality Readiness Matrix</h2>
                <p>
                    This matrix shows whether each CI has the minimum trusted data needed for governance assurance.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Required Fields</th>
                            <th>Consistency</th>
                            <th>Currency</th>
                            <th>Duplicate Risk</th>
                            <th>Evidence Link</th>
                            <th>Data Confidence</th>
                            <th>Data Quality Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td><span class="badge soft-green">Consistent</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-green">Low</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge green">High</span></td>
                            <td><span class="badge green">Data-Ready</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Needs Reconciliation</span></td>
                            <td><span class="badge soft-yellow">Cutover State</span></td>
                            <td><span class="badge soft-green">Low</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td><span class="badge soft-green">Consistent</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-green">Low</span></td>
                            <td><span class="badge soft-yellow">Procedure Needed</span></td>
                            <td><span class="badge yellow">Medium / High</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Needs Reconciliation</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-yellow">Possible Legacy Match</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">Incomplete</span></td>
                            <td><span class="badge soft-red">Conflicting</span></td>
                            <td><span class="badge soft-yellow">OOS Not Closed</span></td>
                            <td><span class="badge soft-yellow">Possible Duplicate</span></td>
                            <td><span class="badge soft-yellow">Closure Needed</span></td>
                            <td><span class="badge red">Low</span></td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Chromeleon Workstation</strong><br><span style="color: var(--muted);">Lab workstation dependency</span></td>
                            <td><span class="badge soft-green">Mostly Complete</span></td>
                            <td><span class="badge soft-yellow">Workstation Link Check</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-green">Low</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge yellow">Medium / High</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Unknown</span></td>
                            <td><span class="badge soft-yellow">Discovered</span></td>
                            <td><span class="badge soft-red">Unknown</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge red">Very Low</span></td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td><span class="badge soft-green">Consistent</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-green">Low</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge green">High</span></td>
                            <td><span class="badge green">Data-Ready</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Data Quality Control Domains</h2>
                <p>
                    CITrust™ separates CI data quality into measurable domains so remediation is precise.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Field Completeness</h3>
                        <p>Checks whether mandatory fields exist: owner, support group, LCM, class, lifecycle, access, evidence, and operational purpose.</p>
                    </div>

                    <div class="card">
                        <h3>Cross-Source Consistency</h3>
                        <p>Compares ServiceNow-style records, MyAccess, Blue Mountain, master list, candidate intake, and operational discovery.</p>
                    </div>

                    <div class="card">
                        <h3>Duplicate Detection</h3>
                        <p>Flags duplicate, near-duplicate, legacy, split-name, or conflicting records that could weaken CMDB trust.</p>
                    </div>

                    <div class="card">
                        <h3>Field Currency</h3>
                        <p>Identifies stale owner, support group, lifecycle, access, evidence, or classification fields that no longer match operations.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Data Quality Decision Logic</h2>
                <p>
                    CITrust™ prevents incomplete or conflicting records from being treated as operationally trusted.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Data-Ready CI</h3>
                        <ul>
                            <li>Required fields are complete.</li>
                            <li>Field values are consistent across key sources.</li>
                            <li>Record is current and reflects operational reality.</li>
                            <li>Duplicate risk is low or reconciled.</li>
                            <li>Evidence links support the field values.</li>
                            <li>Data is strong enough for ServiceNow-readiness, MyAccess routing, audit, and support decisions.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Blocked Data Quality CI</h3>
                        <ul>
                            <li>Required fields are missing.</li>
                            <li>Owner, support group, LCM, or lifecycle state conflicts across sources.</li>
                            <li>Potential duplicate records create confusion.</li>
                            <li>Field values are stale or not evidence-backed.</li>
                            <li>Operational purpose or classification is unclear.</li>
                            <li>Record would create weak CMDB-readiness or audit exposure.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Data Quality Remediation Queue</h2>
                <p>
                    These items should be corrected before the related records are used for ServiceNow-style submission, access routing, audit readiness, or operational reliance.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Record</th>
                            <th>Data Quality Gap</th>
                            <th>Required Action</th>
                            <th>Target State</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Local Backup Review Workstation</td>
                            <td>Missing mandatory fields and evidence; discovered dependency is not governed.</td>
                            <td>Create candidate record, assign owner, support group, LCM, CI class, lifecycle state, and evidence link.</td>
                            <td>Complete governed candidate.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Speedy Glove 1802</td>
                            <td>OOS state, duplicate risk, ownership, and closure evidence are not reconciled.</td>
                            <td>Reconcile OOS record, confirm closure state, attach closure evidence, and remove duplicate ambiguity.</td>
                            <td>Closed and reconciled record.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Niagara BMS Server</td>
                            <td>Cutover-state data is partial and support/access fields need final confirmation.</td>
                            <td>Update candidate readiness evidence, support group confirmation, access role mapping, and cutover state.</td>
                            <td>Data-ready cutover CI.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Speedy Glove 1803</td>
                            <td>Support group, evidence link, and possible legacy match need reconciliation.</td>
                            <td>Reconcile against master list, Blue Mountain, owner, support group, and candidate intake record.</td>
                            <td>Data-ready operational equipment CI.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, update CMDB data, delete duplicates, or write directly into ServiceNow in this demo. This data quality readiness console is a governance assurance overlay for CI field completeness, cross-source consistency, duplicate detection, field currency, evidence-backed data quality, ServiceNow-readiness, MyAccess readiness, audit readiness, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_DATA_QUALITY_READINESS_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Data Quality Readiness Console installed.")
