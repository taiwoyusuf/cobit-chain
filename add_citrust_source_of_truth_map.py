from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_SOURCE_OF_TRUTH_MAP_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/source-of-truth-map")'
ROUTE_ALIAS = '@app.route("/citrust/source-authority-map")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Source-of-Truth Authority Map already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_SOURCE_OF_TRUTH_MAP_V1_ACTIVE
# ============================================================

@app.route("/citrust/source-of-truth-map")
@app.route("/citrust/source-authority-map")
def citrust_source_of_truth_map():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Source-of-Truth Authority Map</title>
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
                border: 1px solid rgba(92,200,255,0.36);
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
                <h1>CITrust™ Source-of-Truth Authority Map</h1>

                <div class="subtitle">
                    Defines which source is authoritative for each CI field and how conflicts should be resolved across ServiceNow-style records, MyAccess, Blue Mountain, master lists, candidate intake, evidence repositories, support-group records, and operational discovery.
                </div>

                <div class="positioning">
                    <strong>Source authority boundary:</strong>
                    ServiceNow remains the system of record for the CI. CITrust™ does not replace ServiceNow or write directly into it in this demo. CITrust™ validates whether each CI field is supported by the correct authoritative source before the record is trusted, submitted, attested, or used operationally.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/reconciliation">CMDB Reconciliation</a>
                    <a href="/citrust/data-quality-readiness">Data Quality</a>
                    <a href="/citrust/mandatory-fields-checklist">Mandatory Fields</a>
                    <a href="/citrust/relationship-readiness">Relationship Readiness</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                    <a href="/citrust/executive-reasoning-panel">Executive Reasoning</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Authority Domains</div>
                    <div class="value">9</div>
                    <div class="note">CI identity, class, owner, support, LCM, access, lifecycle, evidence, dependencies.</div>
                </div>

                <div class="metric">
                    <div class="label">Authoritative Fields</div>
                    <div class="value" style="color: var(--green);">31</div>
                    <div class="note">Fields with defined source authority and reconciliation logic.</div>
                </div>

                <div class="metric">
                    <div class="label">Conflict Checks</div>
                    <div class="value" style="color: var(--yellow);">18</div>
                    <div class="note">Cross-source checks for mismatched owner, support, access, lifecycle, or class.</div>
                </div>

                <div class="metric">
                    <div class="label">Unclear Authority</div>
                    <div class="value" style="color: var(--red);">7</div>
                    <div class="note">Fields where the authoritative source is not yet defensible.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Overrides</div>
                    <div class="value" style="color: var(--orange);">6</div>
                    <div class="note">Cases where evidence must resolve field conflict before trust is granted.</div>
                </div>

                <div class="metric">
                    <div class="label">Submission Ready</div>
                    <div class="value" style="color: var(--blue);">5</div>
                    <div class="note">Records with enough source authority clarity for submission-pack preparation.</div>
                </div>
            </section>

            <section class="section">
                <h2>Source-of-Truth Answer</h2>
                <p>
                    This map answers which source should be trusted when CI field values conflict.
                </p>

                <div class="answer">
                    <strong>Current authority interpretation:</strong>
                    CITrust™ should not trust a CI field simply because it appears in a spreadsheet, export, intake form, or ServiceNow-style page. Each field must trace to the correct authority source. ServiceNow may store the final CI record, but CITrust™ validates whether owner, support group, MyAccess routing, LCM, lifecycle, evidence, dependency, and classification values are supported by the strongest available source.
                </div>
            </section>

            <section class="section">
                <h2>Field Authority Library</h2>
                <p>
                    This table defines the preferred source of truth for each major CI governance field.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>CI Field</th>
                            <th>Primary Authority</th>
                            <th>Secondary Evidence</th>
                            <th>Conflict Rule</th>
                            <th>Trust Impact</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>CI Name / Asset Name</strong></td>
                            <td><span class="badge blue">ServiceNow-style Record / Master List</span></td>
                            <td>Asset export, candidate intake, operational discovery.</td>
                            <td>If names conflict, reconcile against asset identity and operational use.</td>
                            <td>Blocks duplicate and relationship readiness if unresolved.</td>
                        </tr>

                        <tr>
                            <td><strong>CI Class / Type</strong></td>
                            <td><span class="badge purple">CMDB Classification Standard</span></td>
                            <td>Application inventory, asset class, equipment type, infrastructure context.</td>
                            <td>If class conflicts, route to classification readiness before submission.</td>
                            <td>Blocks ServiceNow-readiness if wrong or unclear.</td>
                        </tr>

                        <tr>
                            <td><strong>CI Owner</strong></td>
                            <td><span class="badge green">Business / Technical Owner Confirmation</span></td>
                            <td>ServiceNow field, master list, stakeholder attestation.</td>
                            <td>If owner differs by source, require owner attestation or governance review.</td>
                            <td>Critical blocker if missing.</td>
                        </tr>

                        <tr>
                            <td><strong>Support Group</strong></td>
                            <td><span class="badge orange">ServiceNow Support Routing / IT Operations</span></td>
                            <td>Incident routing model, support team confirmation, LCM input.</td>
                            <td>If support group is unclear, keep CI conditional until routable group is confirmed.</td>
                            <td>Blocks support readiness and incident routing.</td>
                        </tr>

                        <tr>
                            <td><strong>LCM / Lifecycle Owner</strong></td>
                            <td><span class="badge blue">Lifecycle Governance</span></td>
                            <td>CMDB contact, infrastructure owner, application owner, closure owner.</td>
                            <td>If lifecycle owner is unclear, block OOS, retired, cutover, or active lifecycle decisions.</td>
                            <td>Blocks lifecycle readiness.</td>
                        </tr>

                        <tr>
                            <td><strong>MyAccess Role / Approver</strong></td>
                            <td><span class="badge purple">MyAccess / Access Governance</span></td>
                            <td>CI owner, support group, access request form, approver group evidence.</td>
                            <td>MyAccess must resolve access authority; CITrust™ validates alignment.</td>
                            <td>Blocks access readiness if not mapped.</td>
                        </tr>

                        <tr>
                            <td><strong>Lifecycle State</strong></td>
                            <td><span class="badge orange">Lifecycle Evidence / Change Context</span></td>
                            <td>ServiceNow field, closure record, OOS decision, cutover evidence.</td>
                            <td>If state conflicts, evidence overrides stale field values.</td>
                            <td>Blocks lifecycle and audit readiness if unsupported.</td>
                        </tr>

                        <tr>
                            <td><strong>Evidence Location</strong></td>
                            <td><span class="badge green">Evidence Repository / Controlled Artifact</span></td>
                            <td>SOP, backup review, audit trail review, validation, closure, access proof.</td>
                            <td>No evidence means field remains unsupported even if present.</td>
                            <td>Blocks audit readiness and trust scoring.</td>
                        </tr>

                        <tr>
                            <td><strong>Dependency Relationship</strong></td>
                            <td><span class="badge yellow">Operational Discovery / Relationship Review</span></td>
                            <td>ServiceNow relationship, infrastructure diagram, jump path, support input.</td>
                            <td>Hidden dependencies must be added to candidate or relationship review.</td>
                            <td>Blocks change impact and dependency lineage.</td>
                        </tr>

                        <tr>
                            <td><strong>GMP / GxP Impact</strong></td>
                            <td><span class="badge red">Quality / Operational Governance</span></td>
                            <td>System use, data integrity role, lab/manufacturing impact, SOP linkage.</td>
                            <td>If impact is unclear, treat as conditional until confirmed.</td>
                            <td>Blocks audit and criticality reasoning.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Source Authority Matrix by CI</h2>
                <p>
                    This matrix shows whether each CI has clear authority sources for the fields that matter most.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Identity Authority</th>
                            <th>Owner Authority</th>
                            <th>Support Authority</th>
                            <th>Access Authority</th>
                            <th>Lifecycle Authority</th>
                            <th>Evidence Authority</th>
                            <th>Authority Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">Clear</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge green">Authority-Ready</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge soft-yellow">Cutover Context</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Needs Confirmation</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Cutover Evidence</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge soft-green">Clear</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Access Governance</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-yellow">Procedure Needed</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-yellow">Reconcile</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-green">Operational</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-yellow">OOS Partial</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Confirmed</span></td>
                            <td><span class="badge soft-yellow">Closure Needed</span></td>
                            <td><span class="badge soft-yellow">Closure Needed</span></td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-yellow">Discovered</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Clear</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Authority Control Domains</h2>
                <p>
                    CITrust™ separates authority into source, field, evidence, and conflict controls.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Source Authority</h3>
                        <p>Defines which system, team, or artifact is authoritative for a specific CI field.</p>
                    </div>

                    <div class="card">
                        <h3>Conflict Resolution</h3>
                        <p>Determines what happens when ServiceNow-style data, MyAccess, Blue Mountain, master lists, or evidence disagree.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Override</h3>
                        <p>Allows controlled evidence to override stale or incomplete field values when properly reviewed.</p>
                    </div>

                    <div class="card">
                        <h3>Submission Authority</h3>
                        <p>Prevents weak source data from being pushed forward as ServiceNow-ready or operationally trusted.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Authority Decision Logic</h2>
                <p>
                    CITrust™ prevents weak source data from becoming trusted CI data.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Authority-Ready CI</h3>
                        <ul>
                            <li>Each mandatory field has a defined source authority.</li>
                            <li>Owner, support group, LCM, access, lifecycle, and evidence values are traceable.</li>
                            <li>Cross-source conflicts have been resolved or documented.</li>
                            <li>Evidence supports the field values used for readiness decisions.</li>
                            <li>ServiceNow-style submission can be defended.</li>
                            <li>Executive reasoning can explain why the CI is trusted.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Blocked Authority CI</h3>
                        <ul>
                            <li>Field values conflict across source systems.</li>
                            <li>Authority source is unclear or based on tribal knowledge.</li>
                            <li>Evidence does not support the field value.</li>
                            <li>Owner, support group, LCM, or access authority is missing.</li>
                            <li>Lifecycle or OOS state cannot be defended.</li>
                            <li>Submission would create weak or orphaned CMDB data.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Source Authority Remediation Queue</h2>
                <p>
                    These actions clarify source authority before records move forward.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Record</th>
                            <th>Authority Gap</th>
                            <th>Required Action</th>
                            <th>Readiness Unlock</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Local Backup Review Workstation</td>
                            <td>No clear authority for identity, owner, LCM, access route, evidence, or dependency.</td>
                            <td>Create governed candidate and assign authority source for each mandatory field.</td>
                            <td>Blocked → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Speedy Glove 1802</td>
                            <td>OOS lifecycle and access deactivation authority are not defensible.</td>
                            <td>Attach closure evidence and confirm authority for lifecycle owner and access removal.</td>
                            <td>Blocked → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Niagara BMS Server</td>
                            <td>Cutover support, access, and evidence authority remain partial.</td>
                            <td>Confirm support authority, MyAccess role authority, jump path evidence, and cutover source.</td>
                            <td>Conditional → Authority-Ready</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Speedy Glove 1803</td>
                            <td>Support group and evidence authority require reconciliation.</td>
                            <td>Reconcile source authority across master list, candidate record, owner, and evidence path.</td>
                            <td>Conditional → Submission-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, MyAccess, Blue Mountain, master lists, evidence repositories, or human governance. This source-of-truth authority map is a governance assurance overlay for resolving CI field authority, cross-source conflicts, evidence overrides, ServiceNow-readiness, MyAccess-readiness, data quality, relationship readiness, audit readiness, executive reasoning, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_SOURCE_OF_TRUTH_MAP_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Source-of-Truth Authority Map installed.")
