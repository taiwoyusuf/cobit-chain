from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_RELATIONSHIP_READINESS_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/relationship-readiness")'
ROUTE_ALIAS = '@app.route("/citrust/relationship-map")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Relationship Readiness Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_RELATIONSHIP_READINESS_V1_ACTIVE
# ============================================================

@app.route("/citrust/relationship-readiness")
@app.route("/citrust/relationship-map")
def citrust_relationship_readiness():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Relationship Readiness Console</title>
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
                <h1>CITrust™ Relationship Readiness Console</h1>

                <div class="subtitle">
                    Validates whether Configuration Item relationships are complete, accurate, current, evidence-backed, and operationally usable before the CI can be trusted for change impact, incident routing, MyAccess approval, audit response, dependency analysis, and ServiceNow-style submission.
                </div>

                <div class="positioning">
                    <strong>Relationship boundary:</strong>
                    ServiceNow may store CI relationships. CITrust™ validates whether those relationships are governed and defensible. This page does not create, modify, or write CI relationships into ServiceNow in this demo.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/dependency-lineage">Dependency Lineage</a>
                    <a href="/citrust/change-impact-readiness">Change Impact</a>
                    <a href="/citrust/data-quality-readiness">Data Quality</a>
                    <a href="/citrust/mandatory-fields-checklist">Mandatory Fields</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Relationships Checked</div>
                    <div class="value">96</div>
                    <div class="note">Owned by, supported by, depends on, hosted on, used by, accessed through, and approved by.</div>
                </div>

                <div class="metric">
                    <div class="label">Defensible Relationships</div>
                    <div class="value" style="color: var(--green);">51</div>
                    <div class="note">Relationships that are clear, current, and supported by operational context.</div>
                </div>

                <div class="metric">
                    <div class="label">Partial Relationships</div>
                    <div class="value" style="color: var(--yellow);">27</div>
                    <div class="note">Known but not fully evidence-backed or reconciled.</div>
                </div>

                <div class="metric">
                    <div class="label">Missing Relationships</div>
                    <div class="value" style="color: var(--red);">18</div>
                    <div class="note">Relationship gaps that weaken trust, change impact, or audit readiness.</div>
                </div>

                <div class="metric">
                    <div class="label">High Impact Gaps</div>
                    <div class="value" style="color: var(--orange);">8</div>
                    <div class="note">Relationship gaps affecting access, lifecycle, support routing, or cutover.</div>
                </div>

                <div class="metric">
                    <div class="label">Ready for CMDB Review</div>
                    <div class="value" style="color: var(--blue);">12</div>
                    <div class="note">Records with enough relationship context for review-board discussion.</div>
                </div>
            </section>

            <section class="section">
                <h2>Relationship Readiness Answer</h2>
                <p>
                    This console answers whether CI relationships can support governance decisions.
                </p>

                <div class="answer">
                    <strong>Current relationship interpretation:</strong>
                    The relationship layer is partially mature. Core systems have usable ownership and support relationships, but cutover-sensitive systems, hidden workstations, OOS records, and access-path dependencies still need stronger relationship mapping before leadership can rely on them for ServiceNow-readiness, change impact, or audit defense.
                </div>
            </section>

            <section class="section">
                <h2>Relationship Types Library</h2>
                <p>
                    CITrust™ separates relationships into operationally meaningful types instead of treating all links as equal.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Relationship Type</th>
                            <th>Meaning</th>
                            <th>Governance Use</th>
                            <th>Failure Impact</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge blue">Owned By</span></td>
                            <td>CI has accountable business, technical, or operational owner.</td>
                            <td>Ownership, attestation, escalation, audit response.</td>
                            <td>Ownerless CI and weak accountability.</td>
                        </tr>

                        <tr>
                            <td><span class="badge purple">Supported By</span></td>
                            <td>CI routes to a support group that can act on incidents or requests.</td>
                            <td>Incident routing, operational support, escalation.</td>
                            <td>Support failure and delayed response.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">Depends On</span></td>
                            <td>CI relies on another system, workstation, server, network path, vendor path, or process.</td>
                            <td>Change impact, cutover, dependency lineage.</td>
                            <td>Hidden dependency and change failure.</td>
                        </tr>

                        <tr>
                            <td><span class="badge green">Hosted On</span></td>
                            <td>Application or service runs on a specific server, workstation, platform, or infrastructure layer.</td>
                            <td>Infrastructure governance, support routing, lifecycle control.</td>
                            <td>Impact analysis failure.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Accessed Through</span></td>
                            <td>CI is accessed through MyAccess, jump server, admin route, vendor path, or controlled workstation.</td>
                            <td>Access readiness, audit readiness, privileged access governance.</td>
                            <td>Access approval or audit defensibility failure.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">Closed By</span></td>
                            <td>OOS or retired CI has closure owner, closure evidence, and access deactivation proof.</td>
                            <td>Lifecycle closure, audit defense, orphan prevention.</td>
                            <td>Unclosed OOS/retired CI risk.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>CI Relationship Readiness Matrix</h2>
                <p>
                    This matrix shows whether key CI relationships are governed enough to support operational trust.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Owned By</th>
                            <th>Supported By</th>
                            <th>Depends On</th>
                            <th>Accessed Through</th>
                            <th>Lifecycle Relationship</th>
                            <th>Evidence Link</th>
                            <th>Relationship Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge green">Relationship-Ready</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Needs Confirmation</span></td>
                            <td><span class="badge soft-yellow">Jump Path / Cutover</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Cutover Active</span></td>
                            <td><span class="badge soft-yellow">Cutover Evidence</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Infrastructure Path</span></td>
                            <td><span class="badge soft-green">Primary Access Route</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-yellow">Procedure Needed</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-yellow">Local Dependency</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-green">Operational</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Unknown</span></td>
                            <td><span class="badge soft-red">Not Confirmed</span></td>
                            <td><span class="badge soft-yellow">OOS Closure Needed</span></td>
                            <td><span class="badge soft-yellow">Closure Needed</span></td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-red">Hidden</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-yellow">Discovered</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Relationship Control Domains</h2>
                <p>
                    These controls determine whether a CI relationship can be trusted.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Relationship Completeness</h3>
                        <p>Checks whether required owner, support, dependency, access, lifecycle, and evidence relationships exist.</p>
                    </div>

                    <div class="card">
                        <h3>Relationship Accuracy</h3>
                        <p>Validates whether the relationship reflects actual operations instead of stale CMDB, spreadsheet, or tribal knowledge.</p>
                    </div>

                    <div class="card">
                        <h3>Relationship Evidence</h3>
                        <p>Links relationships to owner confirmation, support group evidence, MyAccess roles, SOPs, cutover artifacts, and closure evidence.</p>
                    </div>

                    <div class="card">
                        <h3>Relationship Impact</h3>
                        <p>Determines whether the relationship supports incident routing, access approval, lifecycle closure, audit response, and change impact.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Relationship Decision Logic</h2>
                <p>
                    CI relationships should be trusted only when they can be explained and defended.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Relationship-Ready CI</h3>
                        <ul>
                            <li>Owner and support relationships are confirmed.</li>
                            <li>Dependencies are known and operationally accurate.</li>
                            <li>Access relationship is mapped through MyAccess, jump server, admin path, or vendor route where applicable.</li>
                            <li>Lifecycle relationship aligns with active, cutover, OOS, retired, or closed state.</li>
                            <li>Evidence supports the relationship model.</li>
                            <li>Relationships support audit, change, support, and submission readiness.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Blocked Relationship CI</h3>
                        <ul>
                            <li>Owner or support relationship is missing.</li>
                            <li>Dependency chain is hidden or undocumented.</li>
                            <li>Access relationship is not defensible.</li>
                            <li>OOS or retired relationship lacks closure evidence.</li>
                            <li>Relationship conflicts across sources.</li>
                            <li>Relationship weakness would create ServiceNow-readiness, audit, or change-impact risk.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Relationship Remediation Queue</h2>
                <p>
                    These actions strengthen CI relationship trust before ServiceNow-style submission or operational reliance.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Record</th>
                            <th>Relationship Gap</th>
                            <th>Required Action</th>
                            <th>Readiness Unlock</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Local Backup Review Workstation</td>
                            <td>No owner, access, dependency, evidence, or lifecycle relationship.</td>
                            <td>Create governed candidate and map owner, support, LCM, backup evidence, and access path.</td>
                            <td>Blocked → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Speedy Glove 1802</td>
                            <td>OOS closure relationship and access deactivation relationship are not defensible.</td>
                            <td>Attach closure evidence and confirm access removal and lifecycle owner.</td>
                            <td>Blocked → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Niagara BMS Server</td>
                            <td>Cutover, support, MyAccess, and jump-path relationships are partial.</td>
                            <td>Finalize support group, MyAccess role, jump path, and cutover evidence relationship.</td>
                            <td>Conditional → Relationship-Ready</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Speedy Glove 1803</td>
                            <td>Support and evidence relationships need reconciliation.</td>
                            <td>Reconcile support group, owner, lifecycle, and evidence path against source systems.</td>
                            <td>Conditional → ServiceNow-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, update CMDB relationship records, or write directly into ServiceNow in this demo. This relationship readiness console is a governance assurance overlay for CI relationship completeness, ownership mapping, support routing, dependency lineage, access path validation, lifecycle relationship defense, evidence-backed relationships, change impact readiness, audit readiness, and ServiceNow-readiness.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_RELATIONSHIP_READINESS_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Relationship Readiness Console installed.")
