from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_LIFECYCLE_READINESS_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/lifecycle-readiness")'
ROUTE_ALIAS = '@app.route("/citrust/lcm-readiness")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Lifecycle Readiness Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_LIFECYCLE_READINESS_V1_ACTIVE
# ============================================================

@app.route("/citrust/lifecycle-readiness")
@app.route("/citrust/lcm-readiness")
def citrust_lifecycle_readiness():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Lifecycle Readiness Console</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <style>
            :root {
                --bg: #050d19;
                --panel: #101d2f;
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
                    radial-gradient(circle at bottom left, rgba(255,184,107,0.08), transparent 30%),
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
                border: 1px solid rgba(255,184,107,0.38);
                background: rgba(255,184,107,0.10);
                color: #ffefd8;
                border-radius: 18px;
                padding: 20px;
                margin-top: 16px;
                line-height: 1.65;
                font-size: 15px;
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

            .lifecycle-flow {
                display: grid;
                grid-template-columns: repeat(6, 1fr);
                gap: 12px;
                margin-top: 16px;
            }

            .flow-step {
                border: 1px solid rgba(255,184,107,0.28);
                background: rgba(255,184,107,0.07);
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
                .kpis, .cards, .lifecycle-flow, .two-col {
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
                <h1>CITrust™ Lifecycle Readiness Console</h1>

                <div class="subtitle">
                    Validates whether each Configuration Item has a defensible lifecycle state, assigned LCM, active/OOS/retired/cutover classification, lifecycle evidence, change impact visibility, retirement accountability, and ServiceNow-readiness.
                </div>

                <div class="positioning">
                    <strong>Lifecycle governance boundary:</strong>
                    ServiceNow may store lifecycle state and CMDB fields. CITrust™ validates whether lifecycle state is operationally trustworthy, evidence-backed, and aligned with ownership, support group, MyAccess, dependency, audit, and submission readiness. This page does not create or update ServiceNow CIs.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/ownership-readiness">Ownership Readiness</a>
                    <a href="/citrust/evidence-lineage">Evidence Lineage</a>
                    <a href="/citrust/dependency-lineage">Dependency Lineage</a>
                    <a href="/citrust/trust-score-model">Trust Score Model</a>
                    <a href="/citrust/pre-deviation-readiness">Pre-Deviation Readiness</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                    <a href="/citrust/submission-board">Submission Board</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Lifecycle Records Checked</div>
                    <div class="value">42</div>
                    <div class="note">Records reviewed for active, OOS, retired, cutover, and candidate lifecycle state.</div>
                </div>

                <div class="metric">
                    <div class="label">LCM Assigned</div>
                    <div class="value" style="color: var(--green);">24</div>
                    <div class="note">Lifecycle accountability exists or is inherited through a governed model.</div>
                </div>

                <div class="metric">
                    <div class="label">Active / Defensible</div>
                    <div class="value" style="color: var(--blue);">18</div>
                    <div class="note">Active records have enough lifecycle context for operational reliance.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Lifecycle</div>
                    <div class="value" style="color: var(--yellow);">11</div>
                    <div class="note">Records need lifecycle evidence, support routing, or ownership cleanup.</div>
                </div>

                <div class="metric">
                    <div class="label">OOS / Retired Risk</div>
                    <div class="value" style="color: var(--red);">5</div>
                    <div class="note">Out-of-service or retired records need closure, access, or evidence reconciliation.</div>
                </div>

                <div class="metric">
                    <div class="label">Cutover Watchlist</div>
                    <div class="value" style="color: var(--orange);">8</div>
                    <div class="note">Records in migration, transition, cutover, or revalidation-sensitive state.</div>
                </div>
            </section>

            <section class="section">
                <h2>Lifecycle Readiness Answer</h2>
                <p>
                    This console answers whether the CI lifecycle state can be trusted for operational decisions.
                </p>

                <div class="answer">
                    <strong>Current lifecycle interpretation:</strong>
                    The CI estate has mixed lifecycle readiness. Several active systems are defensible, but some OOS, retired, cutover, and discovered records still need lifecycle ownership, closure evidence, access deactivation confirmation, or change impact linkage before leadership can treat them as operationally trusted.
                </div>
            </section>

            <section class="section">
                <h2>Lifecycle Trust Model</h2>
                <p>
                    CITrust™ separates lifecycle governance into states that can be reviewed, defended, and remediated.
                </p>

                <div class="lifecycle-flow">
                    <div class="flow-step">
                        <h3>1. Candidate</h3>
                        <p>Record discovered but not yet trusted for CMDB-readiness or operational reliance.</p>
                    </div>

                    <div class="flow-step">
                        <h3>2. Active</h3>
                        <p>CI is in operational use and must have owner, support, LCM, access, and evidence.</p>
                    </div>

                    <div class="flow-step">
                        <h3>3. Cutover</h3>
                        <p>CI is under migration, transition, validation, revalidation, or access-path change.</p>
                    </div>

                    <div class="flow-step">
                        <h3>4. Conditional</h3>
                        <p>CI can remain visible but requires remediation before full trust is granted.</p>
                    </div>

                    <div class="flow-step">
                        <h3>5. OOS / Retired</h3>
                        <p>CI is out of service, retired, or pending closure and needs defensible evidence.</p>
                    </div>

                    <div class="flow-step">
                        <h3>6. Closed</h3>
                        <p>CI has closure evidence, access removal proof, and lifecycle accountability resolved.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Lifecycle Readiness Matrix</h2>
                <p>
                    This matrix shows whether each CI lifecycle state is consistent, owned, evidence-backed, and safe for operational reliance.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Current State</th>
                            <th>LCM</th>
                            <th>Owner Alignment</th>
                            <th>Access State</th>
                            <th>Evidence State</th>
                            <th>Change / Cutover Impact</th>
                            <th>Lifecycle Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Aligned</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Stable</span></td>
                            <td><span class="badge green">Lifecycle-Ready</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS server / facility support dependency</span></td>
                            <td><span class="badge soft-yellow">Cutover Active</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Aligned</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Cutover Evidence</span></td>
                            <td><span class="badge soft-yellow">High</span></td>
                            <td><span class="badge yellow">Cutover Watchlist</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Aligned</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-yellow">Procedure Link Needed</span></td>
                            <td><span class="badge soft-yellow">Access Dependency</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-green">Operational</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Aligned</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Local Dependency</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">OOS Not Closed</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Not Confirmed</span></td>
                            <td><span class="badge soft-yellow">Closure Needed</span></td>
                            <td><span class="badge soft-red">Unresolved</span></td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Chromeleon Workstation</strong><br><span style="color: var(--muted);">Lab workstation dependency</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Aligned</span></td>
                            <td><span class="badge soft-yellow">Role Check</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-yellow">Dependency Review</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-yellow">Discovered</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Unknown</span></td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-green">Assigned</span></td>
                            <td><span class="badge soft-green">Aligned</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Stable</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Lifecycle Control Domains</h2>
                <p>
                    CITrust™ checks lifecycle readiness beyond a simple active or inactive field.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>LCM Accountability</h3>
                        <p>Confirms who is responsible for lifecycle state, changes, retirement, cutover, and continuity.</p>
                    </div>

                    <div class="card">
                        <h3>State Reconciliation</h3>
                        <p>Compares active, OOS, retired, pending, and cutover status across ServiceNow-style records, asset lists, and candidate queues.</p>
                    </div>

                    <div class="card">
                        <h3>Closure Evidence</h3>
                        <p>Validates whether retired or OOS records have closure evidence, access removal proof, and ownership accountability.</p>
                    </div>

                    <div class="card">
                        <h3>Change Impact</h3>
                        <p>Identifies whether lifecycle state affects access, support routing, dependency lineage, validation, or audit readiness.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Lifecycle Decision Logic</h2>
                <p>
                    A CI lifecycle state is trusted only when it can be defended through owner, access, evidence, dependency, and operational impact.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Lifecycle-Ready CI</h3>
                        <ul>
                            <li>Lifecycle state is clear and current.</li>
                            <li>LCM is assigned or clearly inherited.</li>
                            <li>Owner and support group align with lifecycle state.</li>
                            <li>Access mapping matches active, OOS, retired, or cutover status.</li>
                            <li>Evidence supports current lifecycle classification.</li>
                            <li>Change, cutover, retirement, or closure impact is understood.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Blocked Lifecycle CI</h3>
                        <ul>
                            <li>Lifecycle state is missing or contradictory.</li>
                            <li>OOS or retired record lacks closure evidence.</li>
                            <li>Access remains unclear after retirement or OOS status.</li>
                            <li>LCM is missing or disputed.</li>
                            <li>Cutover state lacks supporting evidence or ownership.</li>
                            <li>Lifecycle uncertainty creates audit, access, support, or operational risk.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Lifecycle Remediation Queue</h2>
                <p>
                    These lifecycle gaps should be resolved before records are treated as operationally trusted or ServiceNow-ready.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Record</th>
                            <th>Lifecycle Gap</th>
                            <th>Required Action</th>
                            <th>Target State</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Speedy Glove 1802</td>
                            <td>OOS state is not fully closed or evidence-backed.</td>
                            <td>Confirm closure owner, attach closure evidence, verify access deactivation, and reconcile support responsibility.</td>
                            <td>Closed / defensible OOS record.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Local Backup Review Workstation</td>
                            <td>Discovered dependency has no LCM, owner, lifecycle state, or evidence.</td>
                            <td>Create governed candidate, assign lifecycle accountability, and map operational use.</td>
                            <td>Governed candidate with lifecycle owner.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Niagara BMS Server</td>
                            <td>Cutover lifecycle state depends on support routing, jump path, and evidence completion.</td>
                            <td>Attach cutover evidence, confirm LCM, support group, MyAccess role, and post-cutover state.</td>
                            <td>Active lifecycle-ready CI after cutover.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Jump Server Access Path</td>
                            <td>Active dependency needs procedure evidence linked to lifecycle and access governance.</td>
                            <td>Attach admin access procedure or vendor access evidence reference.</td>
                            <td>Lifecycle-ready infrastructure dependency.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, update lifecycle fields, or write directly into ServiceNow in this demo. This lifecycle readiness console is a governance assurance overlay for LCM accountability, lifecycle state validation, OOS closure, cutover readiness, access-state alignment, evidence linkage, dependency impact, audit readiness, and ServiceNow-readiness.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_LIFECYCLE_READINESS_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Lifecycle Readiness Console installed.")
