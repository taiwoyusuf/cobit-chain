from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_RISK_HEATMAP_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/risk-heatmap")'
ROUTE_ALIAS = '@app.route("/citrust/risk-command")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Risk Heatmap already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_RISK_HEATMAP_V1_ACTIVE
# ============================================================

@app.route("/citrust/risk-heatmap")
@app.route("/citrust/risk-command")
def citrust_risk_heatmap():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ CI Governance Risk Heatmap</title>
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
                    radial-gradient(circle at top left, rgba(255,92,112,0.16), transparent 30%),
                    radial-gradient(circle at top right, rgba(92,200,255,0.16), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(247,201,72,0.08), transparent 30%),
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
                border: 1px solid rgba(255,92,112,0.38);
                background: rgba(255,92,112,0.10);
                color: #ffe5e9;
                border-radius: 18px;
                padding: 20px;
                margin-top: 16px;
                line-height: 1.65;
                font-size: 15px;
            }

            .heatmap {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 16px;
                margin-top: 16px;
            }

            .heat-card {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 18px;
            }

            .heat-card h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .heat-card p {
                margin: 0;
                color: var(--muted);
                font-size: 14px;
                line-height: 1.55;
            }

            .bar-wrap {
                margin-top: 10px;
                height: 9px;
                background: rgba(255,255,255,0.09);
                border-radius: 99px;
                overflow: hidden;
            }

            .bar {
                height: 9px;
                border-radius: 99px;
            }

            .bar.redbar { width: 86%; background: var(--red); }
            .bar.orangebar { width: 72%; background: var(--orange); }
            .bar.yellowbar { width: 61%; background: var(--yellow); }
            .bar.bluebar { width: 48%; background: var(--blue); }
            .bar.greenbar { width: 32%; background: var(--green); }

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
                .kpis, .heatmap, .cards, .two-col {
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
                <h1>CITrust™ CI Governance Risk Heatmap</h1>

                <div class="subtitle">
                    Prioritizes Configuration Item governance risks across ownership, support routing, MyAccess, evidence lineage, dependency lineage, lifecycle state, classification, data quality, change impact, audit readiness, and ServiceNow-readiness.
                </div>

                <div class="positioning">
                    <strong>Risk assurance boundary:</strong>
                    ServiceNow remains the system of record. CITrust™ does not create ServiceNow CIs, does not write risk scores into ServiceNow, and does not replace formal risk or change processes. This page is a governance assurance overlay that shows where CI records are operationally weak before they create audit, access, support, or pre-deviation exposure.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                    <a href="/citrust/trust-score-model">Trust Score Model</a>
                    <a href="/citrust/data-quality-readiness">Data Quality</a>
                    <a href="/citrust/evidence-lineage">Evidence Lineage</a>
                    <a href="/citrust/dependency-lineage">Dependency Lineage</a>
                    <a href="/citrust/pre-deviation-readiness">Pre-Deviation Readiness</a>
                    <a href="/citrust/orphans">Orphan CI Intelligence</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Risk Domains Assessed</div>
                    <div class="value">10</div>
                    <div class="note">Ownership, support, access, evidence, dependency, lifecycle, classification, data, change, audit.</div>
                </div>

                <div class="metric">
                    <div class="label">High-Risk CIs</div>
                    <div class="value" style="color: var(--red);">9</div>
                    <div class="note">Records with critical governance gaps requiring immediate remediation.</div>
                </div>

                <div class="metric">
                    <div class="label">Medium-Risk CIs</div>
                    <div class="value" style="color: var(--yellow);">16</div>
                    <div class="note">Records that can remain visible but require controlled remediation.</div>
                </div>

                <div class="metric">
                    <div class="label">Low-Risk CIs</div>
                    <div class="value" style="color: var(--green);">17</div>
                    <div class="note">Records with strong ownership, support, access, evidence, and lifecycle control.</div>
                </div>

                <div class="metric">
                    <div class="label">Pre-Deviation Exposure</div>
                    <div class="value" style="color: var(--orange);">11</div>
                    <div class="note">Weaknesses likely to become audit findings, access failures, or operational issues.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Escalations</div>
                    <div class="value" style="color: var(--blue);">4</div>
                    <div class="note">Items requiring leadership decision on ownership, lifecycle, support, or evidence priority.</div>
                </div>
            </section>

            <section class="section">
                <h2>Risk Heatmap Answer</h2>
                <p>
                    This console answers where CI governance risk is concentrated and what should be fixed first.
                </p>

                <div class="answer">
                    <strong>Current risk interpretation:</strong>
                    The highest CITrust™ risks are concentrated in evidence lineage, ownerless or partially governed operational dependencies, OOS lifecycle closure, hidden workstation dependencies, and incomplete MyAccess routing. These gaps should be remediated before leadership treats the full CI estate as ServiceNow-ready, audit-ready, or operationally trusted.
                </div>
            </section>

            <section class="section">
                <h2>Governance Risk Heatmap</h2>
                <p>
                    CITrust™ ranks risk domains by operational exposure, audit exposure, access impact, and likelihood of creating orphaned or weak CMDB records.
                </p>

                <div class="heatmap">
                    <div class="heat-card">
                        <h3>Evidence Lineage Risk</h3>
                        <span class="badge red">Very High</span>
                        <p>Closure evidence, SOP linkage, backup evidence, audit trail review evidence, and submission evidence remain incomplete for several records.</p>
                        <div class="bar-wrap"><div class="bar redbar"></div></div>
                    </div>

                    <div class="heat-card">
                        <h3>Orphan CI Risk</h3>
                        <span class="badge red">High</span>
                        <p>Some records still have missing or unclear owner, support group, LCM, access route, or evidence reference.</p>
                        <div class="bar-wrap"><div class="bar redbar"></div></div>
                    </div>

                    <div class="heat-card">
                        <h3>Lifecycle Closure Risk</h3>
                        <span class="badge orange">High</span>
                        <p>OOS and retired records require closure evidence, access deactivation proof, and lifecycle accountability.</p>
                        <div class="bar-wrap"><div class="bar orangebar"></div></div>
                    </div>

                    <div class="heat-card">
                        <h3>MyAccess Routing Risk</h3>
                        <span class="badge yellow">Medium</span>
                        <p>Some access roles, approver groups, and admin/vendor access paths remain partially mapped.</p>
                        <div class="bar-wrap"><div class="bar yellowbar"></div></div>
                    </div>

                    <div class="heat-card">
                        <h3>Support Group Risk</h3>
                        <span class="badge yellow">Medium</span>
                        <p>Support routing is improving, but several operational records need support group confirmation and escalation clarity.</p>
                        <div class="bar-wrap"><div class="bar yellowbar"></div></div>
                    </div>

                    <div class="heat-card">
                        <h3>Dependency Risk</h3>
                        <span class="badge yellow">Medium</span>
                        <p>Hidden workstations, local review processes, jump paths, and operational dependencies need stronger mapping.</p>
                        <div class="bar-wrap"><div class="bar yellowbar"></div></div>
                    </div>

                    <div class="heat-card">
                        <h3>Data Quality Risk</h3>
                        <span class="badge blue">Moderate</span>
                        <p>Duplicate risk, stale fields, partial records, and cross-source inconsistency remain in the candidate population.</p>
                        <div class="bar-wrap"><div class="bar bluebar"></div></div>
                    </div>

                    <div class="heat-card">
                        <h3>Classification Risk</h3>
                        <span class="badge green">Lower</span>
                        <p>Most major records have a usable classification, but discovered and OOS records still need confirmation.</p>
                        <div class="bar-wrap"><div class="bar greenbar"></div></div>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Risk Prioritization Matrix</h2>
                <p>
                    This matrix ranks records by the governance risk most likely to block operational trust.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Primary Risk</th>
                            <th>Secondary Risk</th>
                            <th>Impact Area</th>
                            <th>Likelihood</th>
                            <th>Severity</th>
                            <th>Risk Level</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>Owner, access, evidence, and dependency missing</td>
                            <td>Hidden operational review dependency</td>
                            <td>Audit / Backup Review / CMDB</td>
                            <td><span class="badge red">High</span></td>
                            <td><span class="badge red">High</span></td>
                            <td><span class="badge red">Critical</span></td>
                            <td>Create governed candidate and assign owner, support, LCM, access, and evidence path.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>OOS closure and access deactivation not defendable</td>
                            <td>Unclear ownership and lifecycle accountability</td>
                            <td>Lifecycle / Access / Audit</td>
                            <td><span class="badge red">High</span></td>
                            <td><span class="badge red">High</span></td>
                            <td><span class="badge red">Critical</span></td>
                            <td>Attach closure evidence, confirm access removal, and reconcile lifecycle state.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td>Cutover evidence and support routing partial</td>
                            <td>MyAccess role and jump path dependency need final confirmation</td>
                            <td>Cutover / Support / Access</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge red">High</span></td>
                            <td><span class="badge orange">High</span></td>
                            <td>Finalize support group, role mapping, jump path, and cutover evidence linkage.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Support group and evidence linkage partial</td>
                            <td>Operational classification and data quality need reconciliation</td>
                            <td>Support / Evidence / ServiceNow-readiness</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Reconcile support group, owner, lifecycle, and evidence against source records.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Admin access procedure evidence should be linked</td>
                            <td>Privileged access governance explanation needed</td>
                            <td>Access / Infrastructure / Audit</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Attach admin or vendor access procedure evidence and support routing context.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>Approver group confirmation needed</td>
                            <td>Access role evidence should be verified</td>
                            <td>MyAccess / Audit / Lab Operations</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Confirm approver group and role mapping evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>No major current CITrust risk</td>
                            <td>Maintain periodic review</td>
                            <td>Operational Assurance</td>
                            <td><span class="badge green">Low</span></td>
                            <td><span class="badge green">Low</span></td>
                            <td><span class="badge green">Low</span></td>
                            <td>Keep under periodic ownership, support, access, and evidence review.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Risk Control Domains</h2>
                <p>
                    CITrust™ translates weak CMDB records into specific governance risk domains.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Orphan Risk</h3>
                        <p>CI lacks owner, support group, LCM, MyAccess mapping, evidence, or escalation route.</p>
                    </div>

                    <div class="card">
                        <h3>Audit Risk</h3>
                        <p>CI cannot answer audit questions about owner, access, SOP, backup, audit trail, lifecycle, or evidence.</p>
                    </div>

                    <div class="card">
                        <h3>Operational Risk</h3>
                        <p>CI may fail support routing, incident handling, cutover readiness, dependency analysis, or change impact review.</p>
                    </div>

                    <div class="card">
                        <h3>Access Risk</h3>
                        <p>CI has weak MyAccess routing, approver mapping, admin path, vendor access, or role evidence.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Risk Decision Logic</h2>
                <p>
                    Risk is escalated when a CI cannot be operationally defended.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Low-Risk CI</h3>
                        <ul>
                            <li>Owner, support group, and LCM are clear.</li>
                            <li>MyAccess routing and access roles are mapped.</li>
                            <li>Evidence lineage is reviewable.</li>
                            <li>Lifecycle state is current and reconciled.</li>
                            <li>Dependency and support paths are explainable.</li>
                            <li>CI can support audit, change, and operational readiness questions.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>High-Risk CI</h3>
                        <ul>
                            <li>Owner, support group, LCM, or access path is missing.</li>
                            <li>Evidence cannot be located or linked to the CI.</li>
                            <li>Lifecycle state is unresolved, especially OOS or retired records.</li>
                            <li>Dependency chain is hidden or undocumented.</li>
                            <li>Data quality is incomplete or conflicting.</li>
                            <li>Record could create audit, access, support, change, or pre-deviation exposure.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Risk Remediation Queue</h2>
                <p>
                    These items should be handled first because they carry the highest CI governance exposure.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Risk Item</th>
                            <th>Why It Matters</th>
                            <th>Required Remediation</th>
                            <th>Expected Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Local Backup Review Workstation</td>
                            <td>Hidden review dependency with no defensible ownership, access, support, or evidence lineage.</td>
                            <td>Create governed CI candidate and assign owner, support group, LCM, access path, and backup evidence.</td>
                            <td>Convert hidden dependency into governed candidate.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Speedy Glove 1802</td>
                            <td>OOS record may remain operationally ambiguous without closure and access evidence.</td>
                            <td>Confirm closure owner, closure evidence, access deactivation, and lifecycle state.</td>
                            <td>Close orphan lifecycle and access exposure.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Niagara BMS Server</td>
                            <td>Cutover-sensitive dependency requires clear support, access, jump path, and evidence readiness.</td>
                            <td>Finalize support group, MyAccess role, jump path evidence, and cutover evidence.</td>
                            <td>Move from high risk to controlled conditional or trusted state.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Speedy Glove 1803</td>
                            <td>Operational record still has support, evidence, and data quality gaps.</td>
                            <td>Reconcile support group, owner, lifecycle state, and evidence reference.</td>
                            <td>Move to ServiceNow-ready or conditionally trusted state.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, write risk scores into ServiceNow, update CMDB records, or replace formal risk management. This risk heatmap is a governance assurance overlay for CI ownership risk, support routing risk, MyAccess risk, evidence risk, lifecycle risk, dependency risk, data quality risk, classification risk, change impact risk, audit readiness risk, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_RISK_HEATMAP_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Risk Heatmap installed.")
