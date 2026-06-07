from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_READINESS_MATURITY_MODEL_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/readiness-maturity-model")'
ROUTE_ALIAS = '@app.route("/citrust/maturity-model")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Readiness Maturity Model already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_READINESS_MATURITY_MODEL_V1_ACTIVE
# ============================================================

@app.route("/citrust/readiness-maturity-model")
@app.route("/citrust/maturity-model")
def citrust_readiness_maturity_model():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Readiness Maturity Model</title>
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
                border: 1px solid rgba(180,156,255,0.38);
                background: rgba(180,156,255,0.10);
                color: #eee7ff;
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

            .maturity-grid {
                display: grid;
                grid-template-columns: repeat(6, 1fr);
                gap: 12px;
                margin-top: 16px;
            }

            .level-card {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 16px;
                min-height: 205px;
            }

            .level-card h3 {
                margin: 0 0 8px 0;
                font-size: 16px;
            }

            .level-card p {
                margin: 0;
                color: var(--muted);
                font-size: 13px;
                line-height: 1.5;
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
                .kpis, .maturity-grid, .cards, .two-col {
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
                <h1>CITrust™ Readiness Maturity Model</h1>

                <div class="subtitle">
                    Defines maturity levels for Configuration Item governance from unmanaged CI discovery to continuously governed, evidence-backed, executive-defensible, ServiceNow-ready, MyAccess-ready, audit-ready, and operationally trusted CI assurance.
                </div>

                <div class="positioning">
                    <strong>Maturity boundary:</strong>
                    ServiceNow remains the system of record. CITrust™ does not create CIs, update CMDB records, or replace human governance. This maturity model explains how CI governance improves from incomplete records to continuous trust assurance.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/kpi-catalog">KPI Catalog</a>
                    <a href="/citrust/readiness-thresholds">Threshold Policy</a>
                    <a href="/citrust/governance-debt-register">Governance Debt</a>
                    <a href="/citrust/governance-cadence">Governance Cadence</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Maturity Levels</div>
                    <div class="value">6</div>
                    <div class="note">Level 0 unmanaged through Level 5 continuously governed.</div>
                </div>

                <div class="metric">
                    <div class="label">Average Maturity</div>
                    <div class="value" style="color: var(--yellow);">2.8</div>
                    <div class="note">Current estate is between governed intake and evidence-backed readiness.</div>
                </div>

                <div class="metric">
                    <div class="label">Level 4+ CIs</div>
                    <div class="value" style="color: var(--green);">9</div>
                    <div class="note">Records approaching executive-defensible trust.</div>
                </div>

                <div class="metric">
                    <div class="label">Level 2–3 CIs</div>
                    <div class="value" style="color: var(--yellow);">24</div>
                    <div class="note">Records with structure but incomplete evidence, cadence, or relationships.</div>
                </div>

                <div class="metric">
                    <div class="label">Level 0–1 CIs</div>
                    <div class="value" style="color: var(--red);">9</div>
                    <div class="note">Records still unmanaged, discovered, orphaned, or blocked.</div>
                </div>

                <div class="metric">
                    <div class="label">Upgrade Candidates</div>
                    <div class="value" style="color: var(--blue);">14</div>
                    <div class="note">CIs that can move up one level after targeted remediation.</div>
                </div>
            </section>

            <section class="section">
                <h2>Maturity Model Answer</h2>
                <p>
                    This model answers how mature CI governance is and what must happen to move each CI to a higher readiness level.
                </p>

                <div class="answer">
                    <strong>Current maturity interpretation:</strong>
                    CITrust™ maturity is not the same as having a CI record. A CI becomes mature only when identity, owner, support group, LCM, MyAccess routing, lifecycle state, relationships, evidence lineage, cadence, decision history, and audit defensibility are progressively governed. The current estate has strong islands of maturity, but hidden dependencies, OOS closure gaps, access evidence gaps, and stale review cadence are keeping several records below executive-defensible trust.
                </div>
            </section>

            <section class="section">
                <h2>CITrust™ Maturity Levels</h2>
                <p>
                    These levels create a common language for leadership, CMDB teams, ServiceNow teams, infrastructure, MyAccess, and audit stakeholders.
                </p>

                <div class="maturity-grid">
                    <div class="level-card">
                        <h3><span class="badge red">Level 0</span><br>Unmanaged</h3>
                        <p>CI exists only as tribal knowledge, local spreadsheet item, discovered dependency, or informal operational object. No governed owner, support, access, lifecycle, or evidence model exists.</p>
                    </div>

                    <div class="level-card">
                        <h3><span class="badge red">Level 1</span><br>Identified</h3>
                        <p>CI identity is known, but ownership, support group, LCM, MyAccess route, evidence, or classification is incomplete or disputed.</p>
                    </div>

                    <div class="level-card">
                        <h3><span class="badge yellow">Level 2</span><br>Structured Intake</h3>
                        <p>CI candidate has required intake fields started, but relationships, authority source, evidence, and readiness decision remain partial.</p>
                    </div>

                    <div class="level-card">
                        <h3><span class="badge yellow">Level 3</span><br>Governed Review</h3>
                        <p>CI has owner, support, LCM, classification, and partial evidence. It can stay in controlled review but is not fully trusted.</p>
                    </div>

                    <div class="level-card">
                        <h3><span class="badge blue">Level 4</span><br>Evidence-Backed</h3>
                        <p>CI is evidence-backed across owner, support, access, lifecycle, relationships, and readiness reasoning. It can support passport, attestation, and submission-pack preparation.</p>
                    </div>

                    <div class="level-card">
                        <h3><span class="badge green">Level 5</span><br>Continuously Governed</h3>
                        <p>CI remains trusted over time through cadence reviews, decision ledger updates, governance debt control, evidence refresh, and executive-defensible readiness logic.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Maturity Assessment Matrix</h2>
                <p>
                    This matrix shows current maturity level, weakness, and upgrade path for major CITrust™ records.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Current Level</th>
                            <th>Maturity Strength</th>
                            <th>Maturity Weakness</th>
                            <th>Upgrade Requirement</th>
                            <th>Target Level</th>
                            <th>Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge green">Level 5</span></td>
                            <td>Owner, support, lifecycle, access, evidence, and cadence are strong.</td>
                            <td>Periodic review must remain current.</td>
                            <td>Maintain cadence and decision ledger updates.</td>
                            <td>Level 5</td>
                            <td><span class="badge green">Continuously Governed</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge blue">Level 4</span></td>
                            <td>Access route, owner, and support context are well understood.</td>
                            <td>Admin or vendor access procedure evidence should be linked.</td>
                            <td>Attach procedure evidence and refresh access cadence.</td>
                            <td>Level 5</td>
                            <td><span class="badge yellow">Upgrade Candidate</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">Cutover-sensitive BMS dependency</span></td>
                            <td><span class="badge yellow">Level 3</span></td>
                            <td>Owner and lifecycle context exist; cutover path is known.</td>
                            <td>Support group, MyAccess role, jump path, and cutover evidence remain partial.</td>
                            <td>Complete cutover support, access, dependency, and evidence package.</td>
                            <td>Level 4</td>
                            <td><span class="badge yellow">Controlled Review</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge yellow">Level 3</span></td>
                            <td>Operational state and owner context are known.</td>
                            <td>Support group, evidence path, and data quality require reconciliation.</td>
                            <td>Reconcile owner, support group, LCM, evidence, and relationships.</td>
                            <td>Level 4</td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge blue">Level 4</span></td>
                            <td>Core record is strong and evidence-backed.</td>
                            <td>MyAccess approver group and role evidence need confirmation.</td>
                            <td>Confirm MyAccess approver and role evidence.</td>
                            <td>Level 5</td>
                            <td><span class="badge yellow">Near Continuous Governance</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge red">Level 1</span></td>
                            <td>Record identity is partially known.</td>
                            <td>OOS closure, access deactivation, lifecycle owner, and evidence are not defensible.</td>
                            <td>Attach closure evidence, confirm access removal, and reconcile lifecycle owner.</td>
                            <td>Level 3</td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge red">Level 0</span></td>
                            <td>Operational dependency has been discovered.</td>
                            <td>No governed candidate, owner, support group, LCM, access route, evidence, or cadence.</td>
                            <td>Create governed candidate and populate mandatory controls.</td>
                            <td>Level 2</td>
                            <td><span class="badge red">Unmanaged Dependency</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Maturity Domains</h2>
                <p>
                    CITrust™ maturity is calculated from multiple governance dimensions, not a single data field.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Identity Maturity</h3>
                        <p>CI name, class, source authority, duplicate status, and candidate identity are clear and reconciled.</p>
                    </div>

                    <div class="card">
                        <h3>Accountability Maturity</h3>
                        <p>Owner, support group, LCM, escalation route, and attestation owner are confirmed and current.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Maturity</h3>
                        <p>Evidence exists for access, SOP, backup, audit trail, lifecycle, closure, validation, and cutover where applicable.</p>
                    </div>

                    <div class="card">
                        <h3>Continuity Maturity</h3>
                        <p>Cadence reviews, decision ledger entries, governance debt burn-down, and readiness thresholds remain current over time.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Maturity Upgrade Rules</h2>
                <p>
                    A CI cannot skip maturity levels unless the evidence fully supports the target state.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Can Upgrade</h3>
                        <ul>
                            <li>Mandatory fields are complete.</li>
                            <li>Owner, support group, LCM, and access route are confirmed.</li>
                            <li>Relationships and dependencies are mapped.</li>
                            <li>Evidence is linked and reviewable.</li>
                            <li>Decision ledger records the readiness decision.</li>
                            <li>Cadence reviews keep the trust state current.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Cannot Upgrade</h3>
                        <ul>
                            <li>CI is based only on tribal knowledge or spreadsheet presence.</li>
                            <li>Owner, support, LCM, access, lifecycle, or evidence is missing.</li>
                            <li>OOS or retired state lacks closure evidence.</li>
                            <li>Hidden dependency lacks governed candidate record.</li>
                            <li>Field conflicts remain unresolved.</li>
                            <li>Thresholds are overridden without evidence-backed exception logic.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Maturity Upgrade Queue</h2>
                <p>
                    These actions move CIs to the next maturity level.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Maturity Gap</th>
                            <th>Why It Matters</th>
                            <th>Upgrade Action</th>
                            <th>Expected Maturity Lift</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation is Level 0.</td>
                            <td>Recurring operational dependency is unmanaged and not audit-defensible.</td>
                            <td>Create governed candidate and assign owner, support, LCM, access, evidence, and cadence.</td>
                            <td>Level 0 → Level 2</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment is stuck at Level 1.</td>
                            <td>Lifecycle closure cannot be defended without evidence and access deactivation.</td>
                            <td>Attach closure evidence, confirm access removal, and record lifecycle decision.</td>
                            <td>Level 1 → Level 3</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Cutover BMS record is Level 3.</td>
                            <td>Support, access, jump path, and cutover evidence are required for evidence-backed maturity.</td>
                            <td>Finalize cutover evidence package and confirm MyAccess/support routing.</td>
                            <td>Level 3 → Level 4</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access-path evidence is keeping strong records below Level 5.</td>
                            <td>Continuous governance requires current access evidence and review cadence.</td>
                            <td>Attach admin/vendor access evidence and refresh access review cadence.</td>
                            <td>Level 4 → Level 5</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, update CMDB records, or automate governance approval in this demo. This readiness maturity model is a governance assurance overlay for CI maturity scoring, operational trust maturity, ServiceNow-readiness maturity, MyAccess-readiness maturity, evidence maturity, lifecycle maturity, relationship maturity, cadence maturity, governance debt reduction, executive defensibility, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_READINESS_MATURITY_MODEL_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Readiness Maturity Model installed.")
