from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_PRE_DEVIATION_READINESS_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/pre-deviation-readiness")'
ROUTE_ALIAS = '@app.route("/citrust/deviation-prevention")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Pre-Deviation Readiness Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_PRE_DEVIATION_READINESS_V1_ACTIVE
# ============================================================

@app.route("/citrust/pre-deviation-readiness")
@app.route("/citrust/deviation-prevention")
def citrust_pre_deviation_readiness():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Pre-Deviation Readiness Console</title>
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
                    radial-gradient(circle at top left, rgba(255,92,112,0.15), transparent 30%),
                    radial-gradient(circle at top right, rgba(92,200,255,0.16), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(247,201,72,0.08), transparent 30%),
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
                border: 1px solid rgba(255,92,112,0.38);
                background: rgba(255,92,112,0.10);
                color: #ffe5e9;
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
                min-height: 145px;
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
                <h1>CITrust™ Pre-Deviation Readiness Console</h1>

                <div class="subtitle">
                    Detects Configuration Item governance gaps before they become deviations, audit findings, failed access requests, failed cutovers, incident-routing failures, lifecycle ambiguity, or weak ServiceNow-style CMDB records.
                </div>

                <div class="positioning">
                    <strong>Pre-deviation boundary:</strong>
                    CITrust™ does not create deviations, approve quality events, update ServiceNow, or replace human governance. It identifies CI governance conditions that could become operational or audit issues if not remediated before execution, cutover, access change, lifecycle change, or submission review.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                    <a href="/citrust/governance-debt-register">Governance Debt</a>
                    <a href="/citrust/change-impact-readiness">Change Impact</a>
                    <a href="/citrust/evidence-pack-builder">Evidence Pack</a>
                    <a href="/citrust/audit-question-bank">Audit Question Bank</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Pre-Deviation Signals</div>
                    <div class="value">31</div>
                    <div class="note">Open governance conditions that could become operational or audit events.</div>
                </div>

                <div class="metric">
                    <div class="label">Critical Signals</div>
                    <div class="value" style="color: var(--red);">8</div>
                    <div class="note">Owner, support, access, lifecycle, or evidence gaps requiring immediate remediation.</div>
                </div>

                <div class="metric">
                    <div class="label">Watchlist Signals</div>
                    <div class="value" style="color: var(--yellow);">14</div>
                    <div class="note">Conditional risks that require tracking before trust or submission.</div>
                </div>

                <div class="metric">
                    <div class="label">Prevented Risks</div>
                    <div class="value" style="color: var(--green);">9</div>
                    <div class="note">Issues controlled through evidence, ownership, escalation, or remediation closure.</div>
                </div>

                <div class="metric">
                    <div class="label">Cutover Exposure</div>
                    <div class="value" style="color: var(--orange);">6</div>
                    <div class="note">Cutover-sensitive records with unresolved support, access, or evidence risk.</div>
                </div>

                <div class="metric">
                    <div class="label">Escalate Now</div>
                    <div class="value" style="color: var(--blue);">4</div>
                    <div class="note">Items requiring owner, support, lifecycle, access, or leadership action.</div>
                </div>
            </section>

            <section class="section">
                <h2>Pre-Deviation Answer</h2>
                <p>
                    This console answers which CI governance gaps must be closed before they become formal operational problems.
                </p>

                <div class="answer">
                    <strong>Current pre-deviation interpretation:</strong>
                    CITrust™ should treat missing owner, missing support group, unclear LCM, unmapped MyAccess route, hidden dependency, stale evidence, incomplete OOS closure, unresolved vendor handoff, and weak change-impact data as pre-deviation signals. These are not just administrative gaps; they are early warning indicators of failed support, failed access routing, audit weakness, or CMDB trust failure.
                </div>
            </section>

            <section class="section">
                <h2>Pre-Deviation Signal Domains</h2>
                <p>
                    CITrust™ groups early warning signals into governance domains so remediation can happen before failure.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Ownership Signal</h3>
                        <p>Owner, support group, LCM, backup owner, or escalation path is missing, stale, disputed, or not evidence-backed.</p>
                    </div>

                    <div class="card">
                        <h3>Access Signal</h3>
                        <p>MyAccess role, approver group, admin route, vendor access path, or access-removal evidence is incomplete.</p>
                    </div>

                    <div class="card">
                        <h3>Lifecycle Signal</h3>
                        <p>Active, cutover, OOS, retired, or closed state cannot be defended with current lifecycle evidence.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Signal</h3>
                        <p>Evidence exists only informally, is stale, is disconnected from the CI, or cannot support audit-style questioning.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Pre-Deviation Readiness Matrix</h2>
                <p>
                    This matrix identifies which CIs are likely to trigger governance, support, access, audit, or cutover issues if not remediated.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Pre-Deviation Signal</th>
                            <th>Likely Failure Mode</th>
                            <th>Current Control</th>
                            <th>Readiness Decision</th>
                            <th>Required Prevention Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">No Material Signal</span></td>
                            <td>Low likelihood if cadence remains current.</td>
                            <td>Owner, support, evidence, lifecycle, and access context are aligned.</td>
                            <td><span class="badge green">Prevented / Controlled</span></td>
                            <td>Maintain periodic governance cadence and evidence refresh.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge orange">Cutover Signal</span></td>
                            <td>Cutover support failure, vendor handoff gap, access route confusion, or incomplete rollback evidence.</td>
                            <td>Owner and cutover context are known, but support, MyAccess, jump path, and evidence remain partial.</td>
                            <td><span class="badge yellow">Watchlist</span></td>
                            <td>Finalize support group, MyAccess role, jump path, vendor handoff, rollback, and cutover evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge yellow">Access Evidence Signal</span></td>
                            <td>Privileged access could be challenged if admin/vendor procedure evidence is missing.</td>
                            <td>Access route is known, but procedure evidence and backup support owner should be linked.</td>
                            <td><span class="badge yellow">Conditional Prevention</span></td>
                            <td>Attach admin/vendor procedure, access review evidence, and escalation owner.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge yellow">Support / Evidence Signal</span></td>
                            <td>Support routing delay, incomplete evidence trail, or weak operational readiness defense.</td>
                            <td>Operational state is known, but support group, LCM, and evidence path need reconciliation.</td>
                            <td><span class="badge yellow">Conditional Prevention</span></td>
                            <td>Reconcile support group, LCM, access path, evidence, and operational classification.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge yellow">Access Confirmation Signal</span></td>
                            <td>Access request or audit question could fail if approver group evidence is incomplete.</td>
                            <td>Core CI context is strong; MyAccess approver group needs final confirmation.</td>
                            <td><span class="badge yellow">Near Controlled</span></td>
                            <td>Confirm MyAccess approver group, role evidence, and access escalation path.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge red">Lifecycle Closure Signal</span></td>
                            <td>OOS lifecycle ambiguity, access-removal failure, orphan CI exposure, or audit finding.</td>
                            <td>OOS context exists but closure evidence, access removal, and lifecycle owner are not defensible.</td>
                            <td><span class="badge red">High Risk Signal</span></td>
                            <td>Attach closure evidence, confirm access deactivation, assign closure owner, and update decision ledger.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge red">Hidden Dependency Signal</span></td>
                            <td>Recurring operational review depends on an unmanaged CI-like object with no owner, support, access, or evidence.</td>
                            <td>Only operational discovery exists; no governed candidate record exists.</td>
                            <td><span class="badge red">Immediate Prevention Needed</span></td>
                            <td>Create governed candidate and assign owner, support, LCM, access route, evidence, cadence, and escalation path.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Pre-Deviation Decision Logic</h2>
                <p>
                    CITrust™ treats weak governance signals as preventable operational risk.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Prevented / Controlled</h3>
                        <ul>
                            <li>Owner, support group, and LCM are confirmed.</li>
                            <li>MyAccess, admin, vendor, or jump path is evidence-backed.</li>
                            <li>Lifecycle state is clear and current.</li>
                            <li>Dependencies and relationships are mapped.</li>
                            <li>Evidence pack can answer audit-style questions.</li>
                            <li>Decision ledger and cadence review are current.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Pre-Deviation Signal Active</h3>
                        <ul>
                            <li>Owner, support, LCM, or escalation path is missing.</li>
                            <li>Access approval or removal cannot be defended.</li>
                            <li>OOS or retired state lacks closure evidence.</li>
                            <li>Hidden dependency supports recurring work without governance.</li>
                            <li>Change impact is based on incomplete relationship data.</li>
                            <li>Evidence is stale, missing, or disconnected from the CI.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Pre-Deviation Prevention Queue</h2>
                <p>
                    These actions should be completed before the gap becomes an operational issue, audit weakness, or formal deviation driver.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Pre-Deviation Signal</th>
                            <th>Why It Matters</th>
                            <th>Prevention Action</th>
                            <th>Expected Risk Reduction</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no governed CI model.</td>
                            <td>Backup review continuity and evidence may fail without ownership, support, access, and cadence.</td>
                            <td>Create governed candidate and assign owner, support group, LCM, access route, evidence, and review cadence.</td>
                            <td>High Risk Signal → Controlled Candidate</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment lacks closure and access deactivation evidence.</td>
                            <td>Lifecycle ambiguity and access risk may become audit finding or governance exception.</td>
                            <td>Attach closure evidence, confirm access removal, assign closure owner, and record decision.</td>
                            <td>High Risk Signal → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover readiness has partial support/access evidence.</td>
                            <td>Cutover failure, vendor access gap, or support-routing issue may occur after transition.</td>
                            <td>Finalize support group, MyAccess role, jump path, vendor handoff, rollback, and cutover evidence.</td>
                            <td>Watchlist → Controlled Cutover</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Admin/vendor access procedure evidence is incomplete.</td>
                            <td>Privileged access can be challenged during audit or operational review.</td>
                            <td>Attach admin/vendor procedure, access review proof, and escalation owner.</td>
                            <td>Conditional Prevention → Audit-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace deviation management, quality event systems, ServiceNow, MyAccess, change control, audit systems, or human governance. This pre-deviation readiness console is a governance assurance overlay for early detection of CI owner gaps, support gaps, LCM gaps, access gaps, lifecycle gaps, evidence gaps, hidden dependencies, change-impact exposure, audit weakness, ServiceNow-readiness risk, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_PRE_DEVIATION_READINESS_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Pre-Deviation Readiness Console installed.")
