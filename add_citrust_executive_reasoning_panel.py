from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_EXECUTIVE_REASONING_PANEL_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/executive-reasoning-panel")'
ROUTE_ALIAS = '@app.route("/citrust/reasoning-panel")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Executive Reasoning Panel already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_EXECUTIVE_REASONING_PANEL_V1_ACTIVE
# ============================================================

@app.route("/citrust/executive-reasoning-panel")
@app.route("/citrust/reasoning-panel")
def citrust_executive_reasoning_panel():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Executive Reasoning Panel</title>
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

            .reasoning-grid {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 16px;
                margin-top: 16px;
            }

            .reason-card {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 18px;
            }

            .reason-card h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .reason-card p {
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
                .kpis, .cards, .reasoning-grid, .two-col {
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
                <h1>CITrust™ Executive Reasoning Panel</h1>

                <div class="subtitle">
                    Explains why each Configuration Item is trusted, conditional, blocked, or not ServiceNow-ready by translating ownership, support group, MyAccess, evidence, lifecycle, dependency, data quality, classification, and audit checks into executive-ready reasoning.
                </div>

                <div class="positioning">
                    <strong>Reasoning boundary:</strong>
                    CITrust™ provides explainable governance reasoning only. It does not replace ServiceNow, does not create ServiceNow CIs, does not approve changes, and does not write decisions directly into ServiceNow in this demo. Human governance remains the final decision layer.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                    <a href="/citrust/trust-score-model">Trust Score Model</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                    <a href="/citrust/bottleneck-analysis">Bottleneck Analysis</a>
                    <a href="/citrust/submission-board">Submission Board</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Reasoned Decisions</div>
                    <div class="value">42</div>
                    <div class="note">CI records with explainable readiness reasoning.</div>
                </div>

                <div class="metric">
                    <div class="label">Trusted Decisions</div>
                    <div class="value" style="color: var(--green);">18</div>
                    <div class="note">Records with strong evidence-backed trust reasoning.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Decisions</div>
                    <div class="value" style="color: var(--yellow);">15</div>
                    <div class="note">Records with specific remediation required before full trust.</div>
                </div>

                <div class="metric">
                    <div class="label">Blocked Decisions</div>
                    <div class="value" style="color: var(--red);">9</div>
                    <div class="note">Records with blocking ownership, support, access, evidence, or lifecycle gaps.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive Escalations</div>
                    <div class="value" style="color: var(--orange);">4</div>
                    <div class="note">Records requiring leadership decision or cross-functional ownership alignment.</div>
                </div>

                <div class="metric">
                    <div class="label">Submission Ready</div>
                    <div class="value" style="color: var(--blue);">5</div>
                    <div class="note">Records with reasoning strong enough for submission-pack preparation.</div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Reasoning Answer</h2>
                <p>
                    This panel explains the decision behind the score, not just the score itself.
                </p>

                <div class="answer">
                    <strong>Current executive reasoning:</strong>
                    CITrust™ can defend a subset of the CI estate as operationally trusted. However, several records remain conditional or blocked because the governance reasoning cannot yet defend ownership, support routing, access approval, evidence lineage, lifecycle state, dependency chain, or data quality. Leadership should treat trusted records as usable, conditional records as remediation-controlled, and blocked records as not operationally reliable.
                </div>
            </section>

            <section class="section">
                <h2>Reasoning Domains</h2>
                <p>
                    CITrust™ translates technical CMDB weakness into executive-readable decision logic.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Why Trusted?</h3>
                        <p>Owner, support group, LCM, access, evidence, lifecycle, dependency, and audit context are complete enough for operational reliance.</p>
                    </div>

                    <div class="card">
                        <h3>Why Conditional?</h3>
                        <p>CI has usable data but requires remediation, confirmation, or documented exception before full trust is granted.</p>
                    </div>

                    <div class="card">
                        <h3>Why Blocked?</h3>
                        <p>CI lacks critical governance elements and should not be treated as ServiceNow-ready, access-ready, or audit-ready.</p>
                    </div>

                    <div class="card">
                        <h3>What Must Happen Next?</h3>
                        <p>Reasoning identifies the exact ownership, support, access, evidence, lifecycle, or data action needed to unlock readiness.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive CI Reasoning Matrix</h2>
                <p>
                    This matrix explains the readiness decision for each CI in plain executive terms.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Decision</th>
                            <th>Trust Score</th>
                            <th>Reasoning Summary</th>
                            <th>Blocking Factor</th>
                            <th>Executive Interpretation</th>
                            <th>Next Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge green">Trusted</span></td>
                            <td><span class="badge green">94</span></td>
                            <td>Owner, support group, access mapping, lifecycle, evidence, and operational classification are strong.</td>
                            <td>No material blocker</td>
                            <td>Leadership can rely on this CI as governed and operationally defensible.</td>
                            <td>Maintain periodic governance review.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td><span class="badge yellow">79</span></td>
                            <td>Ownership, support, and access are strong, but admin-access procedure evidence should be linked.</td>
                            <td>Procedure evidence</td>
                            <td>Can remain controlled, but should not be described as fully audit-defensible until procedure evidence is attached.</td>
                            <td>Attach admin or vendor access procedure evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td><span class="badge yellow">66</span></td>
                            <td>Owner and LCM are present, but support routing, MyAccess role mapping, jump path, and cutover evidence remain partial.</td>
                            <td>Cutover evidence and access routing</td>
                            <td>Leadership should keep this on controlled watchlist until cutover evidence and routing are complete.</td>
                            <td>Finalize support group, MyAccess role, jump path, and cutover evidence linkage.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td><span class="badge yellow">61</span></td>
                            <td>Operational state is known, but support group, evidence, and data quality require reconciliation.</td>
                            <td>Support and evidence linkage</td>
                            <td>Can remain visible, but should not be considered fully ServiceNow-ready.</td>
                            <td>Reconcile owner, support group, LCM, and evidence path.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge red">Blocked</span></td>
                            <td><span class="badge red">31</span></td>
                            <td>OOS closure, ownership, support responsibility, access deactivation, and lifecycle evidence are not defensible.</td>
                            <td>Lifecycle closure and access deactivation</td>
                            <td>Leadership should not treat this record as trusted until closure and access evidence are complete.</td>
                            <td>Attach closure evidence, confirm access removal, and reconcile lifecycle state.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge red">Blocked</span></td>
                            <td><span class="badge red">22</span></td>
                            <td>Record lacks owner, support group, LCM, MyAccess mapping, classification, evidence, and dependency lineage.</td>
                            <td>Hidden operational dependency</td>
                            <td>This is a high-priority governance blind spot because it supports recurring review activity without defensible CI control.</td>
                            <td>Create governed candidate and assign full accountability model.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td><span class="badge yellow">78</span></td>
                            <td>Core record is strong, but approver group and role mapping should be confirmed for full access-readiness.</td>
                            <td>MyAccess approver confirmation</td>
                            <td>Near trusted, pending access governance confirmation.</td>
                            <td>Confirm approver group and access role evidence.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Reasoning Pattern Library</h2>
                <p>
                    CITrust™ standardizes the reasoning language so leadership, CMDB teams, ServiceNow teams, and governance reviewers see the same explanation.
                </p>

                <div class="reasoning-grid">
                    <div class="reason-card">
                        <h3><span class="badge green">Trusted Reasoning</span></h3>
                        <p>This CI is operationally trusted because ownership, support routing, access mapping, lifecycle state, dependency lineage, and evidence are defensible.</p>
                    </div>

                    <div class="reason-card">
                        <h3><span class="badge yellow">Conditional Reasoning</span></h3>
                        <p>This CI can remain under controlled review, but one or more governance domains require confirmation before full trust.</p>
                    </div>

                    <div class="reason-card">
                        <h3><span class="badge red">Blocked Reasoning</span></h3>
                        <p>This CI should not move forward because critical governance data is missing, contradictory, or not evidence-backed.</p>
                    </div>

                    <div class="reason-card">
                        <h3><span class="badge blue">Submission Reasoning</span></h3>
                        <p>This CI is ready for submission-pack preparation only when the governance explanation can defend mandatory fields and evidence.</p>
                    </div>

                    <div class="reason-card">
                        <h3><span class="badge orange">Escalation Reasoning</span></h3>
                        <p>This CI requires leadership or cross-functional decision because ownership, lifecycle, support, or evidence responsibility is unresolved.</p>
                    </div>

                    <div class="reason-card">
                        <h3><span class="badge purple">Pre-Deviation Reasoning</span></h3>
                        <p>This CI has early-warning signs that could become audit, access, support, lifecycle, or operational readiness issues if not remediated.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Executive Decision Logic</h2>
                <p>
                    This panel keeps reasoning separate from automatic action.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Leadership Can Defend</h3>
                        <ul>
                            <li>Why the CI is trusted or not trusted.</li>
                            <li>Which governance domains are complete.</li>
                            <li>Which evidence supports the decision.</li>
                            <li>Which records are ready for submission-pack preparation.</li>
                            <li>Which conditional records require remediation.</li>
                            <li>Which blocked records create operational or audit exposure.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Leadership Should Not Assume</h3>
                        <ul>
                            <li>That a CI is trusted because it exists in a list.</li>
                            <li>That ServiceNow-style fields are operationally valid without evidence.</li>
                            <li>That MyAccess routing is correct without approver and role mapping.</li>
                            <li>That OOS records are closed without closure evidence.</li>
                            <li>That hidden dependencies are safe without owner, support, and evidence.</li>
                            <li>That AI reasoning replaces human governance approval.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Reasoning-Driven Remediation Queue</h2>
                <p>
                    These are the highest-value actions produced by the reasoning panel.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Reasoning Gap</th>
                            <th>Why It Matters</th>
                            <th>Required Action</th>
                            <th>Expected Reasoning Upgrade</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no defensible governance story.</td>
                            <td>Leadership cannot explain ownership, evidence, support, access, or dependency impact.</td>
                            <td>Create governed candidate and assign owner, support group, LCM, access route, and evidence path.</td>
                            <td>Blocked → Conditional</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment lacks closure and access deactivation reasoning.</td>
                            <td>Audit or operational review could question why the record is still unresolved.</td>
                            <td>Attach closure evidence and confirm access removal.</td>
                            <td>Blocked → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Cutover-sensitive BMS record has partial support and access reasoning.</td>
                            <td>Post-cutover routing, vendor access, and support accountability may not be defensible.</td>
                            <td>Finalize support group, MyAccess role, jump path, and cutover evidence.</td>
                            <td>Conditional → Trusted</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Lab system access approval reasoning needs confirmation.</td>
                            <td>Approver path may depend on manual interpretation.</td>
                            <td>Confirm approver group and role mapping evidence.</td>
                            <td>Conditional → Access-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, approve ServiceNow changes, write decisions into ServiceNow, or replace human governance. This executive reasoning panel is a governance assurance overlay for explainable CI trust, executive decision support, ServiceNow-readiness reasoning, MyAccess readiness reasoning, audit defensibility, evidence lineage, dependency lineage, bottleneck analysis, risk heatmap interpretation, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_EXECUTIVE_REASONING_PANEL_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Executive Reasoning Panel installed.")
