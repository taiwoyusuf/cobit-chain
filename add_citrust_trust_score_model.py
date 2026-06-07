from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_TRUST_SCORE_MODEL_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/trust-score-model")'
ROUTE_ALIAS = '@app.route("/citrust/trust-scoring")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Trust Score Model already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_TRUST_SCORE_MODEL_V1_ACTIVE
# ============================================================

@app.route("/citrust/trust-score-model")
@app.route("/citrust/trust-scoring")
def citrust_trust_score_model():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Trust Score Model</title>
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
                border: 1px solid rgba(92,200,255,0.36);
                background: rgba(92,200,255,0.10);
                color: #d9f3ff;
                border-radius: 18px;
                padding: 20px;
                margin-top: 16px;
                line-height: 1.65;
                font-size: 15px;
            }

            .score-grid {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 16px;
                margin-top: 16px;
            }

            .score-card {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 18px;
            }

            .score-card h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .score-card p {
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

            .bar.owner { width: 82%; background: var(--green); }
            .bar.access { width: 74%; background: var(--blue); }
            .bar.evidence { width: 44%; background: var(--red); }
            .bar.dependency { width: 62%; background: var(--yellow); }

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

            .formula {
                border: 1px solid rgba(180,156,255,0.35);
                background: rgba(180,156,255,0.10);
                color: #eee7ff;
                border-radius: 18px;
                padding: 18px;
                margin-top: 16px;
                font-size: 15px;
                line-height: 1.7;
            }

            .footer {
                color: var(--muted);
                font-size: 12px;
                margin-top: 22px;
                line-height: 1.6;
            }

            @media (max-width: 1180px) {
                .kpis, .score-grid, .two-col {
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
                <h1>CITrust™ Trust Score Model</h1>

                <div class="subtitle">
                    Converts CI governance evidence into an explainable trust score showing whether each Configuration Item is trusted, conditional, or blocked across ownership, support group, LCM, MyAccess routing, evidence lineage, dependency lineage, lifecycle state, audit readiness, and ServiceNow-readiness.
                </div>

                <div class="positioning">
                    <strong>Scoring boundary:</strong>
                    ServiceNow remains the system of record. CITrust™ does not create ServiceNow CIs, does not write scores into ServiceNow in this demo, and does not replace CMDB governance. This page provides a governance assurance score that explains whether a CI can be operationally trusted.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                    <a href="/citrust/evidence-lineage">Evidence Lineage</a>
                    <a href="/citrust/dependency-lineage">Dependency Lineage</a>
                    <a href="/citrust/pre-deviation-readiness">Pre-Deviation Readiness</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                    <a href="/citrust/submission-board">Submission Board</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Average CI Trust Score</div>
                    <div class="value" style="color: var(--yellow);">68</div>
                    <div class="note">Current estate-level trust score across all assessed CI records.</div>
                </div>

                <div class="metric">
                    <div class="label">Trusted CIs</div>
                    <div class="value" style="color: var(--green);">18</div>
                    <div class="note">Score 80–100 with evidence-backed readiness.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional CIs</div>
                    <div class="value" style="color: var(--yellow);">15</div>
                    <div class="note">Score 50–79 with remediable governance gaps.</div>
                </div>

                <div class="metric">
                    <div class="label">Blocked CIs</div>
                    <div class="value" style="color: var(--red);">9</div>
                    <div class="note">Score below 50 or missing critical control ownership.</div>
                </div>

                <div class="metric">
                    <div class="label">Highest Score</div>
                    <div class="value" style="color: var(--green);">94</div>
                    <div class="note">Best-in-class CI record with strong evidence and routing readiness.</div>
                </div>

                <div class="metric">
                    <div class="label">Lowest Score</div>
                    <div class="value" style="color: var(--red);">22</div>
                    <div class="note">Owner, evidence, access, dependency, or lifecycle gaps remain unresolved.</div>
                </div>
            </section>

            <section class="section">
                <h2>Trust Score Interpretation</h2>
                <p>
                    CITrust™ uses scoring to make the CI governance decision explainable.
                </p>

                <div class="answer">
                    <strong>Current scoring interpretation:</strong>
                    The CI estate is not uniformly trustworthy. Some CIs are ready for operational reliance and ServiceNow-style submission, but a meaningful portion remains conditional or blocked because evidence lineage, support routing, lifecycle closure, MyAccess mapping, or dependency trust is incomplete.
                </div>
            </section>

            <section class="section">
                <h2>Trust Score Formula</h2>
                <p>
                    This model is demo-safe and explainable. It does not rely on hidden automation or uncontrolled AI decisions.
                </p>

                <div class="formula">
                    <strong>CI Trust Score =</strong>
                    Ownership Readiness × 20%
                    + Support Group Readiness × 15%
                    + LCM Readiness × 10%
                    + MyAccess Readiness × 15%
                    + Evidence Lineage × 20%
                    + Dependency Lineage × 10%
                    + Lifecycle Readiness × 5%
                    + Audit Readiness × 5%
                </div>

                <div class="score-grid">
                    <div class="score-card">
                        <h3>Ownership Domain</h3>
                        <span class="badge green">82%</span>
                        <p>Owner, support accountability, LCM, and escalation coverage are strongest overall.</p>
                        <div class="bar-wrap"><div class="bar owner"></div></div>
                    </div>

                    <div class="score-card">
                        <h3>Access Domain</h3>
                        <span class="badge blue">74%</span>
                        <p>MyAccess routing is improving, but approver group and role mapping still need cleanup.</p>
                        <div class="bar-wrap"><div class="bar access"></div></div>
                    </div>

                    <div class="score-card">
                        <h3>Evidence Domain</h3>
                        <span class="badge red">44%</span>
                        <p>Evidence remains the weakest area across closure, SOP, backup, audit trail, and submission artifacts.</p>
                        <div class="bar-wrap"><div class="bar evidence"></div></div>
                    </div>

                    <div class="score-card">
                        <h3>Dependency Domain</h3>
                        <span class="badge yellow">62%</span>
                        <p>Several hidden workstation, access path, support, and review dependencies remain partially mapped.</p>
                        <div class="bar-wrap"><div class="bar dependency"></div></div>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Trust Score Board</h2>
                <p>
                    This board explains why each CI is trusted, conditional, or blocked.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Ownership</th>
                            <th>Access</th>
                            <th>Evidence</th>
                            <th>Dependency</th>
                            <th>Lifecycle</th>
                            <th>Trust Score</th>
                            <th>Trust Decision</th>
                            <th>Primary Reason</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">Strong</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge green">94</span></td>
                            <td><span class="badge green">Trusted</span></td>
                            <td>Strong ownership, access, evidence, and lifecycle alignment.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge soft-green">Strong</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-yellow">Procedure Needed</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge yellow">79</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Admin access procedure evidence should be linked.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Cutover</span></td>
                            <td><span class="badge yellow">66</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Support routing, MyAccess role mapping, and cutover evidence remain partial.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Local Dependency</span></td>
                            <td><span class="badge soft-green">Operational</span></td>
                            <td><span class="badge yellow">61</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Support group, access routing, and evidence lineage need reconciliation.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge yellow">78</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Approver group and role mapping should be confirmed.</td>
                        </tr>

                        <tr>
                            <td><strong>Chromeleon Workstation</strong><br><span style="color: var(--muted);">Lab workstation dependency</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Role Check</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-yellow">Workstation Link</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge yellow">73</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Role mapping and workstation dependency evidence should be finalized.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Unknown</span></td>
                            <td><span class="badge soft-yellow">Closure Needed</span></td>
                            <td><span class="badge red">31</span></td>
                            <td><span class="badge red">Blocked</span></td>
                            <td>OOS closure, ownership, access, and lifecycle evidence are not defendable.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Hidden</span></td>
                            <td><span class="badge soft-yellow">Discovered</span></td>
                            <td><span class="badge red">22</span></td>
                            <td><span class="badge red">Blocked</span></td>
                            <td>No defensible owner, access route, evidence lineage, or dependency record.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Trust Decision Thresholds</h2>
                <p>
                    The score supports governance judgment. It does not replace human review or CMDB approval.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Trusted / Conditional / Blocked</h3>
                        <ul>
                            <li><strong>80–100:</strong> Trusted CI with defensible ownership, access, evidence, lifecycle, and dependency lineage.</li>
                            <li><strong>50–79:</strong> Conditional CI requiring remediation, confirmation, or documented exception.</li>
                            <li><strong>0–49:</strong> Blocked CI that should not be treated as operationally trusted.</li>
                            <li>Critical missing owner, support group, LCM, access, or evidence can force blocked status even when some fields look complete.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Why This Matters</h3>
                        <ul>
                            <li>Prevents weak records from becoming trusted CMDB entries.</li>
                            <li>Explains why a CI is ready or not ready.</li>
                            <li>Supports MyAccess routing, audit response, and operational readiness.</li>
                            <li>Identifies remediation priorities before deviation or audit exposure.</li>
                            <li>Creates a defensible governance explanation for leadership.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Score Improvement Queue</h2>
                <p>
                    These actions would raise CI trust scores and move records from blocked or conditional status toward trusted status.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Record</th>
                            <th>Score Blocker</th>
                            <th>Remediation</th>
                            <th>Expected Score Impact</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Local Backup Review Workstation</td>
                            <td>Missing owner, access, evidence, and dependency lineage.</td>
                            <td>Create governed candidate, assign owner, map support group, define LCM, and link backup evidence.</td>
                            <td>Move from blocked to conditional.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Speedy Glove 1802</td>
                            <td>OOS closure, ownership, and access deactivation evidence missing.</td>
                            <td>Attach closure evidence, confirm access removal, and reconcile lifecycle state.</td>
                            <td>Move from blocked to closed/defensible.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Niagara BMS Server</td>
                            <td>Partial support routing, access role mapping, and cutover evidence.</td>
                            <td>Confirm support group, MyAccess role, jump path, and cutover evidence linkage.</td>
                            <td>Move from conditional to trusted.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Jump Server Access Path</td>
                            <td>Administrative access procedure evidence not fully linked.</td>
                            <td>Attach admin-access procedure or vendor-access governance artifact.</td>
                            <td>Move from conditional to trusted.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, write scores into ServiceNow, or bypass CMDB governance in this demo. This trust score model is a governance assurance overlay for explainable CI trust, ServiceNow-readiness, MyAccess readiness, ownership accountability, evidence lineage, dependency lineage, audit readiness, pre-deviation prevention, and executive decision support.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_TRUST_SCORE_MODEL_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Trust Score Model installed.")
