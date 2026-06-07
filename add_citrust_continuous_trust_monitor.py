from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CONTINUOUS_TRUST_MONITOR_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/continuous-trust-monitor")'
ROUTE_ALIAS = '@app.route("/citrust/trust-continuity")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Continuous Trust Monitor already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_CONTINUOUS_TRUST_MONITOR_V1_ACTIVE
# ============================================================

@app.route("/citrust/continuous-trust-monitor")
@app.route("/citrust/trust-continuity")
def citrust_continuous_trust_monitor():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Continuous Trust Monitor</title>
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
                    radial-gradient(circle at top right, rgba(49,208,125,0.14), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(180,156,255,0.10), transparent 30%),
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
                border: 1px solid rgba(49,208,125,0.36);
                background: rgba(49,208,125,0.10);
                color: #dfffea;
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
                <h1>CITrust™ Continuous Trust Monitor</h1>

                <div class="subtitle">
                    Continuously monitors whether Configuration Items remain operationally trusted after evidence drift, cadence failures, access changes, support changes, vendor activity, rollback events, post-change verification, lifecycle updates, and ServiceNow-style readiness remediation.
                </div>

                <div class="positioning">
                    <strong>Continuous trust boundary:</strong>
                    ServiceNow stores CI records. CITrust™ validates whether those CIs remain trustworthy over time. This demo does not update ServiceNow, approve access, execute changes, or replace human governance. It continuously evaluates whether the trust state is still defensible.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/governance-cadence">Governance Cadence</a>
                    <a href="/citrust/evidence-drift-monitor">Evidence Drift</a>
                    <a href="/citrust/post-change-verification">Post-Change Verification</a>
                    <a href="/citrust/pre-deviation-readiness">Pre-Deviation</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Continuous Trust Checks</div>
                    <div class="value">72</div>
                    <div class="note">Checks across cadence, drift, change, access, support, lifecycle, rollback, and evidence.</div>
                </div>

                <div class="metric">
                    <div class="label">Trust Maintained</div>
                    <div class="value" style="color: var(--green);">24</div>
                    <div class="note">CIs whose trusted state remains current and evidence-backed.</div>
                </div>

                <div class="metric">
                    <div class="label">Trust Conditional</div>
                    <div class="value" style="color: var(--yellow);">29</div>
                    <div class="note">CIs with active watchlist conditions or evidence refresh needs.</div>
                </div>

                <div class="metric">
                    <div class="label">Trust Decayed</div>
                    <div class="value" style="color: var(--red);">11</div>
                    <div class="note">CIs where stale evidence, missing ownership, access gaps, or lifecycle gaps weaken trust.</div>
                </div>

                <div class="metric">
                    <div class="label">Refresh Required</div>
                    <div class="value" style="color: var(--orange);">18</div>
                    <div class="note">Records needing evidence, cadence, support, access, or decision refresh.</div>
                </div>

                <div class="metric">
                    <div class="label">Escalate</div>
                    <div class="value" style="color: var(--blue);">6</div>
                    <div class="note">Items requiring owner, support, LCM, MyAccess, or executive escalation.</div>
                </div>
            </section>

            <section class="section">
                <h2>Continuous Trust Answer</h2>
                <p>
                    This monitor answers whether a CI is still trusted today, not only whether it was trusted during onboarding.
                </p>

                <div class="answer">
                    <strong>Current continuous trust interpretation:</strong>
                    CITrust™ should not allow trust to become a one-time onboarding label. A CI must remain continuously defensible through current owner evidence, support routing, LCM accountability, MyAccess mapping, lifecycle evidence, relationship accuracy, cadence reviews, post-change verification, rollback readiness, and decision ledger updates.
                </div>
            </section>

            <section class="section">
                <h2>Continuous Trust Control Domains</h2>
                <p>
                    CITrust™ treats trust as a living governance state that can improve, decay, or become blocked.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Trust Freshness</h3>
                        <p>Confirms evidence, owner, support group, LCM, access route, and lifecycle state are still current.</p>
                    </div>

                    <div class="card">
                        <h3>Trust Drift</h3>
                        <p>Detects when operational reality changes but evidence, decision, relationship, or support data does not update.</p>
                    </div>

                    <div class="card">
                        <h3>Trust Recovery</h3>
                        <p>Tracks remediation, rollback, evidence refresh, post-change checks, and decision updates that restore trust.</p>
                    </div>

                    <div class="card">
                        <h3>Trust Escalation</h3>
                        <p>Escalates decayed trust when owner, access, support, lifecycle, vendor, or evidence gaps become material.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Continuous Trust Matrix</h2>
                <p>
                    This matrix shows whether each CI remains trusted, conditional, decayed, or blocked.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Current Trust State</th>
                            <th>Freshness Signal</th>
                            <th>Drift Signal</th>
                            <th>Post-Change Signal</th>
                            <th>Cadence Signal</th>
                            <th>Trust Decision</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">Trusted</span></td>
                            <td><span class="badge soft-green">Fresh</span></td>
                            <td><span class="badge soft-green">No Drift</span></td>
                            <td><span class="badge soft-green">Verified</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge green">Trust Maintained</span></td>
                            <td>Maintain periodic cadence and evidence review.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td><span class="badge soft-yellow">Cutover Evidence Needed</span></td>
                            <td><span class="badge soft-yellow">Cutover Drift</span></td>
                            <td><span class="badge soft-yellow">Verification Pending</span></td>
                            <td><span class="badge soft-yellow">Due Soon</span></td>
                            <td><span class="badge yellow">Trust Conditional</span></td>
                            <td>Refresh support group, MyAccess role, jump path, vendor handoff, rollback, and post-cutover evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td><span class="badge soft-yellow">Procedure Evidence Needed</span></td>
                            <td><span class="badge soft-yellow">Access Evidence Drift</span></td>
                            <td><span class="badge soft-yellow">Access Check Partial</span></td>
                            <td><span class="badge soft-yellow">Review Due</span></td>
                            <td><span class="badge yellow">Trust Conditional</span></td>
                            <td>Attach current admin/vendor procedure, access review proof, and escalation owner.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td><span class="badge soft-yellow">Evidence Partial</span></td>
                            <td><span class="badge soft-yellow">Support Drift</span></td>
                            <td><span class="badge soft-yellow">Conditional Verification</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge yellow">Trust Conditional</span></td>
                            <td>Reconcile support group, LCM, access path, evidence location, and operational classification.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-yellow">Near Trusted</span></td>
                            <td><span class="badge soft-green">Fresh</span></td>
                            <td><span class="badge soft-yellow">Approver Drift</span></td>
                            <td><span class="badge soft-yellow">Near Verified</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge yellow">Near Trust Maintained</span></td>
                            <td>Confirm MyAccess approver group and role evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">Blocked</span></td>
                            <td><span class="badge soft-red">Closure Missing</span></td>
                            <td><span class="badge soft-red">Lifecycle Drift</span></td>
                            <td><span class="badge soft-red">Verification Failed</span></td>
                            <td><span class="badge soft-red">Overdue</span></td>
                            <td><span class="badge red">Trust Decayed</span></td>
                            <td>Attach closure evidence, confirm access removal, assign closure owner, and update decision ledger.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Unmanaged</span></td>
                            <td><span class="badge soft-red">No Evidence</span></td>
                            <td><span class="badge soft-red">Unmanaged Drift</span></td>
                            <td><span class="badge soft-red">No Verification Model</span></td>
                            <td><span class="badge soft-red">No Cadence</span></td>
                            <td><span class="badge red">No Trust Basis</span></td>
                            <td>Create governed candidate and build owner, support, access, evidence, cadence, and verification model.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Continuous Trust Decision Logic</h2>
                <p>
                    A CI can move from trusted to conditional or blocked if the proof no longer matches reality.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Trust Maintained</h3>
                        <ul>
                            <li>Owner, support group, LCM, and escalation evidence are current.</li>
                            <li>MyAccess, admin, vendor, or jump path evidence is current.</li>
                            <li>Lifecycle state is evidence-backed.</li>
                            <li>Post-change verification is complete where applicable.</li>
                            <li>Evidence drift is absent or remediated.</li>
                            <li>Decision ledger reflects current trust status.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Trust Decayed</h3>
                        <ul>
                            <li>Evidence supports an old owner, support group, or access route.</li>
                            <li>Cadence review is overdue and affects trust.</li>
                            <li>Post-change verification is missing or failed.</li>
                            <li>Lifecycle state is unclear or unsupported.</li>
                            <li>Hidden dependency exists without governed candidate record.</li>
                            <li>Dashboard trust is higher than the evidence can defend.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Continuous Trust Recovery Queue</h2>
                <p>
                    These actions restore trust where evidence, cadence, or operational reality has drifted.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Trust Continuity Gap</th>
                            <th>Why It Matters</th>
                            <th>Recovery Action</th>
                            <th>Expected Trust Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no continuous trust model.</td>
                            <td>Recurring backup review dependency can fail without owner, support, access, evidence, cadence, and verification.</td>
                            <td>Create governed candidate and build continuous trust controls.</td>
                            <td>No Trust Basis → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment trust has decayed due to missing closure evidence.</td>
                            <td>Lifecycle state and access deactivation cannot be defended.</td>
                            <td>Attach closure evidence, confirm access removal, and update decision ledger.</td>
                            <td>Trust Decayed → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover trust remains conditional.</td>
                            <td>Cutover-sensitive CIs need current support, access, vendor, rollback, and post-change evidence.</td>
                            <td>Refresh support group, MyAccess role, jump path, vendor handoff, rollback, and post-cutover verification evidence.</td>
                            <td>Trust Conditional → Trust Reconfirmed</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access evidence has drifted from current admin/vendor route.</td>
                            <td>Privileged access trust decays when procedure and review evidence are stale.</td>
                            <td>Attach current admin/vendor procedure, access review proof, and escalation owner.</td>
                            <td>Trust Conditional → Audit-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, MyAccess, change control, audit systems, validation systems, evidence repositories, or human governance. This continuous trust monitor is a governance assurance overlay for ongoing CI trust validation, evidence freshness, evidence drift, cadence review, support continuity, access continuity, lifecycle continuity, post-change verification, rollback closure, decision ledger update, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_CONTINUOUS_TRUST_MONITOR_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Continuous Trust Monitor installed.")
