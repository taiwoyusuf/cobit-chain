from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_TRUST_DECAY_FORECAST_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/trust-decay-forecast")'
ROUTE_ALIAS = '@app.route("/citrust/ci-trust-forecast")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Trust Decay Forecast already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_TRUST_DECAY_FORECAST_V1_ACTIVE
# ============================================================

@app.route("/citrust/trust-decay-forecast")
@app.route("/citrust/ci-trust-forecast")
def citrust_trust_decay_forecast():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Trust Decay Forecast</title>
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
                    radial-gradient(circle at top right, rgba(255,92,112,0.14), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(247,201,72,0.10), transparent 30%),
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
                <h1>CITrust™ Trust Decay Forecast</h1>

                <div class="subtitle">
                    Forecasts which Configuration Items are most likely to lose operational trust next because of stale evidence, overdue governance cadence, unresolved MyAccess mapping, support-routing gaps, lifecycle ambiguity, failed verification, vendor handoff exposure, rollback weakness, or hidden dependency risk.
                </div>

                <div class="positioning">
                    <strong>Forecast boundary:</strong>
                    CITrust™ does not predict production incidents, approve changes, update ServiceNow, or replace human governance. This forecast identifies early trust-decay patterns so governance teams can refresh evidence, close ownership gaps, confirm access, and prevent weak CIs from becoming audit or operational issues.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/continuous-trust-monitor">Continuous Trust</a>
                    <a href="/citrust/evidence-drift-monitor">Evidence Drift</a>
                    <a href="/citrust/governance-cadence">Governance Cadence</a>
                    <a href="/citrust/pre-deviation-readiness">Pre-Deviation</a>
                    <a href="/citrust/post-change-verification">Post-Change Verification</a>
                    <a href="/citrust/governance-debt-register">Governance Debt</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Forecasted CIs</div>
                    <div class="value">42</div>
                    <div class="note">Records evaluated for near-term trust decay risk.</div>
                </div>

                <div class="metric">
                    <div class="label">Low Decay Risk</div>
                    <div class="value" style="color: var(--green);">14</div>
                    <div class="note">Evidence, cadence, ownership, access, and lifecycle remain stable.</div>
                </div>

                <div class="metric">
                    <div class="label">Medium Decay Risk</div>
                    <div class="value" style="color: var(--yellow);">17</div>
                    <div class="note">Records likely to become conditional if evidence is not refreshed.</div>
                </div>

                <div class="metric">
                    <div class="label">High Decay Risk</div>
                    <div class="value" style="color: var(--orange);">7</div>
                    <div class="note">CIs approaching trust loss due to drift, overdue reviews, or unresolved controls.</div>
                </div>

                <div class="metric">
                    <div class="label">Critical Decay Risk</div>
                    <div class="value" style="color: var(--red);">4</div>
                    <div class="note">CIs likely to become blocked without immediate governance action.</div>
                </div>

                <div class="metric">
                    <div class="label">Preventable</div>
                    <div class="value" style="color: var(--blue);">19</div>
                    <div class="note">Records where targeted action can preserve trust before decay.</div>
                </div>
            </section>

            <section class="section">
                <h2>Trust Decay Forecast Answer</h2>
                <p>
                    This forecast answers which CIs are most likely to lose trust before the next governance review.
                </p>

                <div class="answer">
                    <strong>Current forecast interpretation:</strong>
                    CI trust usually decays before it fails. The strongest predictors are stale evidence, overdue cadence, unresolved support group, incomplete MyAccess route, lifecycle ambiguity, missing post-change verification, vendor handoff without procedure evidence, weak rollback model, and hidden dependencies. CITrust™ should surface these early so teams can prevent trust loss before audit, cutover, access, or support failure.
                </div>
            </section>

            <section class="section">
                <h2>Trust Decay Predictor Domains</h2>
                <p>
                    CITrust™ forecasts trust decay by watching the controls most likely to become stale or unresolved.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Evidence Aging</h3>
                        <p>Evidence is old, incomplete, disconnected, or no longer aligned to current owner, access, support, or lifecycle state.</p>
                    </div>

                    <div class="card">
                        <h3>Cadence Pressure</h3>
                        <p>Ownership review, access review, support review, backup review, audit trail review, or lifecycle review is due or overdue.</p>
                    </div>

                    <div class="card">
                        <h3>Change Volatility</h3>
                        <p>Recent or planned change, cutover, vendor support, access update, rollback, or lifecycle action increases trust movement.</p>
                    </div>

                    <div class="card">
                        <h3>Control Fragility</h3>
                        <p>Trust depends on a weak owner, partial support group, unclear LCM, hidden dependency, unresolved exception, or conditional evidence.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Trust Decay Forecast Matrix</h2>
                <p>
                    This matrix identifies likely trust decay before the CI becomes blocked, stale, or audit-weak.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Current State</th>
                            <th>Decay Predictor</th>
                            <th>Forecast Window</th>
                            <th>Decay Risk</th>
                            <th>Likely Outcome If Ignored</th>
                            <th>Prevention Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">Trusted</span></td>
                            <td>No material drift; cadence must remain current.</td>
                            <td>Next periodic review</td>
                            <td><span class="badge green">Low</span></td>
                            <td>Trust maintained if review cadence remains current.</td>
                            <td>Maintain evidence refresh and periodic governance cadence.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td>Cutover evidence, support group, MyAccess role, jump path, vendor handoff, rollback, and post-change verification are not fully closed.</td>
                            <td>Immediate cutover window</td>
                            <td><span class="badge orange">High</span></td>
                            <td>Trust may decay into blocked cutover readiness or support-routing exposure.</td>
                            <td>Refresh cutover evidence, support group, MyAccess role, jump path, vendor handoff, rollback, and post-change checks.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td>Admin/vendor procedure evidence and access review evidence remain partial.</td>
                            <td>Next privileged access review</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Access readiness may become audit-weak or exception-driven.</td>
                            <td>Attach current admin/vendor procedure, access review proof, and escalation owner.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td>Support group, LCM, evidence path, access route, and operational classification remain partial.</td>
                            <td>Next support / lifecycle review</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Trust may decay into support-routing or evidence-readiness gap.</td>
                            <td>Reconcile support group, LCM, access path, evidence location, and operational classification.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-yellow">Near Trusted</span></td>
                            <td>MyAccess approver group and role evidence need final confirmation.</td>
                            <td>Next access review</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Access-readiness may remain conditional instead of becoming fully trusted.</td>
                            <td>Confirm MyAccess approver group, role mapping, and access escalation evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">Blocked</span></td>
                            <td>Closure evidence, access deactivation proof, lifecycle owner, and decision ledger update are missing.</td>
                            <td>Immediate</td>
                            <td><span class="badge red">Critical</span></td>
                            <td>Blocked state may become audit finding, orphan exposure, or lifecycle ambiguity.</td>
                            <td>Attach closure evidence, confirm access removal, assign closure owner, and update decision ledger.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Unmanaged</span></td>
                            <td>No governed candidate, owner, support, LCM, access, evidence, cadence, or verification model exists.</td>
                            <td>Immediate</td>
                            <td><span class="badge red">Critical</span></td>
                            <td>Trust cannot be established; recurring backup review dependency remains hidden.</td>
                            <td>Create governed candidate and build owner, support, access, evidence, cadence, verification, and escalation model.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Trust Decay Decision Logic</h2>
                <p>
                    Forecasting trust decay helps leadership act before the dashboard turns red.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Low Decay Risk</h3>
                        <ul>
                            <li>Evidence is current and aligned to operational reality.</li>
                            <li>Owner, support group, LCM, and escalation are stable.</li>
                            <li>MyAccess, admin, vendor, or jump path evidence is current.</li>
                            <li>Lifecycle state is evidence-backed.</li>
                            <li>Cadence reviews are current.</li>
                            <li>No unresolved critical exception or hidden dependency exists.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Critical Decay Risk</h3>
                        <ul>
                            <li>Evidence is missing or stale for a critical CI domain.</li>
                            <li>Owner, support group, LCM, or access route is unresolved.</li>
                            <li>OOS or retired state lacks closure proof.</li>
                            <li>Hidden dependency supports recurring operational work.</li>
                            <li>Post-change verification or rollback evidence is missing.</li>
                            <li>Trust state depends on an undocumented assumption.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Trust Decay Prevention Queue</h2>
                <p>
                    These actions prevent conditional or decaying CIs from becoming blocked.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Forecasted Decay</th>
                            <th>Why It Matters</th>
                            <th>Prevention Action</th>
                            <th>Expected Trust Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no trust model.</td>
                            <td>No trust can be preserved because the CI-like dependency is not governed.</td>
                            <td>Create governed candidate and build owner, support, access, evidence, cadence, rollback, and verification model.</td>
                            <td>No Trust Basis → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment remains blocked and may become audit exposure.</td>
                            <td>Lifecycle trust cannot be recovered without closure and access-removal proof.</td>
                            <td>Attach closure evidence, confirm access deactivation, assign closure owner, and update decision ledger.</td>
                            <td>Critical Decay → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover trust may decay during transition.</td>
                            <td>Cutover-sensitive CI needs current support, access, vendor, rollback, and verification evidence.</td>
                            <td>Refresh support group, MyAccess role, jump path, vendor handoff, rollback, and post-cutover evidence.</td>
                            <td>High Decay Risk → Trust Reconfirmed</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access readiness may decay due to stale admin/vendor evidence.</td>
                            <td>Privileged access trust weakens when procedure, review, and escalation evidence are not current.</td>
                            <td>Attach admin/vendor procedure, access review proof, and access escalation owner.</td>
                            <td>Medium Decay Risk → Audit-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, MyAccess, CMDB governance, audit systems, change control, validation systems, evidence repositories, or human governance. This trust decay forecast is a governance assurance overlay for forecasting evidence decay, cadence decay, ownership decay, support decay, access decay, lifecycle decay, relationship decay, vendor handoff decay, rollback weakness, post-change verification gaps, audit weakness, operational trust loss, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_TRUST_DECAY_FORECAST_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Trust Decay Forecast installed.")
