from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_EVIDENCE_DRIFT_MONITOR_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/evidence-drift-monitor")'
ROUTE_ALIAS = '@app.route("/citrust/governance-drift")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Evidence Drift Monitor already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_EVIDENCE_DRIFT_MONITOR_V1_ACTIVE
# ============================================================

@app.route("/citrust/evidence-drift-monitor")
@app.route("/citrust/governance-drift")
def citrust_evidence_drift_monitor():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Evidence Drift Monitor</title>
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
                    radial-gradient(circle at top right, rgba(247,201,72,0.14), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(255,92,112,0.08), transparent 30%),
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
                border: 1px solid rgba(247,201,72,0.38);
                background: rgba(247,201,72,0.10);
                color: #fff4cc;
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
                <h1>CITrust™ Evidence Drift Monitor</h1>

                <div class="subtitle">
                    Detects when Configuration Item evidence no longer matches operational reality after cutover, access changes, support reassignment, lifecycle updates, vendor support, rollback, CMDB-readiness remediation, or periodic review changes.
                </div>

                <div class="positioning">
                    <strong>Evidence drift boundary:</strong>
                    CITrust™ does not update ServiceNow, MyAccess, evidence repositories, or CMDB records in this demo. It identifies drift between what the evidence says and what the CI currently depends on, who owns it, who supports it, how access works, and what lifecycle state is true.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/post-change-verification">Post-Change Verification</a>
                    <a href="/citrust/governance-cadence">Governance Cadence</a>
                    <a href="/citrust/evidence-pack-builder">Evidence Pack</a>
                    <a href="/citrust/source-of-truth-map">Source-of-Truth Map</a>
                    <a href="/citrust/field-conflict-resolution">Conflict Resolution</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Drift Checks</div>
                    <div class="value">44</div>
                    <div class="note">Checks across owner, support, access, lifecycle, evidence, relationships, and cadence.</div>
                </div>

                <div class="metric">
                    <div class="label">No Drift</div>
                    <div class="value" style="color: var(--green);">18</div>
                    <div class="note">Records where evidence still matches current operational reality.</div>
                </div>

                <div class="metric">
                    <div class="label">Minor Drift</div>
                    <div class="value" style="color: var(--yellow);">14</div>
                    <div class="note">Evidence needs refresh, but the CI can remain under controlled review.</div>
                </div>

                <div class="metric">
                    <div class="label">Critical Drift</div>
                    <div class="value" style="color: var(--red);">8</div>
                    <div class="note">Evidence conflicts with ownership, access, support, lifecycle, or dependency reality.</div>
                </div>

                <div class="metric">
                    <div class="label">Stale Evidence</div>
                    <div class="value" style="color: var(--orange);">11</div>
                    <div class="note">Evidence exists but may no longer prove the current CI state.</div>
                </div>

                <div class="metric">
                    <div class="label">Refresh Ready</div>
                    <div class="value" style="color: var(--blue);">12</div>
                    <div class="note">Items that can be corrected by targeted evidence refresh.</div>
                </div>
            </section>

            <section class="section">
                <h2>Evidence Drift Answer</h2>
                <p>
                    This monitor answers whether CI evidence still proves the current trust state.
                </p>

                <div class="answer">
                    <strong>Current drift interpretation:</strong>
                    CITrust™ should not allow old evidence to defend a new operational state. If owner, support group, MyAccess route, vendor path, lifecycle state, dependency relationship, rollback status, or post-change verification has changed, the evidence pack must be refreshed. Otherwise, the CI may appear trusted while the proof no longer matches reality.
                </div>
            </section>

            <section class="section">
                <h2>Evidence Drift Domains</h2>
                <p>
                    CITrust™ separates evidence drift into the operational areas where trust can silently decay.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Ownership Drift</h3>
                        <p>Owner, support group, LCM, backup owner, or escalation path has changed but evidence still reflects the old model.</p>
                    </div>

                    <div class="card">
                        <h3>Access Drift</h3>
                        <p>MyAccess role, approver group, admin path, vendor route, jump path, or access removal evidence is outdated.</p>
                    </div>

                    <div class="card">
                        <h3>Lifecycle Drift</h3>
                        <p>Active, cutover, OOS, retired, or closed state has changed but lifecycle evidence has not been refreshed.</p>
                    </div>

                    <div class="card">
                        <h3>Relationship Drift</h3>
                        <p>Dependencies, hosted-on relationships, accessed-through paths, vendor handoff, or support relationships no longer match evidence.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Evidence Drift Matrix</h2>
                <p>
                    This matrix shows which CI records have evidence drift and what must be refreshed.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Drift Signal</th>
                            <th>Evidence Says</th>
                            <th>Reality / Risk</th>
                            <th>Drift Severity</th>
                            <th>Refresh Action</th>
                            <th>Trust Impact</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">No Material Drift</span></td>
                            <td>Owner, support, access, lifecycle, and evidence are aligned.</td>
                            <td>No material conflict if cadence remains current.</td>
                            <td><span class="badge green">Low</span></td>
                            <td>Maintain periodic evidence review.</td>
                            <td><span class="badge green">Trust Maintained</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge orange">Cutover Drift</span></td>
                            <td>Owner and cutover context are known.</td>
                            <td>Support group, MyAccess role, jump path, vendor handoff, and post-cutover evidence may still be changing.</td>
                            <td><span class="badge orange">High</span></td>
                            <td>Refresh cutover evidence, support routing, access role, jump path, vendor handoff, rollback, and post-change checks.</td>
                            <td><span class="badge yellow">Conditional Trust</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge yellow">Access Evidence Drift</span></td>
                            <td>Access route is known and controlled.</td>
                            <td>Procedure evidence, vendor path, and post-access verification may not be fully linked.</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Attach current admin/vendor procedure, access review proof, and post-change verification evidence.</td>
                            <td><span class="badge yellow">Trust Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge yellow">Support / Evidence Drift</span></td>
                            <td>Operational state is known.</td>
                            <td>Support group, LCM, access route, and evidence path are still being reconciled.</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Refresh support group evidence, LCM evidence, access route, operational classification, and evidence location.</td>
                            <td><span class="badge yellow">Conditional Trust</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge yellow">Access Approver Drift</span></td>
                            <td>Core CI evidence is strong.</td>
                            <td>MyAccess approver group or role evidence needs final confirmation.</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Refresh MyAccess approver group, role mapping, and access escalation evidence.</td>
                            <td><span class="badge yellow">Near Trusted</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge red">Lifecycle Drift</span></td>
                            <td>Legacy record may still exist or be partially known.</td>
                            <td>OOS closure, access removal, lifecycle owner, and closure evidence are not defensible.</td>
                            <td><span class="badge red">Critical</span></td>
                            <td>Attach closure evidence, confirm access removal, assign closure owner, and refresh lifecycle decision evidence.</td>
                            <td><span class="badge red">Trust Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge red">Unmanaged Evidence Drift</span></td>
                            <td>Only operational discovery exists.</td>
                            <td>No governed candidate, owner, support, LCM, access, evidence, cadence, or verification model exists.</td>
                            <td><span class="badge red">Critical</span></td>
                            <td>Create governed candidate and build evidence pack from current operational reality.</td>
                            <td><span class="badge red">No Trust Basis</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Evidence Drift Decision Logic</h2>
                <p>
                    Evidence drift must be treated as trust decay.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>No Material Drift</h3>
                        <ul>
                            <li>Evidence matches current owner, support group, and LCM.</li>
                            <li>Access evidence matches current MyAccess, admin, vendor, or jump route.</li>
                            <li>Lifecycle evidence matches current active, cutover, OOS, retired, or closed state.</li>
                            <li>Relationship evidence matches current dependency reality.</li>
                            <li>Post-change verification evidence is current.</li>
                            <li>Decision ledger reflects the current trust state.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Critical Drift</h3>
                        <ul>
                            <li>Evidence supports an old owner, support group, or lifecycle state.</li>
                            <li>Access route changed but evidence was not refreshed.</li>
                            <li>OOS or retired state lacks closure and access-removal proof.</li>
                            <li>Hidden dependency exists without governed candidate evidence.</li>
                            <li>Cutover state changed but rollback or post-change evidence is missing.</li>
                            <li>Trust score appears green while proof is stale or conflicting.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Evidence Drift Remediation Queue</h2>
                <p>
                    These actions refresh proof so CI trust does not silently decay.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Drift Issue</th>
                            <th>Why It Matters</th>
                            <th>Required Refresh</th>
                            <th>Expected Trust Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no current evidence model.</td>
                            <td>Operational dependency cannot be defended with discovery alone.</td>
                            <td>Create governed candidate and build evidence pack from current owner, support, access, lifecycle, and backup-review reality.</td>
                            <td>No Trust Basis → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment lifecycle evidence does not prove current state.</td>
                            <td>OOS closure and access removal cannot be defended without refreshed evidence.</td>
                            <td>Attach closure evidence, access deactivation proof, lifecycle owner confirmation, and decision ledger update.</td>
                            <td>Trust Blocked → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover evidence may drift during transition.</td>
                            <td>Cutover-sensitive trust can decay quickly if support, access, vendor, rollback, and post-change evidence are not refreshed.</td>
                            <td>Refresh support group, MyAccess role, jump path, vendor handoff, rollback, and post-cutover verification evidence.</td>
                            <td>Conditional Trust → Trust Reconfirmed</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access evidence is outdated after admin/vendor route changes.</td>
                            <td>Privileged access evidence must match the current access route.</td>
                            <td>Attach current admin/vendor procedure, access review proof, and access escalation evidence.</td>
                            <td>Trust Conditional → Audit-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, MyAccess, evidence repositories, audit systems, validation systems, change control, or human governance. This evidence drift monitor is a governance assurance overlay for detecting owner drift, support drift, access drift, lifecycle drift, relationship drift, vendor handoff drift, rollback evidence drift, post-change verification drift, stale evidence, trust decay, audit weakness, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_EVIDENCE_DRIFT_MONITOR_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Evidence Drift Monitor installed.")
