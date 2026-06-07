from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_TRUST_LINEAGE_CONSOLE_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/trust-lineage-console")'
ROUTE_ALIAS = '@app.route("/citrust/ci-trust-lineage")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Trust Lineage Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_TRUST_LINEAGE_CONSOLE_V1_ACTIVE
# ============================================================

@app.route("/citrust/trust-lineage-console")
@app.route("/citrust/ci-trust-lineage")
def citrust_trust_lineage_console():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Trust Lineage Console</title>
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
                    radial-gradient(circle at top right, rgba(180,156,255,0.15), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(49,208,125,0.10), transparent 30%),
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

            .timeline {
                display: grid;
                grid-template-columns: repeat(6, 1fr);
                gap: 12px;
                margin-top: 16px;
            }

            .stage {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 16px;
                min-height: 165px;
            }

            .stage h3 {
                margin: 0 0 8px 0;
                font-size: 16px;
            }

            .stage p {
                margin: 0;
                color: var(--muted);
                font-size: 13px;
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
                .kpis, .cards, .timeline, .two-col {
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
                <h1>CITrust™ Trust Lineage Console</h1>

                <div class="subtitle">
                    Traces the full trust journey of a Configuration Item from candidate discovery to review, evidence pack, remediation, recovery, attestation, passport eligibility, and continuous trust monitoring.
                </div>

                <div class="positioning">
                    <strong>Trust lineage boundary:</strong>
                    ServiceNow remains the system of record. CITrust™ does not create CIs, update CMDB records, approve access, or execute remediation in this demo. It provides the governance lineage that explains how a CI moved from unknown, candidate, conditional, blocked, recovered, attested, or trusted status.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/ci-candidate-factory">Candidate Factory</a>
                    <a href="/ci-candidate-review">Candidate Review</a>
                    <a href="/citrust/evidence-pack-builder">Evidence Pack</a>
                    <a href="/citrust/trust-recovery-board">Trust Recovery</a>
                    <a href="/citrust/recovery-attestation">Recovery Attestation</a>
                    <a href="/citrust/continuous-trust-monitor">Continuous Trust</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Lineage-Tracked CIs</div>
                    <div class="value">42</div>
                    <div class="note">Records with at least one trust-state transition captured.</div>
                </div>

                <div class="metric">
                    <div class="label">Complete Lineage</div>
                    <div class="value" style="color: var(--green);">12</div>
                    <div class="note">CIs with traceable path from intake through trust decision.</div>
                </div>

                <div class="metric">
                    <div class="label">Partial Lineage</div>
                    <div class="value" style="color: var(--yellow);">19</div>
                    <div class="note">CIs with incomplete evidence, decision, recovery, or cadence trace.</div>
                </div>

                <div class="metric">
                    <div class="label">Broken Lineage</div>
                    <div class="value" style="color: var(--red);">7</div>
                    <div class="note">Records where trust status cannot be explained end-to-end.</div>
                </div>

                <div class="metric">
                    <div class="label">Recovered Lineage</div>
                    <div class="value" style="color: var(--blue);">8</div>
                    <div class="note">CIs that moved from decayed or blocked toward restored trust.</div>
                </div>

                <div class="metric">
                    <div class="label">Passport Eligible</div>
                    <div class="value" style="color: var(--purple);">5</div>
                    <div class="note">Records with lineage strong enough for passport-style assurance.</div>
                </div>
            </section>

            <section class="section">
                <h2>Trust Lineage Answer</h2>
                <p>
                    This console answers how a CI reached its current trust state and whether that journey is defensible.
                </p>

                <div class="answer">
                    <strong>Current lineage interpretation:</strong>
                    A CI trust decision is weak if leadership cannot explain how the record moved from discovery to review, evidence, remediation, recovery, attestation, and continuous monitoring. CITrust™ should preserve this lineage so every trusted, conditional, blocked, recovered, or passport-eligible CI has a defensible history.
                </div>
            </section>

            <section class="section">
                <h2>CITrust™ Trust Lineage Stages</h2>
                <p>
                    These stages describe the governed journey from raw CI discovery to continuous trust.
                </p>

                <div class="timeline">
                    <div class="stage">
                        <h3><span class="badge blue">1</span><br>Candidate Discovery</h3>
                        <p>CI emerges from Planner, Excel, Blue Mountain, asset list, ServiceNow-style record, operational dependency, or orphan detection.</p>
                    </div>

                    <div class="stage">
                        <h3><span class="badge yellow">2</span><br>Candidate Review</h3>
                        <p>Owner, support group, LCM, lifecycle state, classification, access route, and submission readiness are reviewed.</p>
                    </div>

                    <div class="stage">
                        <h3><span class="badge purple">3</span><br>Evidence Pack</h3>
                        <p>Required proof is assembled across identity, owner, support, access, lifecycle, relationship, operational, and decision evidence.</p>
                    </div>

                    <div class="stage">
                        <h3><span class="badge orange">4</span><br>Remediation / Recovery</h3>
                        <p>Gaps are closed through evidence refresh, owner confirmation, support routing, access confirmation, lifecycle closure, or recovery action.</p>
                    </div>

                    <div class="stage">
                        <h3><span class="badge green">5</span><br>Attestation / Passport</h3>
                        <p>Reviewer confirms the trust claim, residual risk, recovery evidence, and readiness decision are defensible.</p>
                    </div>

                    <div class="stage">
                        <h3><span class="badge blue">6</span><br>Continuous Trust</h3>
                        <p>Cadence, drift, post-change verification, rollback, and trust-decay forecasting keep the CI trusted over time.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Trust Lineage Matrix</h2>
                <p>
                    This matrix shows whether each CI has a complete, partial, broken, or recovered trust lineage.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Origin</th>
                            <th>Current Trust State</th>
                            <th>Lineage Strength</th>
                            <th>Missing Link</th>
                            <th>Lineage Decision</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>Known application / asset governance source.</td>
                            <td><span class="badge soft-green">Trusted</span></td>
                            <td>Owner, support, access, lifecycle, evidence, cadence, and decision trace are strong.</td>
                            <td>No material missing link.</td>
                            <td><span class="badge green">Complete Lineage</span></td>
                            <td>Maintain cadence and evidence refresh.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td>Cutover-sensitive infrastructure/application dependency.</td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td>Owner and cutover context exist; evidence chain still developing.</td>
                            <td>Support group, MyAccess role, jump path, vendor handoff, rollback, and post-cutover evidence.</td>
                            <td><span class="badge yellow">Partial Lineage</span></td>
                            <td>Close cutover evidence chain and update decision ledger.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Infrastructure access control dependency.</td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td>Access route is known; evidence chain needs procedure support.</td>
                            <td>Admin/vendor procedure, access review proof, post-access verification, escalation owner.</td>
                            <td><span class="badge yellow">Partial Lineage</span></td>
                            <td>Attach access procedure evidence and update access decision trace.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Operational equipment record.</td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td>Operational state is known; trust lineage is incomplete.</td>
                            <td>Support group, LCM, access route, evidence location, and operational classification reconciliation.</td>
                            <td><span class="badge yellow">Partial Lineage</span></td>
                            <td>Reconcile support, lifecycle, access, evidence, and classification lineage.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>Known lab application dependency.</td>
                            <td><span class="badge soft-blue">Near Trusted</span></td>
                            <td>Strong lineage with one access confirmation gap.</td>
                            <td>MyAccess approver group and role evidence.</td>
                            <td><span class="badge blue">Passport Eligible After Check</span></td>
                            <td>Confirm MyAccess approver group and role mapping evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>Legacy / OOS equipment record.</td>
                            <td><span class="badge soft-red">Blocked</span></td>
                            <td>Lineage breaks at lifecycle closure and access removal.</td>
                            <td>Closure evidence, access deactivation proof, closure owner, lifecycle decision, decision ledger update.</td>
                            <td><span class="badge red">Broken Lineage</span></td>
                            <td>Attach closure evidence, confirm access removal, and rebuild lifecycle lineage.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>Discovered hidden operational dependency.</td>
                            <td><span class="badge soft-red">Unmanaged</span></td>
                            <td>No governed lineage exists yet.</td>
                            <td>Candidate record, owner, support group, LCM, access path, backup evidence, cadence, escalation, verification.</td>
                            <td><span class="badge red">No Trust Lineage</span></td>
                            <td>Create governed candidate and start trust lineage from discovery stage.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Trust Lineage Decision Logic</h2>
                <p>
                    A CI’s trust status must be explainable through the full governance trail.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Complete Trust Lineage</h3>
                        <ul>
                            <li>Origin and source authority are known.</li>
                            <li>Candidate review decision is traceable.</li>
                            <li>Evidence pack supports the trust claim.</li>
                            <li>Remediation or recovery actions are linked where needed.</li>
                            <li>Attestation or passport decision is evidence-backed.</li>
                            <li>Continuous trust monitoring keeps lineage current.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Broken Trust Lineage</h3>
                        <ul>
                            <li>CI origin is unclear or only tribal knowledge exists.</li>
                            <li>Candidate review decision is missing.</li>
                            <li>Evidence pack does not support the current trust state.</li>
                            <li>Recovery action was performed without proof.</li>
                            <li>Attestation was attempted without reviewer accountability.</li>
                            <li>Continuous trust state cannot be explained.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Lineage Repair Queue</h2>
                <p>
                    These actions repair broken or partial trust lineage before a CI can be treated as fully trusted.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Lineage Gap</th>
                            <th>Why It Matters</th>
                            <th>Repair Action</th>
                            <th>Expected Lineage Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no trust lineage.</td>
                            <td>Operational dependency cannot be defended without a governed origin and evidence trail.</td>
                            <td>Create governed candidate and build owner, support, LCM, access, backup evidence, cadence, escalation, and verification lineage.</td>
                            <td>No Trust Lineage → Candidate Lineage Started</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment lifecycle lineage is broken.</td>
                            <td>Lifecycle closure cannot be defended without closure and access-removal evidence.</td>
                            <td>Attach closure evidence, confirm access deactivation, assign closure owner, and update decision ledger.</td>
                            <td>Broken Lineage → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover lineage is partial.</td>
                            <td>Cutover-sensitive CI needs support, access, vendor, rollback, and post-change evidence trail.</td>
                            <td>Complete support group, MyAccess role, jump path, vendor handoff, rollback, and post-cutover verification lineage.</td>
                            <td>Partial Lineage → Trust Reconfirmed</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access lineage lacks procedure evidence.</td>
                            <td>Privileged access trust cannot be defended without current procedure and review evidence.</td>
                            <td>Attach admin/vendor procedure, access review proof, and post-access verification evidence.</td>
                            <td>Partial Lineage → Audit-Ready Lineage</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, MyAccess, CMDB governance, audit systems, validation systems, evidence repositories, change control, or human governance. This trust lineage console is a governance assurance overlay for tracing CI origin, candidate review, evidence pack, remediation, recovery, attestation, passport eligibility, continuous trust, evidence drift, decision history, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_TRUST_LINEAGE_CONSOLE_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Trust Lineage Console installed.")
