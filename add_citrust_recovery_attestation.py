from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_RECOVERY_ATTESTATION_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/recovery-attestation")'
ROUTE_ALIAS = '@app.route("/citrust/trust-restoration-attestation")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Recovery Attestation Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_RECOVERY_ATTESTATION_V1_ACTIVE
# ============================================================

@app.route("/citrust/recovery-attestation")
@app.route("/citrust/trust-restoration-attestation")
def citrust_recovery_attestation():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Recovery Attestation Console</title>
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
                    radial-gradient(circle at top right, rgba(49,208,125,0.15), transparent 28%),
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
                <h1>CITrust™ Recovery Attestation Console</h1>

                <div class="subtitle">
                    Provides the formal evidence-backed sign-off layer after trust recovery, confirming whether a Configuration Item can be declared restored, conditionally restored, still blocked, or not defensible.
                </div>

                <div class="positioning">
                    <strong>Attestation boundary:</strong>
                    CITrust™ does not approve access, update ServiceNow, close change records, or replace human governance. This console verifies whether recovery evidence is complete enough for an accountable reviewer to attest that CI trust has been restored.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/trust-recovery-board">Trust Recovery Board</a>
                    <a href="/citrust/trust-decay-forecast">Trust Decay Forecast</a>
                    <a href="/citrust/continuous-trust-monitor">Continuous Trust</a>
                    <a href="/citrust/evidence-pack-builder">Evidence Pack</a>
                    <a href="/citrust/readiness-attestation">Readiness Attestation</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Recovery Attestations</div>
                    <div class="value">21</div>
                    <div class="note">Recovered or recovering CIs requiring attestation review.</div>
                </div>

                <div class="metric">
                    <div class="label">Restored</div>
                    <div class="value" style="color: var(--green);">7</div>
                    <div class="note">CIs with complete evidence and defensible recovery closure.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditionally Restored</div>
                    <div class="value" style="color: var(--yellow);">8</div>
                    <div class="note">CIs recovered enough for controlled use but still requiring closure action.</div>
                </div>

                <div class="metric">
                    <div class="label">Blocked Attestation</div>
                    <div class="value" style="color: var(--red);">4</div>
                    <div class="note">CIs that cannot be attested because required evidence is missing.</div>
                </div>

                <div class="metric">
                    <div class="label">Reviewer Action Needed</div>
                    <div class="value" style="color: var(--orange);">6</div>
                    <div class="note">CIs requiring owner, support, access, lifecycle, or governance reviewer sign-off.</div>
                </div>

                <div class="metric">
                    <div class="label">Passport Eligible</div>
                    <div class="value" style="color: var(--blue);">5</div>
                    <div class="note">Recovered CIs strong enough for CITrust™ Passport review.</div>
                </div>
            </section>

            <section class="section">
                <h2>Recovery Attestation Answer</h2>
                <p>
                    This console answers whether the organization can formally say a recovered CI is trusted again.
                </p>

                <div class="answer">
                    <strong>Current attestation interpretation:</strong>
                    A CI should not be declared recovered simply because remediation work was performed. Recovery attestation requires evidence that the original trust-decay cause was closed, the accountable owner accepted the recovery state, the decision ledger was updated, and post-recovery verification confirms the CI can be operationally trusted again.
                </div>
            </section>

            <section class="section">
                <h2>Recovery Attestation Domains</h2>
                <p>
                    CITrust™ separates recovery sign-off into the domains required for defensible trust restoration.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Recovery Evidence</h3>
                        <p>Proof that the missing owner, support, access, lifecycle, evidence, rollback, or post-change control has been closed.</p>
                    </div>

                    <div class="card">
                        <h3>Reviewer Accountability</h3>
                        <p>Named owner, support, LCM, access, governance, or executive reviewer who accepts the restored trust state.</p>
                    </div>

                    <div class="card">
                        <h3>Decision Integrity</h3>
                        <p>Decision ledger records the recovery rationale, closure condition, residual risk, and final trust decision.</p>
                    </div>

                    <div class="card">
                        <h3>Post-Recovery Control</h3>
                        <p>Cadence review, evidence drift monitoring, and continuous trust logic remain active after restoration.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Recovery Attestation Matrix</h2>
                <p>
                    This matrix shows whether recovered CIs can be formally attested.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Recovery Claim</th>
                            <th>Evidence Status</th>
                            <th>Required Reviewer</th>
                            <th>Residual Risk</th>
                            <th>Attestation Decision</th>
                            <th>Next Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>Trust remains current; no recovery required.</td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td>CI Owner / Application Governance</td>
                            <td>Low if cadence remains current.</td>
                            <td><span class="badge green">Attested Trusted</span></td>
                            <td>Maintain periodic review and evidence refresh.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td>Cutover trust can be restored after support, access, jump path, vendor, rollback, and post-cutover evidence close.</td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td>Infrastructure / Cutover Owner / Access Governance</td>
                            <td>Cutover evidence and access route remain residual risks.</td>
                            <td><span class="badge yellow">Conditional Attestation</span></td>
                            <td>Complete support, MyAccess, jump path, vendor handoff, rollback, and post-change evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Access trust can be restored after procedure and access review evidence are attached.</td>
                            <td><span class="badge soft-yellow">Procedure Needed</span></td>
                            <td>Infrastructure / Access Governance</td>
                            <td>Admin or vendor access evidence still partial.</td>
                            <td><span class="badge yellow">Conditional Attestation</span></td>
                            <td>Attach current admin/vendor procedure, access review proof, and escalation owner.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Support and evidence trust can be restored after reconciliation.</td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td>Operational Owner / CMDB Governance</td>
                            <td>Support group, LCM, access route, and evidence path require confirmation.</td>
                            <td><span class="badge yellow">Reviewer Action Needed</span></td>
                            <td>Confirm support group, LCM, access path, evidence location, and operational classification.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>Near-ready recovery; only access approver evidence requires final confirmation.</td>
                            <td><span class="badge soft-green">Near Complete</span></td>
                            <td>Application Governance / MyAccess Governance</td>
                            <td>Low once approver group and role evidence are confirmed.</td>
                            <td><span class="badge blue">Passport Eligible After Check</span></td>
                            <td>Confirm MyAccess approver group and role mapping evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>Lifecycle trust cannot be restored until closure and access removal are proven.</td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td>Lifecycle Governance / Access Governance</td>
                            <td>High: OOS closure and access removal are not defensible.</td>
                            <td><span class="badge red">Attestation Blocked</span></td>
                            <td>Attach closure evidence, confirm access removal, assign closure owner, and update decision ledger.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>No recovery attestation possible until a governed candidate exists.</td>
                            <td><span class="badge soft-red">No Evidence Pack</span></td>
                            <td>CMDB Governance / Infrastructure</td>
                            <td>Critical: hidden dependency has no governed trust basis.</td>
                            <td><span class="badge red">Not Attestable</span></td>
                            <td>Create governed candidate and build evidence, cadence, escalation, and verification model.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Recovery Attestation Decision Logic</h2>
                <p>
                    Attestation must prove recovery, not just acknowledge remediation activity.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Recovery Can Be Attested</h3>
                        <ul>
                            <li>Original trust-decay cause is identified and closed.</li>
                            <li>Recovery evidence is attached and reviewable.</li>
                            <li>Owner, support, LCM, access, or lifecycle reviewer accepts closure.</li>
                            <li>Residual risk is documented and controlled.</li>
                            <li>Post-recovery verification is complete.</li>
                            <li>Decision ledger reflects the restored trust state.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Attestation Must Be Blocked</h3>
                        <ul>
                            <li>Recovery evidence is missing or stale.</li>
                            <li>No accountable reviewer can accept the restored state.</li>
                            <li>Access removal or access route cannot be defended.</li>
                            <li>OOS closure lacks evidence.</li>
                            <li>Hidden dependency has no governed candidate record.</li>
                            <li>Status is changed without proof that trust was restored.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Attestation Closure Queue</h2>
                <p>
                    These actions must close before recovery can be formally attested.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Attestation Gap</th>
                            <th>Why It Matters</th>
                            <th>Closure Evidence</th>
                            <th>Expected Attestation Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation cannot be attested.</td>
                            <td>No recovery or trust statement is defensible without a governed CI candidate.</td>
                            <td>Candidate record, owner, support group, LCM, access path, backup evidence, cadence, escalation.</td>
                            <td>Not Attestable → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment recovery lacks closure and access-removal evidence.</td>
                            <td>Lifecycle trust cannot be restored without closure proof.</td>
                            <td>Closure evidence, access deactivation proof, closure owner, lifecycle decision, decision ledger update.</td>
                            <td>Attestation Blocked → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover recovery is conditional.</td>
                            <td>Recovered cutover trust requires support, access, vendor, rollback, and post-change evidence.</td>
                            <td>Support group, MyAccess role, jump path evidence, vendor handoff evidence, rollback evidence, post-cutover checks.</td>
                            <td>Conditional Attestation → Trust Restored</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Privileged access recovery lacks final evidence.</td>
                            <td>Admin/vendor access trust cannot be attested without procedure and review proof.</td>
                            <td>Admin/vendor procedure, access review proof, escalation owner, post-access verification.</td>
                            <td>Conditional Attestation → Audit-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, MyAccess, change control, audit systems, validation systems, quality systems, access approvals, or human governance. This recovery attestation console is a governance assurance overlay for formally confirming restored CI trust, evidence-backed recovery, reviewer accountability, residual risk closure, post-recovery verification, decision ledger integrity, passport eligibility, audit defense, and continuous trust preservation.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_RECOVERY_ATTESTATION_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Recovery Attestation Console installed.")
