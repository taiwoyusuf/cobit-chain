from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_GOVERNANCE_CADENCE_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/governance-cadence")'
ROUTE_ALIAS = '@app.route("/citrust/review-cadence")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Governance Cadence Monitor already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_GOVERNANCE_CADENCE_V1_ACTIVE
# ============================================================

@app.route("/citrust/governance-cadence")
@app.route("/citrust/review-cadence")
def citrust_governance_cadence():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Governance Cadence Monitor</title>
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
                <h1>CITrust™ Governance Cadence Monitor</h1>

                <div class="subtitle">
                    Monitors whether each Configuration Item remains trusted over time through recurring ownership review, support group review, MyAccess access review, backup review, audit trail review, lifecycle review, evidence refresh, relationship review, and CMDB reconciliation cadence.
                </div>

                <div class="positioning">
                    <strong>Cadence boundary:</strong>
                    CITrust™ does not replace ServiceNow tasks, scheduled jobs, MyAccess reviews, quality systems, or human governance. This monitor shows which CI governance evidence is current, stale, overdue, or at risk so trust does not decay after initial onboarding.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                    <a href="/citrust/readiness-attestation">Attestation Center</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                    <a href="/citrust/evidence-lineage">Evidence Lineage</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Cadence Checks</div>
                    <div class="value">54</div>
                    <div class="note">Recurring reviews across owner, support, access, backup, audit trail, lifecycle, and evidence.</div>
                </div>

                <div class="metric">
                    <div class="label">Current Reviews</div>
                    <div class="value" style="color: var(--green);">28</div>
                    <div class="note">Reviews current and not creating trust decay.</div>
                </div>

                <div class="metric">
                    <div class="label">Due Soon</div>
                    <div class="value" style="color: var(--yellow);">13</div>
                    <div class="note">Reviews approaching due date or evidence refresh window.</div>
                </div>

                <div class="metric">
                    <div class="label">Overdue</div>
                    <div class="value" style="color: var(--red);">9</div>
                    <div class="note">Reviews overdue enough to weaken operational trust.</div>
                </div>

                <div class="metric">
                    <div class="label">Stale Evidence</div>
                    <div class="value" style="color: var(--orange);">11</div>
                    <div class="note">Evidence exists but may no longer reflect current operational state.</div>
                </div>

                <div class="metric">
                    <div class="label">Escalate</div>
                    <div class="value" style="color: var(--blue);">4</div>
                    <div class="note">Cadence failures requiring owner, support, access, or lifecycle escalation.</div>
                </div>
            </section>

            <section class="section">
                <h2>Governance Cadence Answer</h2>
                <p>
                    This monitor answers whether CI trust is still current or becoming stale.
                </p>

                <div class="answer">
                    <strong>Current cadence interpretation:</strong>
                    CITrust™ should not treat initial onboarding as permanent trust. A CI can decay from trusted to conditional when ownership review, support group review, MyAccess review, backup review, audit trail review, lifecycle review, or evidence refresh becomes overdue. The highest cadence risks are hidden dependencies, OOS closure evidence, access-path evidence, and cutover-sensitive records.
                </div>
            </section>

            <section class="section">
                <h2>Governance Cadence Library</h2>
                <p>
                    CITrust™ tracks review cadence by control domain and evidence type.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Cadence Type</th>
                            <th>Recommended Frequency</th>
                            <th>Purpose</th>
                            <th>Required Evidence</th>
                            <th>Trust Impact If Missed</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Ownership Review</strong></td>
                            <td><span class="badge blue">Quarterly</span></td>
                            <td>Confirm CI owner, LCM, and support accountability remain current.</td>
                            <td>Owner confirmation, LCM confirmation, support-group review.</td>
                            <td>Ownerless or stale accountability risk.</td>
                        </tr>

                        <tr>
                            <td><strong>Support Group Review</strong></td>
                            <td><span class="badge purple">Quarterly</span></td>
                            <td>Confirm incident and request routing remains valid.</td>
                            <td>Support group confirmation and escalation path.</td>
                            <td>Incident routing and operational support risk.</td>
                        </tr>

                        <tr>
                            <td><strong>MyAccess Review</strong></td>
                            <td><span class="badge orange">Quarterly</span></td>
                            <td>Confirm roles, approvers, requestability, admin paths, and vendor access.</td>
                            <td>Access review evidence, approver group confirmation, role mapping.</td>
                            <td>Access approval and audit defensibility risk.</td>
                        </tr>

                        <tr>
                            <td><strong>Backup Review</strong></td>
                            <td><span class="badge green">Monthly</span></td>
                            <td>Confirm backup review evidence exists for relevant systems or dependencies.</td>
                            <td>Monthly backup review artifact or exception rationale.</td>
                            <td>Operational recovery and audit-readiness risk.</td>
                        </tr>

                        <tr>
                            <td><strong>Audit Trail Review</strong></td>
                            <td><span class="badge yellow">Monthly / Quarterly</span></td>
                            <td>Confirm audit trail review is complete where applicable.</td>
                            <td>Audit trail review evidence and reviewer accountability.</td>
                            <td>Data integrity and audit exposure.</td>
                        </tr>

                        <tr>
                            <td><strong>Lifecycle Review</strong></td>
                            <td><span class="badge blue">Quarterly / Event-Based</span></td>
                            <td>Confirm active, OOS, retired, cutover, or closed state remains valid.</td>
                            <td>Lifecycle evidence, closure evidence, cutover evidence, access removal proof.</td>
                            <td>Lifecycle ambiguity and orphan CI risk.</td>
                        </tr>

                        <tr>
                            <td><strong>CMDB Reconciliation</strong></td>
                            <td><span class="badge purple">Monthly / Cutover-Based</span></td>
                            <td>Compare ServiceNow-style records, master lists, assets, candidates, and evidence.</td>
                            <td>Reconciliation log, conflict resolution decision, decision ledger entry.</td>
                            <td>Duplicate, stale, or weak CMDB data.</td>
                        </tr>

                        <tr>
                            <td><strong>Evidence Refresh</strong></td>
                            <td><span class="badge orange">Event-Based</span></td>
                            <td>Refresh evidence when owner, access, lifecycle, support, or system state changes.</td>
                            <td>Updated evidence reference and readiness decision.</td>
                            <td>Evidence no longer reflects operational reality.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>CI Cadence Readiness Matrix</h2>
                <p>
                    This matrix shows whether each CI is current, due soon, overdue, or stale across recurring governance reviews.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Owner Review</th>
                            <th>Support Review</th>
                            <th>MyAccess Review</th>
                            <th>Backup / Audit Review</th>
                            <th>Lifecycle Review</th>
                            <th>Evidence Freshness</th>
                            <th>Cadence Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-green">Fresh</span></td>
                            <td><span class="badge green">Cadence-Ready</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">Cutover-sensitive BMS dependency</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-yellow">Due Soon</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Cutover Evidence</span></td>
                            <td><span class="badge soft-yellow">Cutover Active</span></td>
                            <td><span class="badge soft-yellow">Needs Refresh</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-yellow">Due Soon</span></td>
                            <td><span class="badge soft-yellow">Procedure Evidence Needed</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-green">Operational</span></td>
                            <td><span class="badge soft-yellow">Needs Refresh</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Confirmed</span></td>
                            <td><span class="badge soft-yellow">Closure Needed</span></td>
                            <td><span class="badge soft-red">Overdue</span></td>
                            <td><span class="badge soft-red">Stale / Missing</span></td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Discovered</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge red">Blocked</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Current</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-green">Fresh</span></td>
                            <td><span class="badge yellow">Conditional</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Cadence Control Domains</h2>
                <p>
                    CITrust™ treats review cadence as part of operational trust.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Trust Freshness</h3>
                        <p>Confirms the CI has not become stale since the last readiness decision, attestation, or submission review.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Currency</h3>
                        <p>Checks whether evidence still reflects the current owner, support group, access route, lifecycle state, and operational use.</p>
                    </div>

                    <div class="card">
                        <h3>Review Accountability</h3>
                        <p>Ensures reviews have an accountable owner instead of becoming informal recurring activities.</p>
                    </div>

                    <div class="card">
                        <h3>Cadence Escalation</h3>
                        <p>Escalates overdue or stale reviews before they become audit findings, access failures, or operational issues.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Cadence Decision Logic</h2>
                <p>
                    A trusted CI can become conditional if its governance cadence is missed.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Cadence-Ready CI</h3>
                        <ul>
                            <li>Owner and support group review are current.</li>
                            <li>MyAccess review is current where applicable.</li>
                            <li>Backup and audit trail review evidence is current where applicable.</li>
                            <li>Lifecycle state has been reviewed or is event-current.</li>
                            <li>Evidence has not become stale or disconnected.</li>
                            <li>Decision ledger and attestation remain defensible.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Cadence-Blocked CI</h3>
                        <ul>
                            <li>Recurring review is overdue and affects audit, access, or support readiness.</li>
                            <li>Evidence is stale or missing.</li>
                            <li>Owner, support group, LCM, or access path has changed without review.</li>
                            <li>OOS or retired state remains unresolved past review window.</li>
                            <li>Hidden dependency supports recurring operational work without governance.</li>
                            <li>Leadership cannot defend the current trust state.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Cadence Remediation Queue</h2>
                <p>
                    These actions prevent CI trust from decaying.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Cadence Gap</th>
                            <th>Why It Matters</th>
                            <th>Required Action</th>
                            <th>Expected Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no governed review cadence.</td>
                            <td>Recurring backup review dependency has no owner, evidence, or CI governance schedule.</td>
                            <td>Create governed candidate and assign backup review cadence owner.</td>
                            <td>Blocked → Cadence-controlled candidate.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment closure review is overdue.</td>
                            <td>Lifecycle trust cannot be defended without closure and access removal evidence.</td>
                            <td>Attach closure evidence, confirm access removal, and close lifecycle review.</td>
                            <td>Blocked → Closed / defensible.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover evidence needs refresh.</td>
                            <td>Cutover records become stale quickly if support, access, jump path, and evidence are not refreshed.</td>
                            <td>Refresh support, MyAccess role, jump path, and cutover evidence.</td>
                            <td>Conditional → Cadence-ready.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access-path review is due for jump server route.</td>
                            <td>Privileged access evidence must remain current for audit defensibility.</td>
                            <td>Review admin/vendor access procedure evidence and support routing.</td>
                            <td>Conditional → Audit-ready.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow scheduled reviews, MyAccess access reviews, quality systems, audit systems, or human governance. This governance cadence monitor is an assurance overlay for recurring CI trust review, ownership review, support group review, MyAccess review, backup review, audit trail review, lifecycle review, evidence refresh, CMDB reconciliation, decision freshness, audit readiness, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_GOVERNANCE_CADENCE_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Governance Cadence Monitor installed.")
