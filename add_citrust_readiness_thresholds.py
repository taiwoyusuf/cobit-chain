from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_READINESS_THRESHOLDS_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/readiness-thresholds")'
ROUTE_ALIAS = '@app.route("/citrust/threshold-policy")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Readiness Threshold Policy already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_READINESS_THRESHOLDS_V1_ACTIVE
# ============================================================

@app.route("/citrust/readiness-thresholds")
@app.route("/citrust/threshold-policy")
def citrust_readiness_thresholds():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Readiness Threshold Policy</title>
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
                <h1>CITrust™ Readiness Threshold Policy</h1>

                <div class="subtitle">
                    Defines the red, yellow, green, and blocked threshold rules used across CITrust™ dashboards, trust scoring, KPI catalog, governance debt, cadence, risk heatmap, remediation board, decision ledger, and ServiceNow-readiness views.
                </div>

                <div class="positioning">
                    <strong>Threshold boundary:</strong>
                    CITrust™ thresholds are governance assurance rules. They do not replace ServiceNow configuration, do not update CMDB records, and do not approve changes. They standardize how readiness status is interpreted so leadership can defend why a CI is trusted, conditional, blocked, or submission-ready.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/kpi-catalog">KPI Catalog</a>
                    <a href="/citrust/trust-score-model">Trust Score Model</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                    <a href="/citrust/governance-debt-register">Governance Debt</a>
                    <a href="/citrust/governance-cadence">Governance Cadence</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Threshold Families</div>
                    <div class="value">9</div>
                    <div class="note">Trust, owner, support, access, evidence, lifecycle, relationship, cadence, and debt.</div>
                </div>

                <div class="metric">
                    <div class="label">Green Rules</div>
                    <div class="value" style="color: var(--green);">18</div>
                    <div class="note">Conditions that allow trusted, attested, or submission-ready status.</div>
                </div>

                <div class="metric">
                    <div class="label">Yellow Rules</div>
                    <div class="value" style="color: var(--yellow);">16</div>
                    <div class="note">Conditions that require remediation, confirmation, or exception tracking.</div>
                </div>

                <div class="metric">
                    <div class="label">Red Rules</div>
                    <div class="value" style="color: var(--red);">11</div>
                    <div class="note">Conditions that block trust, attestation, audit-readiness, or submission.</div>
                </div>

                <div class="metric">
                    <div class="label">Escalation Rules</div>
                    <div class="value" style="color: var(--orange);">7</div>
                    <div class="note">Conditions requiring leadership, owner, support, access, or lifecycle escalation.</div>
                </div>

                <div class="metric">
                    <div class="label">Override Rules</div>
                    <div class="value" style="color: var(--blue);">5</div>
                    <div class="note">Rules for evidence-backed override, exception, or temporary conditional status.</div>
                </div>
            </section>

            <section class="section">
                <h2>Threshold Policy Answer</h2>
                <p>
                    This policy answers when a CI should be green, yellow, red, blocked, or escalated.
                </p>

                <div class="answer">
                    <strong>Current threshold interpretation:</strong>
                    CITrust™ should not allow subjective dashboard colors. A CI is green only when core governance controls are complete and evidence-backed. A CI is yellow when it is usable only under controlled remediation or exception. A CI is red when critical owner, support, LCM, MyAccess, lifecycle, evidence, relationship, or data-quality controls are missing.
                </div>
            </section>

            <section class="section">
                <h2>Core Readiness Threshold Rules</h2>
                <p>
                    These rules standardize how CITrust™ converts governance evidence into readiness status.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Readiness Domain</th>
                            <th>Green Threshold</th>
                            <th>Yellow Threshold</th>
                            <th>Red / Blocked Threshold</th>
                            <th>Governance Impact</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>CI Trust Score</strong></td>
                            <td><span class="badge green">85–100</span> Evidence-backed and operationally defensible.</td>
                            <td><span class="badge yellow">60–84</span> Conditional with named remediation.</td>
                            <td><span class="badge red">0–59</span> Critical gaps block trust.</td>
                            <td>Determines trusted, conditional, or blocked executive posture.</td>
                        </tr>

                        <tr>
                            <td><strong>Owner Coverage</strong></td>
                            <td><span class="badge green">Owner confirmed</span> and current.</td>
                            <td><span class="badge yellow">Owner likely</span> but pending confirmation.</td>
                            <td><span class="badge red">Owner missing</span> or disputed.</td>
                            <td>Blocks attestation and audit-readiness if missing.</td>
                        </tr>

                        <tr>
                            <td><strong>Support Group</strong></td>
                            <td><span class="badge green">Routable support group</span> confirmed.</td>
                            <td><span class="badge yellow">Support group pending</span> or partial.</td>
                            <td><span class="badge red">No support group</span> or escalation path.</td>
                            <td>Blocks incident-readiness and operational reliance.</td>
                        </tr>

                        <tr>
                            <td><strong>LCM / Lifecycle Owner</strong></td>
                            <td><span class="badge green">LCM assigned</span> and lifecycle state clear.</td>
                            <td><span class="badge yellow">LCM pending</span> or inherited but not attested.</td>
                            <td><span class="badge red">LCM missing</span> for active, OOS, retired, or cutover CI.</td>
                            <td>Blocks lifecycle readiness and closure defensibility.</td>
                        </tr>

                        <tr>
                            <td><strong>MyAccess Mapping</strong></td>
                            <td><span class="badge green">Roles and approvers mapped</span> with evidence.</td>
                            <td><span class="badge yellow">Role or approver partial</span> but known.</td>
                            <td><span class="badge red">Access route unknown</span> or not defensible.</td>
                            <td>Blocks access-readiness and audit defense.</td>
                        </tr>

                        <tr>
                            <td><strong>Evidence Lineage</strong></td>
                            <td><span class="badge green">Evidence linked</span> and reviewable.</td>
                            <td><span class="badge yellow">Evidence partial</span> or needs refresh.</td>
                            <td><span class="badge red">Evidence missing</span> for required domain.</td>
                            <td>Blocks audit-readiness and trust scoring.</td>
                        </tr>

                        <tr>
                            <td><strong>Lifecycle State</strong></td>
                            <td><span class="badge green">Active, OOS, retired, or closed state</span> evidence-backed.</td>
                            <td><span class="badge yellow">State known</span> but evidence incomplete.</td>
                            <td><span class="badge red">State conflicting</span> or unsupported.</td>
                            <td>Blocks OOS closure, retirement, and cutover readiness.</td>
                        </tr>

                        <tr>
                            <td><strong>Relationship Readiness</strong></td>
                            <td><span class="badge green">Owned by, supported by, depends on, accessed through</span> mapped.</td>
                            <td><span class="badge yellow">Relationship partial</span> but known.</td>
                            <td><span class="badge red">Hidden or missing relationship</span>.</td>
                            <td>Blocks change impact and dependency lineage.</td>
                        </tr>

                        <tr>
                            <td><strong>Governance Cadence</strong></td>
                            <td><span class="badge green">Reviews current</span> and evidence fresh.</td>
                            <td><span class="badge yellow">Due soon</span> or evidence aging.</td>
                            <td><span class="badge red">Overdue</span> or stale evidence affects trust.</td>
                            <td>Can downgrade trusted CI to conditional or blocked.</td>
                        </tr>

                        <tr>
                            <td><strong>Governance Debt</strong></td>
                            <td><span class="badge green">No critical debt</span> or debt actively controlled.</td>
                            <td><span class="badge yellow">Open debt</span> with named remediation owner.</td>
                            <td><span class="badge red">Critical aging debt</span> with no closure path.</td>
                            <td>Drives escalation and burn-down priority.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Status Interpretation Library</h2>
                <p>
                    CITrust™ uses these definitions to keep dashboard language consistent.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3><span class="badge green">Trusted</span></h3>
                        <p>Core governance domains are complete, current, evidence-backed, and operationally defensible.</p>
                    </div>

                    <div class="card">
                        <h3><span class="badge yellow">Conditional</span></h3>
                        <p>Record can remain visible, but requires remediation, confirmation, exception, or evidence refresh before full trust.</p>
                    </div>

                    <div class="card">
                        <h3><span class="badge red">Blocked</span></h3>
                        <p>Critical owner, support, access, lifecycle, evidence, relationship, or data-quality control is missing.</p>
                    </div>

                    <div class="card">
                        <h3><span class="badge orange">Escalate</span></h3>
                        <p>Risk cannot be resolved by field cleanup alone and requires owner, support, access, lifecycle, or leadership decision.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Threshold-to-Action Matrix</h2>
                <p>
                    Every threshold should trigger an action, not only a color.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>Condition</th>
                            <th>Required Action</th>
                            <th>Allowed Movement</th>
                            <th>Not Allowed</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge green">Green</span></td>
                            <td>Required fields, relationships, evidence, ownership, access, lifecycle, and cadence are defensible.</td>
                            <td>Maintain periodic review and decision ledger entry.</td>
                            <td>Passport, attestation, executive trust reporting, submission pack if applicable.</td>
                            <td>No bypass of formal ServiceNow process.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Yellow</span></td>
                            <td>One or more governance controls are partial but have a defined remediation path.</td>
                            <td>Assign remediation owner, track exception if needed, refresh evidence.</td>
                            <td>Controlled review, remediation board, exception register, watchlist.</td>
                            <td>Full trust or final attestation without closure.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">Red</span></td>
                            <td>Critical owner, support, access, lifecycle, evidence, or dependency control is missing.</td>
                            <td>Block trust, create remediation action, escalate if operational impact exists.</td>
                            <td>Remediation only.</td>
                            <td>Submission-ready, attestation-ready, trusted, or audit-ready status.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">Escalate</span></td>
                            <td>Decision needs leadership, owner, support, access, lifecycle, or governance decision.</td>
                            <td>Record decision in decision ledger and assign accountable resolution owner.</td>
                            <td>Controlled exception only if risk is documented and time-bound.</td>
                            <td>Silent waiver or undocumented exception.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Threshold Override Rules</h2>
                <p>
                    CITrust™ should allow overrides only when evidence and governance decision are explicit.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Override Allowed</h3>
                        <ul>
                            <li>Override has accountable decision owner.</li>
                            <li>Evidence supports why the threshold can be temporarily adjusted.</li>
                            <li>Risk is documented in exception register.</li>
                            <li>Closure condition is defined.</li>
                            <li>Decision is recorded in the decision ledger.</li>
                            <li>Override is time-bound and visible to leadership.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Override Not Allowed</h3>
                        <ul>
                            <li>Owner, support group, LCM, or access path is missing.</li>
                            <li>Evidence is missing for audit-sensitive CI.</li>
                            <li>OOS or retired CI lacks closure evidence.</li>
                            <li>Hidden dependency supports recurring operational work.</li>
                            <li>Threshold is changed only to make dashboard look better.</li>
                            <li>Decision is not recorded or cannot be defended.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Threshold-Driven Remediation Queue</h2>
                <p>
                    These are the threshold failures that should trigger immediate remediation.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Threshold Breach</th>
                            <th>Why It Matters</th>
                            <th>Required Action</th>
                            <th>Expected Status Change</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden dependency with missing owner, support, LCM, access, and evidence.</td>
                            <td>Fails owner, relationship, access, evidence, and data-quality thresholds.</td>
                            <td>Create governed candidate and populate mandatory controls.</td>
                            <td>Red → Yellow</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS CI without closure and access deactivation evidence.</td>
                            <td>Fails lifecycle, access, evidence, and audit-readiness thresholds.</td>
                            <td>Attach closure evidence and confirm access removal.</td>
                            <td>Red → Closed / Green</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Cutover-sensitive CI with partial support, MyAccess, jump path, and cutover evidence.</td>
                            <td>Creates conditional operational trust and change-impact exposure.</td>
                            <td>Finalize support, access, jump path, and cutover evidence.</td>
                            <td>Yellow → Green</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Governance cadence evidence due or stale.</td>
                            <td>Trusted CI may decay into conditional status.</td>
                            <td>Refresh owner, support, access, backup, audit trail, lifecycle, and evidence reviews.</td>
                            <td>Yellow → Green</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CMDB configuration, MyAccess, audit systems, or human governance. This readiness threshold policy is a governance assurance overlay for standardizing KPI interpretation, trust score bands, red-yellow-green rules, exception rules, escalation rules, remediation triggers, ServiceNow-readiness thresholds, audit-readiness thresholds, cadence thresholds, governance debt thresholds, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_READINESS_THRESHOLDS_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Readiness Threshold Policy installed.")
