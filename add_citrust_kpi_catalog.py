from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_KPI_CATALOG_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/kpi-catalog")'
ROUTE_ALIAS = '@app.route("/citrust/readiness-kpis")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust KPI Catalog already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_KPI_CATALOG_V1_ACTIVE
# ============================================================

@app.route("/citrust/kpi-catalog")
@app.route("/citrust/readiness-kpis")
def citrust_kpi_catalog():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Readiness KPI Catalog</title>
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
                    radial-gradient(circle at bottom right, rgba(49,208,125,0.08), transparent 30%),
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
                border: 1px solid rgba(92,200,255,0.36);
                background: rgba(92,200,255,0.10);
                color: #d9f3ff;
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
                <h1>CITrust™ Readiness KPI Catalog</h1>

                <div class="subtitle">
                    Defines the core metrics used to measure whether Configuration Items are operationally trusted, ServiceNow-ready, MyAccess-ready, audit-ready, evidence-backed, relationship-ready, cadence-current, remediation-controlled, and executive-defensible.
                </div>

                <div class="positioning">
                    <strong>KPI boundary:</strong>
                    CITrust™ KPIs are governance assurance metrics. They do not replace ServiceNow reporting, do not create CIs, do not update CMDB fields, and do not approve changes. They explain how CI trust is measured and why leadership should rely on, hold, or remediate a CI.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/trust-score-model">Trust Score Model</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                    <a href="/citrust/governance-debt-register">Governance Debt</a>
                    <a href="/citrust/governance-cadence">Governance Cadence</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">KPI Families</div>
                    <div class="value">10</div>
                    <div class="note">Trust, ownership, access, evidence, lifecycle, relationship, data, risk, debt, cadence.</div>
                </div>

                <div class="metric">
                    <div class="label">Defined KPIs</div>
                    <div class="value" style="color: var(--blue);">32</div>
                    <div class="note">Metrics used across CITrust™ dashboards and readiness views.</div>
                </div>

                <div class="metric">
                    <div class="label">Executive KPIs</div>
                    <div class="value" style="color: var(--purple);">8</div>
                    <div class="note">Leadership-facing metrics for readiness defense and prioritization.</div>
                </div>

                <div class="metric">
                    <div class="label">Blocking KPIs</div>
                    <div class="value" style="color: var(--red);">7</div>
                    <div class="note">Metrics that indicate when trust, submission, or attestation should be held.</div>
                </div>

                <div class="metric">
                    <div class="label">Cadence KPIs</div>
                    <div class="value" style="color: var(--orange);">5</div>
                    <div class="note">Metrics that detect stale evidence, overdue reviews, and trust decay.</div>
                </div>

                <div class="metric">
                    <div class="label">Remediation KPIs</div>
                    <div class="value" style="color: var(--green);">6</div>
                    <div class="note">Metrics that show whether governance debt is being burned down.</div>
                </div>
            </section>

            <section class="section">
                <h2>KPI Catalog Answer</h2>
                <p>
                    This catalog answers how CITrust™ measures whether a CI can be operationally trusted.
                </p>

                <div class="answer">
                    <strong>Current KPI interpretation:</strong>
                    CITrust™ should not rely on one score alone. A trustworthy CI requires multiple KPI families: owner coverage, support routing coverage, MyAccess mapping, evidence completeness, lifecycle clarity, relationship completeness, field quality, conflict resolution, cadence freshness, governance debt reduction, and executive decision defensibility.
                </div>
            </section>

            <section class="section">
                <h2>Executive KPI Library</h2>
                <p>
                    These are the top-level metrics leadership should use to understand CI readiness.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>KPI</th>
                            <th>Purpose</th>
                            <th>Formula / Logic</th>
                            <th>Good Signal</th>
                            <th>Bad Signal</th>
                            <th>Used By</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>CI Trust Coverage</strong></td>
                            <td>Measures the percentage of CIs that are operationally trusted.</td>
                            <td>Trusted CIs / Total CI Population</td>
                            <td><span class="badge soft-green">High trusted percentage</span></td>
                            <td><span class="badge soft-red">Large conditional or blocked population</span></td>
                            <td>Executive Dashboard, Command Center, Trust Score Model.</td>
                        </tr>

                        <tr>
                            <td><strong>ServiceNow-Readiness Rate</strong></td>
                            <td>Measures how many candidates are ready for submission-pack preparation.</td>
                            <td>Submission-ready records / Candidate population</td>
                            <td><span class="badge soft-green">Fields and evidence complete</span></td>
                            <td><span class="badge soft-red">Mandatory field or evidence blockers</span></td>
                            <td>Submission Board, Mandatory Fields Checklist.</td>
                        </tr>

                        <tr>
                            <td><strong>Owner Coverage Rate</strong></td>
                            <td>Measures whether CIs have accountable ownership.</td>
                            <td>CIs with confirmed owner / Total CIs</td>
                            <td><span class="badge soft-green">Owner and LCM confirmed</span></td>
                            <td><span class="badge soft-red">Ownerless or stale accountability</span></td>
                            <td>Ownership Readiness, Attestation Center, Audit Readiness.</td>
                        </tr>

                        <tr>
                            <td><strong>Support Routing Coverage</strong></td>
                            <td>Measures whether CIs can route incidents and support requests.</td>
                            <td>CIs with confirmed support group / Total support-relevant CIs</td>
                            <td><span class="badge soft-green">Support group routable</span></td>
                            <td><span class="badge soft-red">Support group missing or disputed</span></td>
                            <td>Support Readiness, Risk Heatmap, Bottleneck Analysis.</td>
                        </tr>

                        <tr>
                            <td><strong>MyAccess Mapping Coverage</strong></td>
                            <td>Measures access-routing readiness.</td>
                            <td>CIs with roles and approvers mapped / Access-controlled CIs</td>
                            <td><span class="badge soft-green">Approver group and role evidence confirmed</span></td>
                            <td><span class="badge soft-red">Access route cannot be defended</span></td>
                            <td>MyAccess Readiness, Audit Readiness, Attestation Center.</td>
                        </tr>

                        <tr>
                            <td><strong>Evidence Completeness Rate</strong></td>
                            <td>Measures whether CI trust claims are evidence-backed.</td>
                            <td>CIs with required evidence / Evidence-required CIs</td>
                            <td><span class="badge soft-green">Evidence linked and reviewable</span></td>
                            <td><span class="badge soft-red">SOP, backup, audit trail, closure, or access evidence missing</span></td>
                            <td>Evidence Lineage, Audit Readiness, Governance Debt.</td>
                        </tr>

                        <tr>
                            <td><strong>Governance Debt Load</strong></td>
                            <td>Measures accumulated unresolved governance gaps.</td>
                            <td>Open debt items weighted by risk and age</td>
                            <td><span class="badge soft-green">Debt decreasing</span></td>
                            <td><span class="badge soft-red">Critical debt aging or increasing</span></td>
                            <td>Governance Debt Register, Remediation Board.</td>
                        </tr>

                        <tr>
                            <td><strong>Cadence Freshness Rate</strong></td>
                            <td>Measures whether recurring reviews remain current.</td>
                            <td>Current reviews / Required recurring reviews</td>
                            <td><span class="badge soft-green">Reviews current</span></td>
                            <td><span class="badge soft-red">Overdue reviews or stale evidence</span></td>
                            <td>Governance Cadence, Decision Ledger, Audit Readiness.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>KPI Domain Catalog</h2>
                <p>
                    CITrust™ uses KPI families so dashboards can explain both readiness and the reason behind readiness.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Trust KPIs</h3>
                        <p>Trusted, conditional, blocked, attestation-ready, passport-ready, and ServiceNow-ready record counts.</p>
                    </div>

                    <div class="card">
                        <h3>Ownership KPIs</h3>
                        <p>Owner coverage, support group coverage, LCM coverage, escalation coverage, and attestation coverage.</p>
                    </div>

                    <div class="card">
                        <h3>Access KPIs</h3>
                        <p>MyAccess mapping coverage, approver group confirmation, role evidence, admin path, and vendor access readiness.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence KPIs</h3>
                        <p>Evidence completeness, evidence freshness, SOP linkage, backup review evidence, audit trail evidence, and closure proof.</p>
                    </div>

                    <div class="card">
                        <h3>Lifecycle KPIs</h3>
                        <p>Active, OOS, retired, cutover, closure, access deactivation, and lifecycle-owner readiness.</p>
                    </div>

                    <div class="card">
                        <h3>Relationship KPIs</h3>
                        <p>Owned by, supported by, depends on, hosted on, accessed through, approved by, and closed by relationship coverage.</p>
                    </div>

                    <div class="card">
                        <h3>Data KPIs</h3>
                        <p>Mandatory field completion, duplicate risk, source authority, conflict resolution, and cross-source reconciliation.</p>
                    </div>

                    <div class="card">
                        <h3>Debt KPIs</h3>
                        <p>Open debt, aging debt, critical debt, evidence debt, ownership debt, and debt burn-down readiness.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CITrust™ KPI Matrix</h2>
                <p>
                    These KPIs convert CITrust™ readiness into measurable governance intelligence.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>KPI Family</th>
                            <th>Metric</th>
                            <th>Threshold Logic</th>
                            <th>Executive Meaning</th>
                            <th>Remediation Trigger</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Trust</strong></td>
                            <td>Blocked CI Count</td>
                            <td><span class="badge red">Any critical blocked CI requires visibility</span></td>
                            <td>Leadership should not rely on blocked records.</td>
                            <td>Create remediation action or exception decision.</td>
                        </tr>

                        <tr>
                            <td><strong>Ownership</strong></td>
                            <td>Owner Coverage Rate</td>
                            <td><span class="badge yellow">Below target means accountability risk</span></td>
                            <td>Ownerless records cannot be defended in audit or operations.</td>
                            <td>Assign owner and record decision in ledger.</td>
                        </tr>

                        <tr>
                            <td><strong>Support</strong></td>
                            <td>Support Group Coverage</td>
                            <td><span class="badge yellow">Missing support group makes CI conditional or blocked</span></td>
                            <td>Incident and request routing may fail.</td>
                            <td>Confirm routable support group and escalation path.</td>
                        </tr>

                        <tr>
                            <td><strong>Access</strong></td>
                            <td>MyAccess Mapping Coverage</td>
                            <td><span class="badge orange">Access-controlled CI without mapping is high risk</span></td>
                            <td>Access approval cannot be defended.</td>
                            <td>Confirm roles, approvers, and evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Evidence</strong></td>
                            <td>Evidence Completeness</td>
                            <td><span class="badge red">Missing evidence blocks audit readiness</span></td>
                            <td>Trust claim cannot be proven.</td>
                            <td>Attach SOP, backup, audit trail, closure, access, or cutover evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Lifecycle</strong></td>
                            <td>OOS Closure Coverage</td>
                            <td><span class="badge red">OOS without closure proof remains blocked</span></td>
                            <td>Lifecycle state cannot be defended.</td>
                            <td>Attach closure evidence and access deactivation proof.</td>
                        </tr>

                        <tr>
                            <td><strong>Relationship</strong></td>
                            <td>Relationship Completeness</td>
                            <td><span class="badge yellow">Missing key relationships weaken change impact</span></td>
                            <td>Dependencies and impact may be hidden.</td>
                            <td>Map owned by, supported by, depends on, and accessed through.</td>
                        </tr>

                        <tr>
                            <td><strong>Cadence</strong></td>
                            <td>Overdue Review Count</td>
                            <td><span class="badge orange">Overdue reviews create trust decay</span></td>
                            <td>Trusted CIs may become conditional.</td>
                            <td>Refresh review evidence and decision status.</td>
                        </tr>

                        <tr>
                            <td><strong>Debt</strong></td>
                            <td>Critical Governance Debt</td>
                            <td><span class="badge red">Critical debt should be burned down first</span></td>
                            <td>Unresolved gaps accumulate operational risk.</td>
                            <td>Prioritize remediation board action.</td>
                        </tr>

                        <tr>
                            <td><strong>Decision</strong></td>
                            <td>Decision Defensibility Rate</td>
                            <td><span class="badge blue">Decisions need owner, rationale, evidence, and next action</span></td>
                            <td>Leadership can explain why a CI is trusted or blocked.</td>
                            <td>Complete decision ledger entry.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>KPI Decision Logic</h2>
                <p>
                    KPIs must support action, not just reporting.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Healthy KPI Signal</h3>
                        <ul>
                            <li>Trusted CI population is increasing.</li>
                            <li>Blocked CI population is decreasing.</li>
                            <li>Evidence completeness and freshness are improving.</li>
                            <li>Owner, support, LCM, and MyAccess coverage are high.</li>
                            <li>Governance debt is actively burning down.</li>
                            <li>Decision ledger explains readiness status clearly.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Unhealthy KPI Signal</h3>
                        <ul>
                            <li>Blocked records remain unresolved.</li>
                            <li>Critical governance debt is aging.</li>
                            <li>Access mapping and support routing remain partial.</li>
                            <li>Evidence is missing or stale.</li>
                            <li>Cadence reviews are overdue.</li>
                            <li>Executive dashboard shows improvement without actual remediation.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>KPI-Driven Remediation Queue</h2>
                <p>
                    These actions improve the highest-value CITrust™ metrics.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>KPI Gap</th>
                            <th>Why It Matters</th>
                            <th>Required Action</th>
                            <th>Expected KPI Improvement</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Critical blocked CI count remains high.</td>
                            <td>Blocked CIs cannot be trusted, attested, or submitted.</td>
                            <td>Create governed candidates, close OOS items, and assign accountability.</td>
                            <td>Blocked CI Count ↓ / Candidate Review Readiness ↑</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Evidence completeness below target.</td>
                            <td>Missing evidence weakens audit readiness and trust scoring.</td>
                            <td>Attach SOP, backup, audit trail, closure, access, and cutover evidence.</td>
                            <td>Evidence Completeness ↑ / Audit Risk ↓</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>MyAccess mapping partially complete.</td>
                            <td>Access approvals cannot be defended without role and approver mapping.</td>
                            <td>Confirm MyAccess roles, approver groups, requestability, and access evidence.</td>
                            <td>MyAccess Coverage ↑ / Access Risk ↓</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Governance cadence reviews due or stale.</td>
                            <td>Trust decays when reviews are missed.</td>
                            <td>Refresh ownership, support, access, backup, audit trail, and lifecycle reviews.</td>
                            <td>Cadence Freshness ↑ / Stale Evidence ↓</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow reporting, CMDB dashboards, MyAccess reporting, audit systems, or human governance. This readiness KPI catalog is a governance assurance overlay for defining CI trust metrics, ServiceNow-readiness metrics, MyAccess-readiness metrics, evidence metrics, lifecycle metrics, relationship metrics, governance debt metrics, cadence metrics, executive dashboard logic, remediation prioritization, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_KPI_CATALOG_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust KPI Catalog installed.")
