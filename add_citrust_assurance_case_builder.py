from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_ASSURANCE_CASE_BUILDER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/assurance-case-builder")'
ROUTE_ALIAS = '@app.route("/citrust/ci-assurance-case")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Assurance Case Builder already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_ASSURANCE_CASE_BUILDER_V1_ACTIVE
# ============================================================

@app.route("/citrust/assurance-case-builder")
@app.route("/citrust/ci-assurance-case")
def citrust_assurance_case_builder():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Assurance Case Builder</title>
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

            .case-grid {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 16px;
                margin-top: 16px;
            }

            .case-card {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 18px;
                min-height: 170px;
            }

            .case-card h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .case-card p {
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
                .kpis, .case-grid, .two-col {
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
                <h1>CITrust™ Assurance Case Builder</h1>

                <div class="subtitle">
                    Builds a structured governance argument showing whether a Configuration Item can be operationally trusted, what evidence supports the claim, what assumptions remain, what risks challenge the claim, and what remediation is required before trust can be defended.
                </div>

                <div class="positioning">
                    <strong>Assurance case boundary:</strong>
                    CITrust™ does not replace ServiceNow, does not create ServiceNow CIs, and does not approve changes in this demo. This assurance case builder organizes governance claims, evidence, risks, rebuttals, decisions, and open conditions so leadership can defend CI trust with traceable reasoning.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/executive-reasoning-panel">Executive Reasoning</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                    <a href="/citrust/readiness-attestation">Attestation Center</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Assurance Cases</div>
                    <div class="value">42</div>
                    <div class="note">CI records with trust claims, evidence claims, and decision claims.</div>
                </div>

                <div class="metric">
                    <div class="label">Complete Cases</div>
                    <div class="value" style="color: var(--green);">14</div>
                    <div class="note">Claims, evidence, assumptions, rebuttals, and decisions are defensible.</div>
                </div>

                <div class="metric">
                    <div class="label">Partial Cases</div>
                    <div class="value" style="color: var(--yellow);">19</div>
                    <div class="note">Assurance argument exists but evidence or closure remains incomplete.</div>
                </div>

                <div class="metric">
                    <div class="label">Failed Cases</div>
                    <div class="value" style="color: var(--red);">9</div>
                    <div class="note">Critical governance claims cannot be proven.</div>
                </div>

                <div class="metric">
                    <div class="label">Open Rebuttals</div>
                    <div class="value" style="color: var(--orange);">12</div>
                    <div class="note">Risks or objections that challenge CI trust.</div>
                </div>

                <div class="metric">
                    <div class="label">Passport-Ready</div>
                    <div class="value" style="color: var(--blue);">8</div>
                    <div class="note">Cases strong enough for CITrust™ Passport or attestation review.</div>
                </div>
            </section>

            <section class="section">
                <h2>Assurance Case Answer</h2>
                <p>
                    This page answers whether the organization can make and defend the claim that a CI is operationally trusted.
                </p>

                <div class="answer">
                    <strong>Current assurance interpretation:</strong>
                    A CI should be trusted only when the assurance case can prove the claim with evidence. The strongest cases have clear owner, support group, LCM, MyAccess route, lifecycle state, relationship map, evidence lineage, decision ledger entry, cadence review, and no unresolved critical rebuttal. Weak cases remain conditional or blocked because the trust claim cannot yet survive governance challenge.
                </div>
            </section>

            <section class="section">
                <h2>Assurance Case Structure</h2>
                <p>
                    CITrust™ uses an assurance case structure so trust is not based on informal confidence.
                </p>

                <div class="case-grid">
                    <div class="case-card">
                        <h3><span class="badge blue">Claim</span></h3>
                        <p>The CI can be operationally trusted for support, access, lifecycle, audit, change impact, and ServiceNow-style readiness.</p>
                    </div>

                    <div class="case-card">
                        <h3><span class="badge green">Evidence</span></h3>
                        <p>Owner confirmation, support mapping, MyAccess role, SOP, backup, audit trail, lifecycle, closure, and relationship evidence.</p>
                    </div>

                    <div class="case-card">
                        <h3><span class="badge yellow">Assumptions</span></h3>
                        <p>Known conditions that must remain true, such as support ownership, access path, lifecycle state, or cutover context.</p>
                    </div>

                    <div class="case-card">
                        <h3><span class="badge orange">Rebuttals</span></h3>
                        <p>Risks or objections that challenge trust, including missing evidence, unresolved ownership, stale review, or hidden dependency.</p>
                    </div>

                    <div class="case-card">
                        <h3><span class="badge purple">Decision</span></h3>
                        <p>Trusted, conditional, blocked, exception-approved, attestation-ready, passport-ready, or submission-ready.</p>
                    </div>

                    <div class="case-card">
                        <h3><span class="badge red">Open Condition</span></h3>
                        <p>Specific unresolved issue that must close before the assurance case can be upgraded.</p>
                    </div>

                    <div class="case-card">
                        <h3><span class="badge blue">Owner</span></h3>
                        <p>The accountable governance owner who can defend the assurance case and accept the decision rationale.</p>
                    </div>

                    <div class="case-card">
                        <h3><span class="badge green">Closure</span></h3>
                        <p>Evidence-backed action that moves the case from failed or partial to complete and defensible.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Assurance Case Matrix</h2>
                <p>
                    This matrix shows whether each CI has a complete assurance argument.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Trust Claim</th>
                            <th>Evidence Basis</th>
                            <th>Assumption</th>
                            <th>Rebuttal / Challenge</th>
                            <th>Assurance Decision</th>
                            <th>Closure Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>CI is operationally trusted and audit-defensible.</td>
                            <td>Owner, support, access, lifecycle, evidence, and cadence are aligned.</td>
                            <td>Periodic review remains current.</td>
                            <td>No material challenge.</td>
                            <td><span class="badge green">Complete Case</span></td>
                            <td>Maintain cadence and decision ledger updates.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Access route is controlled and supportable.</td>
                            <td>Infrastructure access model and support context are known.</td>
                            <td>Access procedure will be linked and kept current.</td>
                            <td>Formal admin/vendor procedure evidence is not fully linked.</td>
                            <td><span class="badge yellow">Partial Case</span></td>
                            <td>Attach admin or vendor access procedure evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">Cutover-sensitive BMS dependency</span></td>
                            <td>CI can be trusted after cutover controls are completed.</td>
                            <td>Owner and lifecycle context exist; cutover path is known.</td>
                            <td>Support group, MyAccess role, and jump path will be finalized.</td>
                            <td>Cutover evidence, support routing, access role, and jump path remain partial.</td>
                            <td><span class="badge yellow">Conditional Case</span></td>
                            <td>Finalize support, MyAccess, jump path, and cutover evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>CI is operational but not fully ServiceNow-ready.</td>
                            <td>Operational state is known and owner context exists.</td>
                            <td>Support group and evidence path can be reconciled.</td>
                            <td>Support group, evidence, and data-quality gaps remain open.</td>
                            <td><span class="badge yellow">Partial Case</span></td>
                            <td>Reconcile owner, support group, LCM, evidence, and classification.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td>CI is near trusted and access-ready.</td>
                            <td>Core record, owner, support, and evidence are strong.</td>
                            <td>MyAccess approver group can be confirmed.</td>
                            <td>Approver group and role evidence need final confirmation.</td>
                            <td><span class="badge yellow">Near Complete</span></td>
                            <td>Confirm MyAccess approver group and role evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>CI cannot be trusted until lifecycle closure is proven.</td>
                            <td>Legacy and OOS context exist but are insufficient.</td>
                            <td>Closure and access deactivation evidence can be located.</td>
                            <td>OOS closure, access deactivation, lifecycle owner, and closure evidence are not defensible.</td>
                            <td><span class="badge red">Failed Case</span></td>
                            <td>Attach closure evidence and confirm access removal.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>CI cannot be trusted because governance identity is missing.</td>
                            <td>Only operational discovery exists.</td>
                            <td>Candidate record can be created.</td>
                            <td>No owner, support group, LCM, access route, evidence, classification, or cadence exists.</td>
                            <td><span class="badge red">Failed Case</span></td>
                            <td>Create governed candidate and populate mandatory governance controls.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Assurance Case Decision Rules</h2>
                <p>
                    CITrust™ uses assurance cases to prevent weak readiness claims from becoming executive truth.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Complete Assurance Case</h3>
                        <ul>
                            <li>Trust claim is clear and specific.</li>
                            <li>Owner, support group, LCM, and access path are confirmed.</li>
                            <li>Evidence supports the claim.</li>
                            <li>Relationships and dependencies are known.</li>
                            <li>Rebuttals are closed or documented as non-material.</li>
                            <li>Decision ledger and cadence review keep the case current.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Failed Assurance Case</h3>
                        <ul>
                            <li>Claim cannot be supported by evidence.</li>
                            <li>Owner, support, LCM, access, lifecycle, or evidence is missing.</li>
                            <li>OOS or retired state lacks closure evidence.</li>
                            <li>Hidden dependency lacks governed candidate record.</li>
                            <li>Rebuttal remains critical and unresolved.</li>
                            <li>Leadership cannot defend why the CI is trusted.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Assurance Case Closure Queue</h2>
                <p>
                    These actions upgrade weak assurance cases into defensible governance cases.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Case Weakness</th>
                            <th>Why It Matters</th>
                            <th>Closure Action</th>
                            <th>Expected Upgrade</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no assurance case.</td>
                            <td>Recurring operational review depends on a CI-like object with no governed identity or evidence.</td>
                            <td>Create candidate, assign owner/support/LCM/access/evidence, and open decision ledger entry.</td>
                            <td>Failed Case → Partial Case</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment lifecycle case cannot be defended.</td>
                            <td>Closure and access deactivation are required before lifecycle trust can be claimed.</td>
                            <td>Attach closure evidence and confirm access removal.</td>
                            <td>Failed Case → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover assurance case remains conditional.</td>
                            <td>Cutover trust requires support, access, dependency, and evidence alignment.</td>
                            <td>Finalize support group, MyAccess role, jump path, and cutover evidence.</td>
                            <td>Conditional Case → Complete Case</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access evidence weakens otherwise strong cases.</td>
                            <td>Admin, vendor, or approver route must be defensible during audit or review.</td>
                            <td>Attach MyAccess, admin, vendor, or approver evidence and update attestation.</td>
                            <td>Partial Case → Complete Case</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, approve access, approve changes, or update CMDB records in this demo. This assurance case builder is a governance assurance overlay for CI trust claims, evidence-backed reasoning, rebuttal management, attestation readiness, passport readiness, audit readiness, decision defensibility, lifecycle assurance, ServiceNow-readiness, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_ASSURANCE_CASE_BUILDER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Assurance Case Builder installed.")
