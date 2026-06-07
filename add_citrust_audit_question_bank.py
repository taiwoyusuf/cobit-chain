from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AUDIT_QUESTION_BANK_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/audit-question-bank")'
ROUTE_ALIAS = '@app.route("/citrust/ci-audit-defense")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Audit Question Bank already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AUDIT_QUESTION_BANK_V1_ACTIVE
# ============================================================

@app.route("/citrust/audit-question-bank")
@app.route("/citrust/ci-audit-defense")
def citrust_audit_question_bank():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Audit Question Bank</title>
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

            .question-grid {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 16px;
                margin-top: 16px;
            }

            .question-card {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 18px;
                min-height: 170px;
            }

            .question-card h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .question-card p {
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
                .kpis, .question-grid, .two-col {
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
                <h1>CITrust™ Audit Question Bank</h1>

                <div class="subtitle">
                    Converts CI governance readiness into audit-defense questions, expected evidence, weak answers, strong answers, and readiness decisions so teams can defend whether a Configuration Item is operationally trusted, ServiceNow-ready, MyAccess-ready, lifecycle-ready, and evidence-backed.
                </div>

                <div class="positioning">
                    <strong>Audit defense boundary:</strong>
                    CITrust™ does not replace audit systems, quality systems, ServiceNow, MyAccess, or human governance. This question bank prepares governance teams to answer CI trust questions with evidence-backed reasoning and identifies where the answer is weak, conditional, or blocked.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                    <a href="/citrust/evidence-pack-builder">Evidence Pack Builder</a>
                    <a href="/citrust/assurance-case-builder">Assurance Case</a>
                    <a href="/citrust/readiness-attestation">Attestation Center</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Audit Questions</div>
                    <div class="value">48</div>
                    <div class="note">Questions mapped across ownership, support, access, lifecycle, evidence, cadence, and submission.</div>
                </div>

                <div class="metric">
                    <div class="label">Defensible Answers</div>
                    <div class="value" style="color: var(--green);">21</div>
                    <div class="note">Questions with strong evidence-backed responses.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Answers</div>
                    <div class="value" style="color: var(--yellow);">17</div>
                    <div class="note">Answers requiring remediation, confirmation, or exception logic.</div>
                </div>

                <div class="metric">
                    <div class="label">Weak Answers</div>
                    <div class="value" style="color: var(--red);">10</div>
                    <div class="note">Questions that expose missing evidence or unresolved governance control gaps.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Gaps</div>
                    <div class="value" style="color: var(--orange);">16</div>
                    <div class="note">Open proof gaps that weaken audit defensibility.</div>
                </div>

                <div class="metric">
                    <div class="label">Ready for Defense</div>
                    <div class="value" style="color: var(--blue);">9</div>
                    <div class="note">CIs that can support structured audit-question defense.</div>
                </div>
            </section>

            <section class="section">
                <h2>Audit Question Bank Answer</h2>
                <p>
                    This page answers whether the CITrust™ evidence pack can survive audit-style questioning.
                </p>

                <div class="answer">
                    <strong>Current audit-defense interpretation:</strong>
                    A CI is audit-defensible only when the team can answer who owns it, who supports it, how access is approved, what it depends on, whether lifecycle state is current, where evidence lives, whether reviews are current, and why the readiness decision is justified. Weak answers should trigger remediation before the CI is treated as trusted or submission-ready.
                </div>
            </section>

            <section class="section">
                <h2>Audit Question Categories</h2>
                <p>
                    CITrust™ organizes expected questions by governance domain.
                </p>

                <div class="question-grid">
                    <div class="question-card">
                        <h3><span class="badge blue">Ownership Questions</span></h3>
                        <p>Who owns the CI? Who is accountable for lifecycle, support, review, and readiness decisions?</p>
                    </div>

                    <div class="question-card">
                        <h3><span class="badge purple">Support Questions</span></h3>
                        <p>Which support group receives incidents, requests, escalations, and operational accountability?</p>
                    </div>

                    <div class="question-card">
                        <h3><span class="badge orange">Access Questions</span></h3>
                        <p>How is access requested, approved, reviewed, removed, and routed through MyAccess or controlled access paths?</p>
                    </div>

                    <div class="question-card">
                        <h3><span class="badge green">Evidence Questions</span></h3>
                        <p>Where is the SOP, backup, audit trail, validation, closure, access, and cutover evidence?</p>
                    </div>

                    <div class="question-card">
                        <h3><span class="badge yellow">Lifecycle Questions</span></h3>
                        <p>Is the CI active, OOS, retired, cutover, or closed, and what evidence proves the lifecycle state?</p>
                    </div>

                    <div class="question-card">
                        <h3><span class="badge blue">Dependency Questions</span></h3>
                        <p>What does the CI depend on, what depends on it, and what is the change-impact path?</p>
                    </div>

                    <div class="question-card">
                        <h3><span class="badge red">Exception Questions</span></h3>
                        <p>What gaps remain, who accepted the risk, what is the closure condition, and when must it be remediated?</p>
                    </div>

                    <div class="question-card">
                        <h3><span class="badge green">Decision Questions</span></h3>
                        <p>Why is the CI trusted, conditional, blocked, attestation-ready, or ServiceNow-ready?</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CITrust™ Audit Question Matrix</h2>
                <p>
                    This matrix shows the expected audit question, required proof, weak answer, strong answer, and CITrust™ readiness impact.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Audit Question</th>
                            <th>Required Evidence</th>
                            <th>Weak Answer</th>
                            <th>Strong Answer</th>
                            <th>Readiness Impact</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Who owns this CI?</strong></td>
                            <td>Owner confirmation, LCM assignment, support group mapping, decision ledger entry.</td>
                            <td>“We think the owner is probably the application team.”</td>
                            <td>“The owner, LCM, support group, and escalation path are confirmed and linked in the evidence pack.”</td>
                            <td><span class="badge red">Blocks trust if unanswered</span></td>
                        </tr>

                        <tr>
                            <td><strong>Which support group responds if this CI fails?</strong></td>
                            <td>Support group confirmation, incident routing context, escalation path.</td>
                            <td>“Someone from infrastructure usually handles it.”</td>
                            <td>“The routable support group is documented, confirmed, and aligned with the CI relationship map.”</td>
                            <td><span class="badge orange">High operational impact</span></td>
                        </tr>

                        <tr>
                            <td><strong>How is access requested and approved?</strong></td>
                            <td>MyAccess role, approver group, requestability, admin path, vendor access route, access review evidence.</td>
                            <td>“Access is handled manually when needed.”</td>
                            <td>“Access route, approver group, roles, admin path, and review evidence are mapped and defensible.”</td>
                            <td><span class="badge red">Blocks access-readiness</span></td>
                        </tr>

                        <tr>
                            <td><strong>Where is the evidence that this CI is reviewed?</strong></td>
                            <td>Backup review, audit trail review, periodic review evidence, review cadence, reviewer accountability.</td>
                            <td>“Reviews are done, but I need to find where they are stored.”</td>
                            <td>“Review artifacts are linked, current, and tied to the CI governance cadence.”</td>
                            <td><span class="badge orange">Audit-readiness risk</span></td>
                        </tr>

                        <tr>
                            <td><strong>What is the lifecycle state of this CI?</strong></td>
                            <td>Active, OOS, retired, cutover, closure, access deactivation, and lifecycle owner evidence.</td>
                            <td>“It is probably out of service, but the record may still exist.”</td>
                            <td>“Lifecycle state is evidence-backed with closure proof and access deactivation where applicable.”</td>
                            <td><span class="badge red">Blocks lifecycle readiness</span></td>
                        </tr>

                        <tr>
                            <td><strong>What does this CI depend on?</strong></td>
                            <td>Relationship map, dependency lineage, hosted-on relationship, accessed-through relationship, change impact context.</td>
                            <td>“We know there are dependencies, but they are not fully mapped.”</td>
                            <td>“Dependencies are mapped, relationship types are documented, and change-impact risk is understood.”</td>
                            <td><span class="badge yellow">Conditional until mapped</span></td>
                        </tr>

                        <tr>
                            <td><strong>Why is this CI trusted, conditional, or blocked?</strong></td>
                            <td>Trust score, threshold policy, decision ledger, assurance case, evidence pack, remediation status.</td>
                            <td>“The dashboard shows yellow, but I am not sure why.”</td>
                            <td>“The readiness decision is supported by the trust score, threshold rule, evidence pack, and decision ledger.”</td>
                            <td><span class="badge blue">Executive defensibility</span></td>
                        </tr>

                        <tr>
                            <td><strong>What open exceptions exist?</strong></td>
                            <td>Exception register, owner, risk statement, closure condition, remediation action, expiry or review date.</td>
                            <td>“There are a few gaps, but we are tracking them informally.”</td>
                            <td>“Each exception has a named owner, documented risk, closure condition, and remediation action.”</td>
                            <td><span class="badge orange">Exception governance</span></td>
                        </tr>

                        <tr>
                            <td><strong>Can this record be submitted as ServiceNow-ready?</strong></td>
                            <td>Mandatory fields checklist, source authority, conflict resolution, evidence pack, candidate review decision.</td>
                            <td>“It looks complete enough from the spreadsheet.”</td>
                            <td>“Mandatory fields, source authority, evidence, relationships, and candidate review decision support submission-pack readiness.”</td>
                            <td><span class="badge red">Blocks submission if weak</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>CI Audit Defense Matrix</h2>
                <p>
                    This view shows which CIs are ready to answer audit-style questions and which are exposed.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Strongest Defense</th>
                            <th>Weakest Answer</th>
                            <th>Evidence Needed</th>
                            <th>Audit Defense Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td>Owner, support, lifecycle, access, and evidence are aligned.</td>
                            <td>No material weak answer if cadence remains current.</td>
                            <td>Periodic review evidence refresh.</td>
                            <td><span class="badge green">Defense-Ready</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td>Access route and support context are understood.</td>
                            <td>Formal admin/vendor access procedure evidence may not be fully linked.</td>
                            <td>Admin access procedure, vendor access route, access review evidence.</td>
                            <td><span class="badge yellow">Conditional Defense</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">Cutover-sensitive BMS dependency</span></td>
                            <td>Owner and cutover context are known.</td>
                            <td>Support group, MyAccess role, jump path, and cutover evidence remain partial.</td>
                            <td>Support confirmation, role mapping, jump-path evidence, cutover artifact.</td>
                            <td><span class="badge yellow">Watchlist Defense</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td>Operational state is known.</td>
                            <td>Support group and evidence path need reconciliation.</td>
                            <td>Owner/support/LCM evidence, operational classification, evidence path.</td>
                            <td><span class="badge yellow">Conditional Defense</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td>OOS context is known.</td>
                            <td>Closure evidence and access deactivation cannot be defended yet.</td>
                            <td>Closure proof, access removal proof, lifecycle decision record.</td>
                            <td><span class="badge red">Defense Failed</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td>Operational dependency has been discovered.</td>
                            <td>No governed CI identity, owner, support group, LCM, access route, evidence, or cadence.</td>
                            <td>Candidate record, owner, support, LCM, access path, backup review evidence.</td>
                            <td><span class="badge red">Defense Failed</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Audit Defense Decision Logic</h2>
                <p>
                    A strong answer must be backed by evidence, not memory or informal ownership.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Audit-Defensible Answer</h3>
                        <ul>
                            <li>Answer identifies accountable owner or governance owner.</li>
                            <li>Evidence location is known and reviewable.</li>
                            <li>CI lifecycle state is current and supported.</li>
                            <li>Access route and approver group are mapped where applicable.</li>
                            <li>Relationship and dependency context are documented.</li>
                            <li>Decision ledger explains the readiness decision.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Weak Audit Answer</h3>
                        <ul>
                            <li>Answer depends on tribal knowledge.</li>
                            <li>Evidence cannot be located quickly.</li>
                            <li>Owner, support, LCM, or access route is uncertain.</li>
                            <li>Lifecycle state is assumed instead of evidence-backed.</li>
                            <li>Open exceptions are informal or undocumented.</li>
                            <li>CI is described as trusted without evidence pack support.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Audit Defense Remediation Queue</h2>
                <p>
                    These actions convert weak answers into defensible answers.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Weak Audit Answer</th>
                            <th>Why It Matters</th>
                            <th>Required Remediation</th>
                            <th>Expected Defense Upgrade</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>“We know this workstation is used, but it is not governed as a CI.”</td>
                            <td>Hidden operational dependency cannot survive audit questioning.</td>
                            <td>Create governed candidate and assign owner, support, LCM, access, evidence, and cadence.</td>
                            <td>Defense Failed → Conditional Defense</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>“This equipment is OOS, but closure evidence is not attached.”</td>
                            <td>OOS lifecycle status cannot be defended without closure and access removal proof.</td>
                            <td>Attach closure evidence and confirm access deactivation.</td>
                            <td>Defense Failed → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>“Cutover support and access path are still being finalized.”</td>
                            <td>Cutover-sensitive systems require strong support, access, and dependency evidence.</td>
                            <td>Finalize support group, MyAccess role, jump path, and cutover evidence.</td>
                            <td>Watchlist Defense → Defense-Ready</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>“Admin/vendor access path is known, but procedure evidence is not linked.”</td>
                            <td>Privileged access cannot be fully defended without procedure and review evidence.</td>
                            <td>Attach admin/vendor access procedure and access review evidence.</td>
                            <td>Conditional Defense → Audit-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, MyAccess, audit systems, quality systems, or human governance. This audit question bank is a governance assurance overlay for CI audit defensibility, evidence-backed answers, ownership defense, support routing defense, MyAccess defense, lifecycle defense, dependency defense, exception defense, decision defense, audit-readiness, ServiceNow-readiness, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AUDIT_QUESTION_BANK_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Audit Question Bank installed.")
