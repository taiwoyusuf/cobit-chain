from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_EVIDENCE_LINEAGE_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/evidence-lineage")'
ROUTE_ALIAS = '@app.route("/citrust/evidence-command")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Evidence Lineage Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_EVIDENCE_LINEAGE_V1_ACTIVE
# ============================================================

@app.route("/citrust/evidence-lineage")
@app.route("/citrust/evidence-command")
def citrust_evidence_lineage():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Evidence Lineage Console</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <style>
            :root {
                --bg: #050d19;
                --panel: #101d2f;
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
                    radial-gradient(circle at bottom left, rgba(247,201,72,0.08), transparent 30%),
                    var(--bg);
                color: var(--text);
            }

            .page {
                max-width: 1400px;
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
                font-size: 39px;
                line-height: 1.1;
            }

            .subtitle {
                color: var(--muted);
                font-size: 16px;
                line-height: 1.6;
                max-width: 1080px;
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

            .lineage-flow {
                display: grid;
                grid-template-columns: repeat(6, 1fr);
                gap: 12px;
                margin-top: 16px;
            }

            .flow-step {
                border: 1px solid rgba(92,200,255,0.28);
                background: rgba(92,200,255,0.07);
                border-radius: 18px;
                padding: 16px;
            }

            .flow-step h3 {
                margin: 0 0 8px 0;
                font-size: 15px;
            }

            .flow-step p {
                margin: 0;
                font-size: 13px;
                color: var(--muted);
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
                .kpis, .cards, .lineage-flow, .two-col {
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
                <h1>CITrust™ Evidence Lineage Console</h1>

                <div class="subtitle">
                    Validates whether each Configuration Item is backed by reviewable evidence across ownership, support group, LCM, MyAccess routing, SOP linkage, backup review, audit trail review, validation, lifecycle state, and ServiceNow-readiness.
                </div>

                <div class="positioning">
                    <strong>Evidence assurance boundary:</strong>
                    ServiceNow stores CI records and related fields. CITrust™ validates whether the evidence behind those fields is complete, current, traceable, and operationally defendable. This page does not create ServiceNow CIs, does not write evidence to ServiceNow, and does not replace the system of record.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/servicenow-ci-readiness">ServiceNow CI Readiness</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                    <a href="/citrust/dependency-lineage">Dependency Lineage</a>
                    <a href="/citrust/ownership-readiness">Ownership Readiness</a>
                    <a href="/citrust/reconciliation">CMDB Reconciliation</a>
                    <a href="/citrust/submission-board">Submission Board</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Evidence Objects Checked</div>
                    <div class="value">86</div>
                    <div class="note">Ownership, SOP, access, backup, audit trail, validation, lifecycle, and submission artifacts.</div>
                </div>

                <div class="metric">
                    <div class="label">Fully Linked</div>
                    <div class="value" style="color: var(--green);">34</div>
                    <div class="note">Evidence is linked to the CI and can be reviewed without manual explanation.</div>
                </div>

                <div class="metric">
                    <div class="label">Partially Linked</div>
                    <div class="value" style="color: var(--yellow);">27</div>
                    <div class="note">Evidence exists but is incomplete, indirect, or not fully connected to the CI.</div>
                </div>

                <div class="metric">
                    <div class="label">Missing Evidence</div>
                    <div class="value" style="color: var(--red);">19</div>
                    <div class="note">Evidence required for operational trust or audit defense is absent.</div>
                </div>

                <div class="metric">
                    <div class="label">Stale Evidence</div>
                    <div class="value" style="color: var(--orange);">6</div>
                    <div class="note">Evidence exists but may not reflect current owner, access, lifecycle, or support state.</div>
                </div>

                <div class="metric">
                    <div class="label">Pre-Deviation Flags</div>
                    <div class="value" style="color: var(--blue);">11</div>
                    <div class="note">Evidence gaps identified before becoming audit findings, deviations, or routing failures.</div>
                </div>
            </section>

            <section class="section">
                <h2>Evidence Lineage Answer</h2>
                <p>
                    This console answers whether the CI can be defended with evidence, not just fields.
                </p>

                <div class="answer">
                    <strong>Current evidence interpretation:</strong>
                    Several CIs have enough evidence to support operational reliance and audit response, but the estate is not uniformly evidence-backed. The biggest weaknesses are partial SOP linkage, missing closure evidence for OOS records, incomplete MyAccess role evidence, and disconnected backup or audit trail review artifacts.
                </div>
            </section>

            <section class="section">
                <h2>Evidence Chain Model</h2>
                <p>
                    CITrust™ treats evidence as a chain. If one link is missing, the CI may still exist, but it cannot be fully trusted.
                </p>

                <div class="lineage-flow">
                    <div class="flow-step">
                        <h3>1. CI Record</h3>
                        <p>ServiceNow-style record, candidate record, master list item, or asset reference.</p>
                    </div>

                    <div class="flow-step">
                        <h3>2. Owner Evidence</h3>
                        <p>Proof that ownership, support group, and LCM are current and accountable.</p>
                    </div>

                    <div class="flow-step">
                        <h3>3. Access Evidence</h3>
                        <p>MyAccess role, approver group, access path, or requestability mapping.</p>
                    </div>

                    <div class="flow-step">
                        <h3>4. Procedure Evidence</h3>
                        <p>SOP, work instruction, admin procedure, or operational control reference.</p>
                    </div>

                    <div class="flow-step">
                        <h3>5. Review Evidence</h3>
                        <p>Backup review, audit trail review, user review, validation, or operational check evidence.</p>
                    </div>

                    <div class="flow-step">
                        <h3>6. Decision Evidence</h3>
                        <p>Candidate review, submission pack, exception, closure, or executive readiness decision.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Evidence Lineage Matrix</h2>
                <p>
                    This matrix shows whether each CI has the evidence needed to support ownership, access, SOP, review activity, lifecycle state, and ServiceNow-readiness.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Owner Evidence</th>
                            <th>Access Evidence</th>
                            <th>SOP / Procedure</th>
                            <th>Backup / Audit Trail</th>
                            <th>Lifecycle Evidence</th>
                            <th>Submission Evidence</th>
                            <th>Evidence Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Linked</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-green">Ready</span></td>
                            <td><span class="badge green">Evidence-Backed</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td><span class="badge soft-yellow">Cutover Evidence</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td><span class="badge yellow">Partially Backed</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-yellow">Procedure Needed</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-green">Ready</span></td>
                            <td><span class="badge yellow">Partially Backed</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Needs Link</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-green">Operational</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td><span class="badge yellow">Partially Backed</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Closure Needed</span></td>
                            <td><span class="badge soft-red">Blocked</span></td>
                            <td><span class="badge red">Evidence Gap</span></td>
                        </tr>

                        <tr>
                            <td><strong>Chromeleon Workstation</strong><br><span style="color: var(--muted);">Lab workstation dependency</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-yellow">Role Check</span></td>
                            <td><span class="badge soft-green">Linked</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td><span class="badge yellow">Partially Backed</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-yellow">Discovered</span></td>
                            <td><span class="badge soft-red">Blocked</span></td>
                            <td><span class="badge red">Evidence Gap</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Linked</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td><span class="badge yellow">Partially Backed</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Evidence Assurance Domains</h2>
                <p>
                    CITrust™ separates evidence into domains so gaps can be remediated precisely.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Ownership Evidence</h3>
                        <p>Confirms who owns the CI, who supports it, who manages lifecycle accountability, and who can answer audit questions.</p>
                    </div>

                    <div class="card">
                        <h3>Access Evidence</h3>
                        <p>Confirms MyAccess role mapping, approver group, requestability, privileged access route, and vendor or admin access path.</p>
                    </div>

                    <div class="card">
                        <h3>Operational Evidence</h3>
                        <p>Links backup reviews, audit trail reviews, user reviews, SOPs, work instructions, validation references, and recurring checks.</p>
                    </div>

                    <div class="card">
                        <h3>Lifecycle Evidence</h3>
                        <p>Confirms active, retired, OOS, cutover, or pending state with supporting closure, migration, validation, or change evidence.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Evidence Decision Logic</h2>
                <p>
                    CITrust™ uses evidence quality to prevent weak CI records from being treated as trusted records.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Evidence-Backed CI</h3>
                        <ul>
                            <li>Owner, support group, and LCM evidence are available.</li>
                            <li>MyAccess approver path and access roles are mapped or justified.</li>
                            <li>SOP, work instruction, or procedural evidence is linked where required.</li>
                            <li>Backup, audit trail, user review, validation, or operational review evidence is available where applicable.</li>
                            <li>Lifecycle state is supported by evidence.</li>
                            <li>Submission or candidate-review decision is traceable.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Evidence Gap CI</h3>
                        <ul>
                            <li>CI exists but evidence cannot be located.</li>
                            <li>Evidence exists but is not connected to the CI.</li>
                            <li>Access route is not supported by role or approver evidence.</li>
                            <li>OOS or retired record lacks closure evidence.</li>
                            <li>Backup or audit trail review depends on undocumented local process.</li>
                            <li>Candidate is pushed forward without defensible evidence lineage.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Evidence Remediation Queue</h2>
                <p>
                    These evidence gaps should be resolved before records are treated as ServiceNow-ready, audit-ready, or operationally trusted.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Record</th>
                            <th>Evidence Gap</th>
                            <th>Required Action</th>
                            <th>Target State</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Local Backup Review Workstation</td>
                            <td>Missing owner, access, SOP, backup review, and evidence lineage.</td>
                            <td>Create governed candidate and attach backup review evidence path, owner, support group, and LCM.</td>
                            <td>Evidence-backed operational dependency.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">High</span></td>
                            <td>Speedy Glove 1802</td>
                            <td>Closure evidence and access deactivation proof are incomplete.</td>
                            <td>Attach OOS closure record, access removal evidence, and lifecycle decision reference.</td>
                            <td>Closed record with defensible lifecycle evidence.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Niagara BMS Server</td>
                            <td>Cutover evidence, support route confirmation, and MyAccess role evidence remain partial.</td>
                            <td>Link cutover validation evidence, support group confirmation, role mapping, and jump path evidence.</td>
                            <td>Conditionally backed record moved to trusted evidence state.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Jump Server Access Path</td>
                            <td>Administrative access procedure or work instruction evidence should be linked.</td>
                            <td>Attach admin-access process evidence, vendor access control reference, or support routing artifact.</td>
                            <td>Fully evidence-backed infrastructure dependency.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, upload evidence into ServiceNow, or write directly into ServiceNow in this demo. This evidence lineage console is a governance assurance overlay for evidence-backed CI trust, ownership validation, MyAccess readiness, SOP linkage, backup and audit trail evidence, lifecycle defensibility, submission readiness, audit readiness, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_EVIDENCE_LINEAGE_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Evidence Lineage Console installed.")
