from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_EVIDENCE_PACK_BUILDER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/evidence-pack-builder")'
ROUTE_ALIAS = '@app.route("/citrust/ci-evidence-pack")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Evidence Pack Builder already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_EVIDENCE_PACK_BUILDER_V1_ACTIVE
# ============================================================

@app.route("/citrust/evidence-pack-builder")
@app.route("/citrust/ci-evidence-pack")
def citrust_evidence_pack_builder():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Evidence Pack Builder</title>
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
                    radial-gradient(circle at bottom right, rgba(180,156,255,0.08), transparent 30%),
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

            .pack-grid {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 16px;
                margin-top: 16px;
            }

            .pack-card {
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                border-radius: 18px;
                padding: 18px;
                min-height: 170px;
            }

            .pack-card h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .pack-card p {
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
                .kpis, .pack-grid, .two-col {
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
                <h1>CITrust™ Evidence Pack Builder</h1>

                <div class="subtitle">
                    Assembles the evidence required to defend a Configuration Item across ownership, support group, LCM, MyAccess, lifecycle state, relationship mapping, SOP linkage, backup review, audit trail review, closure proof, cutover readiness, decision history, and ServiceNow-style submission readiness.
                </div>

                <div class="positioning">
                    <strong>Evidence pack boundary:</strong>
                    CITrust™ does not replace ServiceNow, does not create CIs, and does not write evidence into ServiceNow in this demo. This builder defines the evidence bundle needed before a CI can be trusted, attested, audited, passed to a passport, or prepared for submission-pack review.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/evidence-lineage">Evidence Lineage</a>
                    <a href="/citrust/assurance-case-builder">Assurance Case</a>
                    <a href="/citrust/readiness-attestation">Attestation Center</a>
                    <a href="/citrust/passport">CITrust™ Passport</a>
                    <a href="/ci-submission-pack">Submission Pack</a>
                    <a href="/citrust/audit-readiness">Audit Readiness</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Evidence Packs</div>
                    <div class="value">42</div>
                    <div class="note">CI records requiring evidence pack evaluation.</div>
                </div>

                <div class="metric">
                    <div class="label">Complete Packs</div>
                    <div class="value" style="color: var(--green);">13</div>
                    <div class="note">Evidence bundles complete enough for trust or attestation.</div>
                </div>

                <div class="metric">
                    <div class="label">Partial Packs</div>
                    <div class="value" style="color: var(--yellow);">18</div>
                    <div class="note">Evidence exists but is incomplete, stale, or not fully linked.</div>
                </div>

                <div class="metric">
                    <div class="label">Failed Packs</div>
                    <div class="value" style="color: var(--red);">11</div>
                    <div class="note">Evidence missing for critical governance domains.</div>
                </div>

                <div class="metric">
                    <div class="label">Audit-Ready Packs</div>
                    <div class="value" style="color: var(--blue);">9</div>
                    <div class="note">Packs strong enough to support audit questioning.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Gaps</div>
                    <div class="value" style="color: var(--orange);">27</div>
                    <div class="note">Open evidence items requiring remediation or exception tracking.</div>
                </div>
            </section>

            <section class="section">
                <h2>Evidence Pack Answer</h2>
                <p>
                    This builder answers whether the CI has enough proof to support the trust claim.
                </p>

                <div class="answer">
                    <strong>Current evidence interpretation:</strong>
                    A CI should not be described as trusted unless its evidence pack can prove ownership, support routing, lifecycle state, access path, relationships, operational purpose, review cadence, and readiness decision. The weakest packs are attached to hidden dependencies, OOS records, cutover-sensitive systems, and access paths where formal procedure evidence is still missing.
                </div>
            </section>

            <section class="section">
                <h2>Evidence Pack Components</h2>
                <p>
                    CITrust™ organizes evidence into reusable domains so every CI can be defended consistently.
                </p>

                <div class="pack-grid">
                    <div class="pack-card">
                        <h3><span class="badge blue">Identity Evidence</span></h3>
                        <p>CI name, class, asset identity, operational purpose, source authority, and duplicate-resolution evidence.</p>
                    </div>

                    <div class="pack-card">
                        <h3><span class="badge green">Ownership Evidence</span></h3>
                        <p>CI owner, support group, LCM, escalation path, and stakeholder attestation evidence.</p>
                    </div>

                    <div class="pack-card">
                        <h3><span class="badge purple">Access Evidence</span></h3>
                        <p>MyAccess roles, approver groups, admin access path, vendor route, jump server route, and access review proof.</p>
                    </div>

                    <div class="pack-card">
                        <h3><span class="badge orange">Lifecycle Evidence</span></h3>
                        <p>Active state, OOS state, retirement, closure proof, access deactivation, cutover, and transition evidence.</p>
                    </div>

                    <div class="pack-card">
                        <h3><span class="badge yellow">Operational Evidence</span></h3>
                        <p>SOP linkage, backup review, audit trail review, operational review cadence, and support procedure evidence.</p>
                    </div>

                    <div class="pack-card">
                        <h3><span class="badge blue">Relationship Evidence</span></h3>
                        <p>Owned by, supported by, depends on, hosted on, accessed through, approved by, and closed by evidence.</p>
                    </div>

                    <div class="pack-card">
                        <h3><span class="badge green">Decision Evidence</span></h3>
                        <p>Decision ledger, readiness threshold, maturity level, assurance case, exception status, and attestation decision.</p>
                    </div>

                    <div class="pack-card">
                        <h3><span class="badge red">Gap Evidence</span></h3>
                        <p>Open evidence gaps, blocked controls, remediation actions, exception register entries, and closure conditions.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Evidence Pack Matrix</h2>
                <p>
                    This matrix shows which evidence packs are complete, partial, or blocked.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Identity</th>
                            <th>Owner / Support / LCM</th>
                            <th>MyAccess / Access</th>
                            <th>Lifecycle</th>
                            <th>Operational Evidence</th>
                            <th>Decision Evidence</th>
                            <th>Pack Decision</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-green">Logged</span></td>
                            <td><span class="badge green">Complete Pack</span></td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td><span class="badge soft-yellow">Procedure Needed</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td><span class="badge yellow">Partial Pack</span></td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">Cutover-sensitive BMS dependency</span></td>
                            <td><span class="badge soft-yellow">Cutover Context</span></td>
                            <td><span class="badge soft-yellow">Support Pending</span></td>
                            <td><span class="badge soft-yellow">Role Partial</span></td>
                            <td><span class="badge soft-yellow">Cutover Active</span></td>
                            <td><span class="badge soft-yellow">Cutover Evidence</span></td>
                            <td><span class="badge soft-yellow">Watchlist</span></td>
                            <td><span class="badge yellow">Conditional Pack</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-yellow">Reconcile</span></td>
                            <td><span class="badge soft-yellow">Support Pending</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-green">Operational</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Conditional</span></td>
                            <td><span class="badge yellow">Partial Pack</span></td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td><span class="badge soft-green">Complete</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Active</span></td>
                            <td><span class="badge soft-green">Available</span></td>
                            <td><span class="badge soft-yellow">Near Complete</span></td>
                            <td><span class="badge yellow">Near Complete</span></td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Access Removal Missing</span></td>
                            <td><span class="badge soft-red">Closure Needed</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-red">Blocked</span></td>
                            <td><span class="badge red">Failed Pack</span></td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-yellow">Discovered</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Blocked</span></td>
                            <td><span class="badge red">No Pack</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Evidence Pack Decision Logic</h2>
                <p>
                    A CI evidence pack must prove the claim, not merely list documents.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Evidence Pack Complete</h3>
                        <ul>
                            <li>CI identity and class are clear.</li>
                            <li>Owner, support group, and LCM evidence are available.</li>
                            <li>MyAccess or access-route evidence is mapped where applicable.</li>
                            <li>Lifecycle state is supported by current evidence.</li>
                            <li>Operational evidence is linked and reviewable.</li>
                            <li>Decision ledger, assurance case, and attestation are aligned.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Evidence Pack Failed</h3>
                        <ul>
                            <li>Owner, support group, LCM, or access route is missing.</li>
                            <li>OOS or retired state lacks closure evidence.</li>
                            <li>Access deactivation evidence is missing where required.</li>
                            <li>Hidden dependency has no governed candidate record.</li>
                            <li>Evidence is stale, disconnected, or contradictory.</li>
                            <li>Leadership cannot defend the trust claim during audit or review.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Evidence Pack Closure Queue</h2>
                <p>
                    These actions complete weak evidence packs before trust, attestation, passport, or submission review.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Evidence Gap</th>
                            <th>Why It Matters</th>
                            <th>Required Evidence</th>
                            <th>Expected Pack Upgrade</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no evidence pack.</td>
                            <td>Recurring operational review dependency has no governed proof model.</td>
                            <td>Candidate record, owner, support group, LCM, access path, backup review evidence, and cadence owner.</td>
                            <td>No Pack → Partial Pack</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment lacks closure and access removal evidence.</td>
                            <td>Lifecycle trust cannot be defended without closure proof.</td>
                            <td>Closure evidence, access deactivation proof, lifecycle owner, and decision ledger entry.</td>
                            <td>Failed Pack → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS cutover evidence pack is incomplete.</td>
                            <td>Cutover trust requires support, access, jump path, dependency, and evidence alignment.</td>
                            <td>Support confirmation, MyAccess role, jump path evidence, cutover evidence, and owner attestation.</td>
                            <td>Conditional Pack → Complete Pack</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Access procedure evidence missing for jump server route.</td>
                            <td>Admin and vendor access must be defensible during audit or inspection-style questioning.</td>
                            <td>Admin access procedure, vendor access route, access review evidence, and support routing context.</td>
                            <td>Partial Pack → Audit-Ready Pack</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, create ServiceNow CIs, update CMDB records, approve access, or approve changes in this demo. This evidence pack builder is a governance assurance overlay for assembling identity evidence, ownership evidence, support evidence, LCM evidence, MyAccess evidence, lifecycle evidence, operational evidence, relationship evidence, decision evidence, audit-readiness evidence, passport evidence, submission-pack readiness, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_EVIDENCE_PACK_BUILDER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Evidence Pack Builder installed.")
