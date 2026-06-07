from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_VENDOR_HANDOFF_READINESS_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/vendor-handoff-readiness")'
ROUTE_ALIAS = '@app.route("/citrust/vendor-support-handoff")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Vendor Handoff Readiness Console already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_VENDOR_HANDOFF_READINESS_V1_ACTIVE
# ============================================================

@app.route("/citrust/vendor-handoff-readiness")
@app.route("/citrust/vendor-support-handoff")
def citrust_vendor_handoff_readiness():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Vendor Handoff Readiness Console</title>
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
                    radial-gradient(circle at top right, rgba(255,184,107,0.14), transparent 28%),
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
                border: 1px solid rgba(255,184,107,0.38);
                background: rgba(255,184,107,0.10);
                color: #ffe8c9;
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
                min-height: 150px;
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
                <h1>CITrust™ Vendor Handoff Readiness Console</h1>

                <div class="subtitle">
                    Validates whether vendor support can be safely and defensibly handed off through approved access routes, jump-server controls, support ownership, MyAccess approval, admin procedure evidence, issue escalation, and post-support evidence capture.
                </div>

                <div class="positioning">
                    <strong>Vendor handoff boundary:</strong>
                    CITrust™ does not approve vendor access, create ServiceNow tickets, update CMDB records, or replace MyAccess in this demo. It validates whether vendor support paths are governed, evidence-backed, routed through the correct support model, and defensible during audit or operational review.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/readiness-command-center">Command Center</a>
                    <a href="/citrust/support-group-readiness">Support Group Readiness</a>
                    <a href="/citrust/myaccess-readiness">MyAccess Readiness</a>
                    <a href="/citrust/escalation-path-console">Escalation Path</a>
                    <a href="/citrust/evidence-pack-builder">Evidence Pack Builder</a>
                    <a href="/citrust/audit-question-bank">Audit Question Bank</a>
                    <a href="/citrust/remediation-board">Remediation Board</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Vendor-Sensitive CIs</div>
                    <div class="value">18</div>
                    <div class="note">CIs that may require vendor, admin, or third-party support handoff.</div>
                </div>

                <div class="metric">
                    <div class="label">Handoff-Ready</div>
                    <div class="value" style="color: var(--green);">7</div>
                    <div class="note">Vendor path, support owner, access route, and evidence model are defensible.</div>
                </div>

                <div class="metric">
                    <div class="label">Conditional Handoff</div>
                    <div class="value" style="color: var(--yellow);">8</div>
                    <div class="note">Vendor support is known but access, procedure, or evidence remains partial.</div>
                </div>

                <div class="metric">
                    <div class="label">Blocked Handoff</div>
                    <div class="value" style="color: var(--red);">3</div>
                    <div class="note">Vendor support should not proceed without governance closure.</div>
                </div>

                <div class="metric">
                    <div class="label">Procedure Gaps</div>
                    <div class="value" style="color: var(--orange);">6</div>
                    <div class="note">Admin/vendor procedure evidence missing or incomplete.</div>
                </div>

                <div class="metric">
                    <div class="label">Jump Path Gaps</div>
                    <div class="value" style="color: var(--blue);">4</div>
                    <div class="note">Jump-server, remote-access, or controlled access route requires confirmation.</div>
                </div>
            </section>

            <section class="section">
                <h2>Vendor Handoff Answer</h2>
                <p>
                    This console answers whether vendor support can be performed without creating access, support, audit, or operational governance exposure.
                </p>

                <div class="answer">
                    <strong>Current vendor-handoff interpretation:</strong>
                    Vendor support should not be treated as safe simply because the vendor knows the system. CITrust™ requires a clear support owner, approved access path, MyAccess or access-routing evidence, jump-server route where applicable, admin procedure evidence, issue record, post-support evidence capture, and escalation owner before vendor handoff can be considered defensible.
                </div>
            </section>

            <section class="section">
                <h2>Vendor Handoff Control Domains</h2>
                <p>
                    CITrust™ separates vendor handoff into the controls that determine whether third-party support is governed.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Vendor Identity</h3>
                        <p>Confirms which vendor, contractor, service provider, or third-party support path is associated with the CI.</p>
                    </div>

                    <div class="card">
                        <h3>Access Route</h3>
                        <p>Validates whether support uses MyAccess, jump server, admin route, supervised access, or approved remote path.</p>
                    </div>

                    <div class="card">
                        <h3>Support Ownership</h3>
                        <p>Confirms internal owner, support group, LCM, and escalation owner remain accountable during vendor activity.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Capture</h3>
                        <p>Ensures request evidence, access approval, work performed, change impact, and post-support closure proof are captured.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Vendor Handoff Readiness Matrix</h2>
                <p>
                    This matrix shows whether vendor handoff is ready, conditional, or blocked for key CI records.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Configuration Item</th>
                            <th>Vendor / Third Party</th>
                            <th>Internal Owner</th>
                            <th>Access Route</th>
                            <th>Support Handoff</th>
                            <th>Evidence Required</th>
                            <th>Handoff Decision</th>
                            <th>Next Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Blue Mountain RAM</strong><br><span style="color: var(--muted);">Asset and calibration governance system</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-green">Mapped</span></td>
                            <td><span class="badge soft-green">Defined</span></td>
                            <td>Support and access evidence maintained through periodic review.</td>
                            <td><span class="badge green">Handoff-Ready</span></td>
                            <td>Maintain periodic vendor/support review.</td>
                        </tr>

                        <tr>
                            <td><strong>Niagara BMS Server</strong><br><span style="color: var(--muted);">BMS / facility support dependency</span></td>
                            <td><span class="badge soft-green">Vendor Known</span></td>
                            <td><span class="badge soft-yellow">Cutover Owner</span></td>
                            <td><span class="badge soft-yellow">Jump Path Partial</span></td>
                            <td><span class="badge soft-yellow">Support Pending</span></td>
                            <td>Vendor handoff evidence, jump path evidence, support group, access role, cutover record.</td>
                            <td><span class="badge yellow">Conditional Handoff</span></td>
                            <td>Finalize support group, jump-server route, vendor access evidence, and cutover escalation path.</td>
                        </tr>

                        <tr>
                            <td><strong>Jump Server Access Path</strong><br><span style="color: var(--muted);">Controlled admin and vendor access route</span></td>
                            <td><span class="badge soft-blue">Access Control Layer</span></td>
                            <td><span class="badge soft-green">Infrastructure</span></td>
                            <td><span class="badge soft-green">Controlled Route</span></td>
                            <td><span class="badge soft-yellow">Procedure Needed</span></td>
                            <td>Admin/vendor access procedure, access review evidence, support routing, approval path.</td>
                            <td><span class="badge yellow">Procedure Conditional</span></td>
                            <td>Attach admin/vendor procedure and confirm backup support owner.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1803</strong><br><span style="color: var(--muted);">Operational manufacturing equipment</span></td>
                            <td><span class="badge soft-yellow">Likely Vendor</span></td>
                            <td><span class="badge soft-green">Operational Owner</span></td>
                            <td><span class="badge soft-yellow">Partial</span></td>
                            <td><span class="badge soft-yellow">Pending</span></td>
                            <td>Vendor support path, internal support group, access evidence, evidence location.</td>
                            <td><span class="badge yellow">Conditional Handoff</span></td>
                            <td>Reconcile vendor path, support group, LCM, and access/evidence model.</td>
                        </tr>

                        <tr>
                            <td><strong>Empower Lab System</strong><br><span style="color: var(--muted);">GMP lab application dependency</span></td>
                            <td><span class="badge soft-green">Known</span></td>
                            <td><span class="badge soft-green">Confirmed</span></td>
                            <td><span class="badge soft-yellow">Approver Check</span></td>
                            <td><span class="badge soft-green">Defined</span></td>
                            <td>MyAccess approver evidence and vendor/admin route evidence.</td>
                            <td><span class="badge yellow">Near Handoff-Ready</span></td>
                            <td>Confirm MyAccess approver group and access route evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Speedy Glove 1802</strong><br><span style="color: var(--muted);">Out-of-service equipment</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Unclear</span></td>
                            <td><span class="badge soft-red">Not Defensible</span></td>
                            <td><span class="badge soft-red">Closure Missing</span></td>
                            <td>Closure evidence, vendor disengagement or support closure, access removal proof.</td>
                            <td><span class="badge red">Blocked Handoff</span></td>
                            <td>Confirm closure owner, access removal, support closure, and lifecycle evidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Local Backup Review Workstation</strong><br><span style="color: var(--muted);">Monthly backup review dependency</span></td>
                            <td><span class="badge soft-red">Unknown</span></td>
                            <td><span class="badge soft-red">Missing</span></td>
                            <td><span class="badge soft-red">Not Mapped</span></td>
                            <td><span class="badge soft-red">No Handoff Model</span></td>
                            <td>Candidate record, owner, support group, LCM, access path, review evidence.</td>
                            <td><span class="badge red">No Vendor Handoff Model</span></td>
                            <td>Create governed candidate and define vendor/admin/support model if applicable.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Vendor Handoff Decision Logic</h2>
                <p>
                    Vendor support must remain governed even when the vendor performs the technical work.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Vendor Handoff-Ready</h3>
                        <ul>
                            <li>Vendor or third-party support path is known.</li>
                            <li>Internal owner and support group remain accountable.</li>
                            <li>Access route is approved, controlled, and evidence-backed.</li>
                            <li>Jump server or admin route is defined where applicable.</li>
                            <li>Escalation and handoff owner are documented.</li>
                            <li>Post-support evidence capture and closure path are defined.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Vendor Handoff-Blocked</h3>
                        <ul>
                            <li>Vendor access route is informal or unknown.</li>
                            <li>Internal support owner is missing.</li>
                            <li>MyAccess approver or admin route is not defensible.</li>
                            <li>Jump path is required but not confirmed.</li>
                            <li>OOS or retired CI lacks vendor/support closure evidence.</li>
                            <li>Support would proceed without audit-defensible proof.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Vendor Handoff Remediation Queue</h2>
                <p>
                    These actions close vendor handoff gaps before support, access, or audit exposure occurs.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Handoff Gap</th>
                            <th>Why It Matters</th>
                            <th>Required Action</th>
                            <th>Expected Readiness Upgrade</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden backup review workstation has no vendor/admin support model.</td>
                            <td>Operational dependency may be supported informally without governance.</td>
                            <td>Create governed candidate and define owner, support group, LCM, access route, and vendor/admin model.</td>
                            <td>No Handoff Model → Candidate Review</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS equipment lacks vendor/support closure evidence.</td>
                            <td>Support closure and access removal must be defensible before lifecycle closure.</td>
                            <td>Attach closure evidence, confirm access removal, and document vendor/support disengagement.</td>
                            <td>Blocked Handoff → Closed / Defensible</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>BMS vendor handoff depends on partial jump path and support routing.</td>
                            <td>Cutover-sensitive vendor support must route through controlled access and support ownership.</td>
                            <td>Confirm vendor handoff path, jump server route, support group, MyAccess role, and cutover evidence.</td>
                            <td>Conditional Handoff → Handoff-Ready</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Admin/vendor access procedure evidence missing.</td>
                            <td>Privileged support cannot be audit-defensible without procedure and approval evidence.</td>
                            <td>Attach admin/vendor procedure, approval path, access review evidence, and escalation owner.</td>
                            <td>Procedure Conditional → Audit-Ready</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, MyAccess, vendor management, access governance, audit systems, or human approval. This vendor handoff readiness console is a governance assurance overlay for vendor support readiness, third-party support routing, jump-server routing, admin access defensibility, vendor access evidence, internal support ownership, escalation ownership, post-support evidence capture, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_VENDOR_HANDOFF_READINESS_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Vendor Handoff Readiness Console installed.")
