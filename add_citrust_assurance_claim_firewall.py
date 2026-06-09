from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_ASSURANCE_CLAIM_FIREWALL_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/assurance-claim-firewall")'
ROUTE_ALIAS = '@app.route("/citrust/trust-claim-firewall")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Assurance Claim Firewall already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_ASSURANCE_CLAIM_FIREWALL_V1_ACTIVE
# ============================================================

@app.route("/citrust/assurance-claim-firewall")
@app.route("/citrust/trust-claim-firewall")
def citrust_assurance_claim_firewall():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Assurance Claim Firewall</title>
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
                    radial-gradient(circle at top right, rgba(255,92,112,0.18), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(49,208,125,0.11), transparent 30%),
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
                max-width: 1160px;
                margin-top: 14px;
            }

            .positioning {
                margin-top: 18px;
                padding: 16px 18px;
                border: 1px solid rgba(255,92,112,0.38);
                background: rgba(255,92,112,0.10);
                border-radius: 16px;
                color: #ffe5e9;
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
                border: 1px solid rgba(92,200,255,0.38);
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

            .soft-orange {
                color: #ffe8c9;
                background: rgba(255,184,107,0.14);
                border: 1px solid rgba(255,184,107,0.36);
            }

            .soft-purple {
                color: #eee7ff;
                background: rgba(180,156,255,0.13);
                border: 1px solid rgba(180,156,255,0.35);
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
                min-height: 155px;
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

            .claim-strip {
                display: grid;
                grid-template-columns: 1fr 1fr 1fr;
                gap: 16px;
                margin-top: 16px;
            }

            .claim-box {
                border: 1px solid rgba(92,200,255,0.30);
                background: rgba(92,200,255,0.08);
                border-radius: 18px;
                padding: 18px;
            }

            .claim-box h3 {
                margin: 0 0 8px 0;
                font-size: 17px;
            }

            .claim-box p {
                margin: 0;
                color: #d9f3ff;
                font-size: 14px;
                line-height: 1.6;
            }

            .footer {
                color: var(--muted);
                font-size: 12px;
                margin-top: 22px;
                line-height: 1.6;
            }

            @media (max-width: 1180px) {
                .kpis, .cards, .two-col, .claim-strip {
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
                <h1>CITrust™ Assurance Claim Firewall</h1>

                <div class="subtitle">
                    A world-class governance claim firewall that prevents unsupported executive assurance statements by checking every readiness, trust, control, access, lifecycle, exception, certificate, and audit-defense claim against evidence, owner accountability, maturity, freshness, residual risk, and decision-ledger rationale.
                </div>

                <div class="positioning">
                    <strong>Category-defining capability:</strong>
                    Most organizations allow people to say “ready,” “controlled,” or “trusted” before the evidence is strong enough. CITrust™ Assurance Claim Firewall acts as a pre-claim defense layer: if the proof is missing, stale, conditional, ownerless, or not reviewed, the claim is blocked, downgraded, or forced into limitation language.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/trust-failure-premortem-engine">Trust Failure Pre-Mortem</a>
                    <a href="/citrust/executive-assurance-digital-twin">Assurance Digital Twin</a>
                    <a href="/citrust/executive-assurance-decision-ledger">Assurance Decision Ledger</a>
                    <a href="/citrust/control-audit-defense-pack">Control Defense Pack</a>
                    <a href="/citrust/executive-control-assurance-briefing">Executive Briefing</a>
                    <a href="/citrust/control-assurance-attestation">Control Attestation</a>
                    <a href="/citrust/executive-dashboard">Executive Dashboard</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Claims Screened</div>
                    <div class="value">41</div>
                    <div class="note">Executive, audit, readiness, certificate, and control claims tested against evidence.</div>
                </div>

                <div class="metric">
                    <div class="label">Claims Approved</div>
                    <div class="value" style="color: var(--green);">13</div>
                    <div class="note">Claims fully supported by evidence, maturity, ownership, and decision rationale.</div>
                </div>

                <div class="metric">
                    <div class="label">Claims Downgraded</div>
                    <div class="value" style="color: var(--yellow);">16</div>
                    <div class="note">Claims converted from absolute to conditional language.</div>
                </div>

                <div class="metric">
                    <div class="label">Claims Blocked</div>
                    <div class="value" style="color: var(--red);">7</div>
                    <div class="note">Claims not safe to make because proof is missing or maturity is too weak.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Gaps Found</div>
                    <div class="value" style="color: var(--orange);">11</div>
                    <div class="note">Missing proof items discovered before leadership reliance.</div>
                </div>

                <div class="metric">
                    <div class="label">False Confidence Prevented</div>
                    <div class="value" style="color: var(--blue);">82%</div>
                    <div class="note">Demo estimate of unsupported claim risk reduced by the firewall.</div>
                </div>
            </section>

            <section class="section">
                <h2>Assurance Claim Firewall Answer</h2>
                <p>
                    This page answers whether leadership is allowed to make a claim based on the actual assurance evidence.
                </p>

                <div class="answer">
                    <strong>Current firewall interpretation:</strong>
                    CITrust™ should not allow a CI, control, certificate, access path, cutover state, or support model to be described as ready, trusted, controlled, or audit defensible unless evidence confirms the claim. If proof is incomplete, the claim must be downgraded to conditional. If ownership, evidence, or maturity is too weak, the claim must be blocked.
                </div>
            </section>

            <section class="section">
                <h2>Claim Firewall Engines</h2>
                <p>
                    CITrust™ transforms vague confidence language into governed, evidence-tested assurance statements.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Claim-to-Evidence Resolver</h3>
                        <p>Maps every executive statement to the required proof: access, support, lifecycle, exception, certificate, cutover, owner, and review evidence.</p>
                    </div>

                    <div class="card">
                        <h3>Unsupported Claim Blocker</h3>
                        <p>Blocks claims where the evidence is missing, stale, ownerless, manually chased, or not strong enough to survive audit questioning.</p>
                    </div>

                    <div class="card">
                        <h3>Conditional Language Generator</h3>
                        <p>Converts overstated claims into accurate limitation language, such as “conditionally ready,” “rely with monitoring,” or “not yet defensible.”</p>
                    </div>

                    <div class="card">
                        <h3>Executive Reliance Gatekeeper</h3>
                        <p>Prevents leadership from relying on a control unless maturity, evidence, decision rationale, and residual-risk position support reliance.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Claim Firewall Snapshot</h2>
                <p>
                    This is the executive “can we safely say this?” view.
                </p>

                <div class="claim-strip">
                    <div class="claim-box">
                        <h3><span class="badge green">Allowed Claim</span> Lifecycle Closure</h3>
                        <p>
                            Safe to say OOS and retired CI trust is controlled where closure evidence, access deactivation proof, lifecycle decision, and decision-ledger rationale are complete.
                        </p>
                    </div>

                    <div class="claim-box">
                        <h3><span class="badge yellow">Downgraded Claim</span> Access Assurance</h3>
                        <p>
                            Do not say access is fully controlled. Say access assurance is improving but conditional until admin/vendor procedure and access review proof are current.
                        </p>
                    </div>

                    <div class="claim-box">
                        <h3><span class="badge red">Blocked Claim</span> Support Reliability</h3>
                        <p>
                            Do not claim support routing is reliable until support group, resolver path, LCM, escalation owner, and evidence location become mandatory.
                        </p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Assurance Claim Firewall Matrix</h2>
                <p>
                    This matrix tests common executive claims before they are used in leadership, audit, or governance communication.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Proposed Claim</th>
                            <th>Required Proof</th>
                            <th>Current Evidence State</th>
                            <th>Firewall Decision</th>
                            <th>Approved Language</th>
                            <th>Blocked Language</th>
                            <th>Required Action</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>“Lifecycle closure is controlled.”</strong></td>
                            <td>Closure evidence, access deactivation proof, lifecycle decision, owner acceptance, decision-ledger rationale.</td>
                            <td>Evidence complete and gate operating.</td>
                            <td><span class="badge green">Allow</span></td>
                            <td>Lifecycle closure is controlled where closure and access-removal evidence are mandatory.</td>
                            <td>All retired or OOS CIs are automatically safe.</td>
                            <td>Maintain trend review and closure monitoring.</td>
                        </tr>

                        <tr>
                            <td><strong>“This CI is cutover ready.”</strong></td>
                            <td>Support, access, vendor handoff, rollback readiness, recovery attestation, post-cutover verification.</td>
                            <td>Evidence pack exists but recovery and verification may remain incomplete.</td>
                            <td><span class="badge yellow">Downgrade</span></td>
                            <td>This CI is conditionally cutover ready pending recovery attestation and post-cutover verification.</td>
                            <td>This CI is fully ready for cutover.</td>
                            <td>Complete recovery attestation and post-cutover verification.</td>
                        </tr>

                        <tr>
                            <td><strong>“Access governance is fully defensible.”</strong></td>
                            <td>MyAccess role, approver group, admin/vendor procedure, jump path, access review proof, post-access verification.</td>
                            <td>MyAccess mapping improving but procedure and review proof can be stale.</td>
                            <td><span class="badge yellow">Downgrade</span></td>
                            <td>Access governance is conditionally defensible where full access evidence is current.</td>
                            <td>All access paths are fully governed.</td>
                            <td>Block renewal unless full access evidence bundle is attached.</td>
                        </tr>

                        <tr>
                            <td><strong>“Support routing is reliable.”</strong></td>
                            <td>Support group, resolver path, LCM, escalation owner, evidence location, cadence, reviewer acceptance.</td>
                            <td>Evidence remains inconsistent and not mandatory.</td>
                            <td><span class="badge red">Block</span></td>
                            <td>Support routing requires further evidence before reliance.</td>
                            <td>Support routing is reliable and fully controlled.</td>
                            <td>Make support and LCM evidence mandatory before candidate approval.</td>
                        </tr>

                        <tr>
                            <td><strong>“Hidden dependencies are controlled.”</strong></td>
                            <td>Candidate record, owner, support, LCM, access path, evidence model, review cadence, verification proof.</td>
                            <td>Candidate creation requirement exists but intake remains partly manual.</td>
                            <td><span class="badge orange">Escalate</span></td>
                            <td>Hidden dependency intake is improving but must become mandatory before reliance.</td>
                            <td>All hidden dependencies are controlled.</td>
                            <td>Force candidate creation before exception, certificate, or trust review.</td>
                        </tr>

                        <tr>
                            <td><strong>“Exceptions are governed.”</strong></td>
                            <td>Exception owner, expiry date, escalation owner, closure evidence, residual-risk statement, decision-ledger entry.</td>
                            <td>Owner and expiry visible; escalation owner not consistently enforced.</td>
                            <td><span class="badge yellow">Downgrade</span></td>
                            <td>Exceptions are visible and partially governed, with escalation ownership still requiring enforcement.</td>
                            <td>All exceptions are fully controlled.</td>
                            <td>Require escalation owner before exception approval.</td>
                        </tr>

                        <tr>
                            <td><strong>“Certificate-ready means the CI can be trusted.”</strong></td>
                            <td>Certificate status, evidence freshness, exception state, access review, lifecycle state, support readiness, trust monitoring.</td>
                            <td>Certificate lifecycle visibility exists but must remain tied to evidence freshness.</td>
                            <td><span class="badge yellow">Condition</span></td>
                            <td>Certificate-ready supports trust only when evidence remains current and exceptions are controlled.</td>
                            <td>Certificate-ready always means fully trusted.</td>
                            <td>Link certificate state to evidence freshness and continuous trust monitoring.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Claim Firewall Decision Logic</h2>
                <p>
                    The firewall protects leadership from saying more than the evidence can defend.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Claim Can Pass</h3>
                        <ul>
                            <li>Evidence is complete, current, and reviewable.</li>
                            <li>Owner, reviewer, and escalation path are clear.</li>
                            <li>Control maturity supports the claim.</li>
                            <li>Exceptions and residual risk are disclosed.</li>
                            <li>Decision ledger explains the reliance decision.</li>
                            <li>Claim language matches evidence strength.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Claim Must Be Blocked</h3>
                        <ul>
                            <li>Evidence is missing, stale, informal, or optional.</li>
                            <li>Claim says “fully ready” where status is conditional.</li>
                            <li>Owner, support, access, or escalation role is unclear.</li>
                            <li>Hidden dependency can bypass candidate review.</li>
                            <li>Certificate state is not tied to evidence freshness.</li>
                            <li>Statement would create false executive confidence.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Claim Firewall Action Queue</h2>
                <p>
                    These actions turn blocked or downgraded claims into defensible statements.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Blocked / Downgraded Claim</th>
                            <th>Why It Is Unsafe</th>
                            <th>Evidence Required To Pass</th>
                            <th>Future Approved Claim</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Support routing is reliable.</td>
                            <td>Support and LCM evidence is not mandatory enough to defend reliance.</td>
                            <td>Support group, resolver path, LCM, escalation owner, evidence location, cadence, reviewer acceptance.</td>
                            <td>Support routing is evidence-backed and operationally reviewable.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Hidden dependencies are controlled.</td>
                            <td>Manual intake can allow dependencies to bypass CI candidate governance.</td>
                            <td>Candidate record, owner, support, access, evidence model, cadence, verification proof.</td>
                            <td>Hidden dependencies are governed through mandatory candidate intake.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Access governance is fully defensible.</td>
                            <td>Procedure, review proof, and post-access verification may not be current.</td>
                            <td>MyAccess mapping, approver group, admin/vendor procedure, jump path, access review proof, post-access verification.</td>
                            <td>Access governance is defensible for CIs with current full access proof.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>This CI is cutover ready.</td>
                            <td>Cutover claim may overstate readiness if recovery and verification evidence are incomplete.</td>
                            <td>Vendor handoff, rollback readiness, recovery attestation, support evidence, access evidence, post-cutover verification.</td>
                            <td>This CI is cutover ready with complete recovery and verification evidence.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This assurance claim firewall is a governance assurance overlay for unsupported-claim prevention, executive reliance protection, claim-to-evidence mapping, conditional-language enforcement, false-confidence reduction, certificate readiness defense, CMDB-readiness defense, audit survivability, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_ASSURANCE_CLAIM_FIREWALL_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Assurance Claim Firewall installed.")
