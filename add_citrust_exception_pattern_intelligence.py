from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_EXCEPTION_PATTERN_INTELLIGENCE_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/exception-pattern-intelligence")'
ROUTE_ALIAS = '@app.route("/citrust/certificate-exception-patterns")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Exception Pattern Intelligence already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_EXCEPTION_PATTERN_INTELLIGENCE_V1_ACTIVE
# ============================================================

@app.route("/citrust/exception-pattern-intelligence")
@app.route("/citrust/certificate-exception-patterns")
def citrust_exception_pattern_intelligence():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Exception Pattern Intelligence</title>
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
                    radial-gradient(circle at top right, rgba(255,184,107,0.15), transparent 28%),
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
                <h1>CITrust™ Exception Pattern Intelligence</h1>

                <div class="subtitle">
                    Detects recurring certificate-exception patterns across Configuration Items so governance teams can distinguish isolated gaps from systemic CMDB, MyAccess, support-routing, lifecycle, evidence, and hidden-dependency failures.
                </div>

                <div class="positioning">
                    <strong>Pattern-intelligence boundary:</strong>
                    CITrust™ does not update ServiceNow, approve access, close exceptions, or replace human governance in this demo. It analyzes recurring exception signals and surfaces systemic governance weaknesses that should be corrected upstream before more CIs become conditional, suspended, or not certifiable.
                </div>

                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/exception-closure-attestation">Exception Closure</a>
                    <a href="/citrust/exception-expiry-monitor">Exception Expiry</a>
                    <a href="/citrust/certificate-exception-review-board">Exception Review Board</a>
                    <a href="/citrust/certificate-lifecycle-command-center">Certificate Command Center</a>
                    <a href="/citrust/governance-debt-register">Governance Debt</a>
                    <a href="/citrust/risk-heatmap">Risk Heatmap</a>
                    <a href="/citrust/decision-ledger">Decision Ledger</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric">
                    <div class="label">Pattern Signals</div>
                    <div class="value">37</div>
                    <div class="note">Recurring exception signals detected across certificate-tracked CIs.</div>
                </div>

                <div class="metric">
                    <div class="label">Access Patterns</div>
                    <div class="value" style="color: var(--orange);">11</div>
                    <div class="note">Repeated MyAccess, approver, admin, vendor, or jump-path evidence gaps.</div>
                </div>

                <div class="metric">
                    <div class="label">Support Patterns</div>
                    <div class="value" style="color: var(--yellow);">8</div>
                    <div class="note">Repeated support group, resolver, escalation, or LCM mapping gaps.</div>
                </div>

                <div class="metric">
                    <div class="label">Lifecycle Patterns</div>
                    <div class="value" style="color: var(--red);">6</div>
                    <div class="note">Repeated OOS, closure, retirement, or access-removal evidence failures.</div>
                </div>

                <div class="metric">
                    <div class="label">Evidence Patterns</div>
                    <div class="value" style="color: var(--blue);">9</div>
                    <div class="note">Repeated stale evidence, missing evidence, or proof-to-reality mismatch.</div>
                </div>

                <div class="metric">
                    <div class="label">Systemic Risks</div>
                    <div class="value" style="color: var(--purple);">5</div>
                    <div class="note">Patterns likely caused by process design rather than isolated CI defects.</div>
                </div>
            </section>

            <section class="section">
                <h2>Exception Pattern Answer</h2>
                <p>
                    This console answers whether CI certificate exceptions are isolated one-off issues or signs of a broader governance weakness.
                </p>

                <div class="answer">
                    <strong>Current pattern interpretation:</strong>
                    Repeated exceptions should not be treated as independent noise. If multiple CIs show the same missing support group, stale access evidence, unclear lifecycle closure, hidden dependency, or incomplete evidence pack, CITrust™ should escalate the pattern as a systemic governance gap requiring upstream correction.
                </div>
            </section>

            <section class="section">
                <h2>Exception Pattern Domains</h2>
                <p>
                    CITrust™ groups exception patterns into domains that reveal where the governance operating model is weakening.
                </p>

                <div class="cards">
                    <div class="card">
                        <h3>Access Exception Pattern</h3>
                        <p>Recurring MyAccess role, approver group, privileged access, vendor route, jump path, or access-removal evidence gaps.</p>
                    </div>

                    <div class="card">
                        <h3>Support Exception Pattern</h3>
                        <p>Recurring support group, resolver path, escalation owner, LCM, backup owner, or vendor support accountability gaps.</p>
                    </div>

                    <div class="card">
                        <h3>Lifecycle Exception Pattern</h3>
                        <p>Recurring active, cutover, OOS, retired, closed, rollback, or post-change lifecycle proof failures.</p>
                    </div>

                    <div class="card">
                        <h3>Evidence Exception Pattern</h3>
                        <p>Recurring stale evidence, incomplete evidence packs, broken lineage, overdue reviews, or certificate proof mismatch.</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>CI Exception Pattern Matrix</h2>
                <p>
                    This matrix shows repeated exception patterns and the systemic action required.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Pattern</th>
                            <th>Affected CIs</th>
                            <th>Observed Signal</th>
                            <th>Likely Root Cause</th>
                            <th>Pattern Severity</th>
                            <th>Systemic Action</th>
                            <th>Expected Governance Result</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><strong>Access Evidence Pattern</strong></td>
                            <td>Niagara BMS, Jump Server, Empower</td>
                            <td>MyAccess role, approver group, admin/vendor procedure, or access review evidence is partial.</td>
                            <td>Access governance evidence is not consistently linked to CI certificate state.</td>
                            <td><span class="badge orange">High</span></td>
                            <td>Define mandatory access-evidence bundle for every certificate-ready CI.</td>
                            <td>Reduced access exceptions and faster certificate renewal.</td>
                        </tr>

                        <tr>
                            <td><strong>Support Routing Pattern</strong></td>
                            <td>Niagara BMS, Speedy Glove 1803, local dependencies</td>
                            <td>Support group, resolver path, escalation chain, or LCM assignment remains partial.</td>
                            <td>Support model is being discovered after CI candidate creation instead of before trust decision.</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Require support group and LCM evidence before certificate review.</td>
                            <td>Fewer conditional support certificates and better incident-routing confidence.</td>
                        </tr>

                        <tr>
                            <td><strong>Lifecycle Closure Pattern</strong></td>
                            <td>Speedy Glove 1802 and other OOS-style records</td>
                            <td>OOS closure, access removal, closure owner, and lifecycle decision evidence are missing.</td>
                            <td>Lifecycle closure is not tied tightly enough to CI certificate suspension and restoration logic.</td>
                            <td><span class="badge red">Critical</span></td>
                            <td>Create lifecycle closure evidence gate before OOS certificate can be restored or closed.</td>
                            <td>Reduced orphan exposure and stronger audit defensibility.</td>
                        </tr>

                        <tr>
                            <td><strong>Hidden Dependency Pattern</strong></td>
                            <td>Local Backup Review Workstation and unmanaged operational dependencies</td>
                            <td>Operationally important CI-like object exists without governed candidate, owner, support, access, or evidence model.</td>
                            <td>Operational dependencies are not consistently converted into CI candidates.</td>
                            <td><span class="badge red">Critical</span></td>
                            <td>Create hidden-dependency intake rule and force candidate review before certificate exception consideration.</td>
                            <td>Hidden dependencies become visible governance objects.</td>
                        </tr>

                        <tr>
                            <td><strong>Cutover Evidence Pattern</strong></td>
                            <td>Niagara BMS and cutover-sensitive infrastructure</td>
                            <td>Support, access, vendor, rollback, and post-cutover evidence remain open during transition.</td>
                            <td>Cutover evidence is distributed across owners instead of managed as a single certificate evidence chain.</td>
                            <td><span class="badge orange">High</span></td>
                            <td>Bundle cutover support, access, vendor, rollback, and post-change checks into one required evidence pack.</td>
                            <td>Cleaner cutover certificate attestation and lower trust decay.</td>
                        </tr>

                        <tr>
                            <td><strong>Exception Aging Pattern</strong></td>
                            <td>Jump Server, Speedy Glove 1803, cutover exceptions</td>
                            <td>Exceptions remain open beyond review date or require repeated extensions.</td>
                            <td>Exception closure accountability is not linked strongly enough to escalation cadence.</td>
                            <td><span class="badge yellow">Medium</span></td>
                            <td>Escalate exceptions automatically when expiry, closure evidence, or owner action is missing.</td>
                            <td>Fewer stale exceptions and fewer suspended certificates.</td>
                        </tr>

                        <tr>
                            <td><strong>Strong Control Pattern</strong></td>
                            <td>Blue Mountain RAM</td>
                            <td>Owner, support, lifecycle, evidence, and cadence remain aligned.</td>
                            <td>Evidence model is mature and can be reused as a benchmark.</td>
                            <td><span class="badge green">Low</span></td>
                            <td>Use as reference model for other certificate-ready CIs.</td>
                            <td>Replicable certificate assurance pattern.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Pattern Decision Logic</h2>
                <p>
                    Pattern intelligence helps governance leaders fix the process, not only the individual CI.
                </p>

                <div class="two-col">
                    <div class="logic-box">
                        <h3>Isolated Exception</h3>
                        <ul>
                            <li>Only one CI is affected.</li>
                            <li>Cause is specific to one owner, system, access route, or lifecycle event.</li>
                            <li>Closure evidence is clear and obtainable.</li>
                            <li>No similar exception appears in other certificate-tracked CIs.</li>
                            <li>Decision can remain at local owner or reviewer level.</li>
                            <li>Closure does not require operating-model change.</li>
                        </ul>
                    </div>

                    <div class="logic-box">
                        <h3>Systemic Pattern</h3>
                        <ul>
                            <li>Same exception type appears across multiple CIs.</li>
                            <li>Missing evidence reflects process design rather than one-off failure.</li>
                            <li>Access, support, lifecycle, or evidence gaps repeat after remediation.</li>
                            <li>Exceptions age or expire without consistent closure.</li>
                            <li>Certificate status depends on manual follow-up rather than governed cadence.</li>
                            <li>Executive-level governance correction is needed.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Pattern Remediation Queue</h2>
                <p>
                    These actions reduce recurring certificate exceptions across the CITrust™ lifecycle.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Recurring Pattern</th>
                            <th>Why It Matters</th>
                            <th>Systemic Remediation</th>
                            <th>Expected Outcome</th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Hidden operational dependencies lack governed candidate records.</td>
                            <td>Unmanaged dependencies cannot be trusted, certified, or exception-managed.</td>
                            <td>Create hidden-dependency intake rule and require candidate review before any exception.</td>
                            <td>Hidden dependency pattern reduced.</td>
                        </tr>

                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>OOS lifecycle closure evidence is repeatedly missing.</td>
                            <td>OOS and retired records create audit and access-removal exposure when closure proof is weak.</td>
                            <td>Add lifecycle closure gate requiring closure evidence, access deactivation proof, and decision ledger update.</td>
                            <td>Lifecycle suspension pattern reduced.</td>
                        </tr>

                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Privileged access evidence is repeatedly incomplete.</td>
                            <td>Access assurance decays when admin, vendor, jump path, or MyAccess evidence is not attached.</td>
                            <td>Define required access evidence bundle for certificate readiness and renewal.</td>
                            <td>Access exception pattern reduced.</td>
                        </tr>

                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Support and LCM assignments are discovered late.</td>
                            <td>Late support discovery weakens trust decisions and creates conditional certificates.</td>
                            <td>Require support group, resolver path, LCM, and escalation evidence before certificate review.</td>
                            <td>Support exception pattern reduced.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, CITrust™ Passport, MyAccess, CMDB governance, quality systems, audit systems, change control, validation systems, evidence repositories, or human governance. This exception pattern intelligence console is a governance assurance overlay for recurring exception detection, access-pattern detection, support-pattern detection, lifecycle-pattern detection, evidence-pattern detection, hidden-dependency pattern detection, exception aging analysis, systemic remediation, audit defense, operational trust, and pre-deviation prevention.
            </div>

        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_EXCEPTION_PATTERN_INTELLIGENCE_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Exception Pattern Intelligence installed.")
