from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_TRUST_IMMUNE_SYSTEM_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/trust-immune-system")'
ROUTE_ALIAS = '@app.route("/citrust/governance-immune-system")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Trust Immune System already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_TRUST_IMMUNE_SYSTEM_V1_ACTIVE
# ============================================================

@app.route("/citrust/trust-immune-system")
@app.route("/citrust/governance-immune-system")
def citrust_trust_immune_system():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Trust Immune System</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <style>
            :root {
                --bg:#040b14; --panel:rgba(14,27,44,.92); --line:rgba(255,255,255,.12);
                --text:#eef5ff; --muted:#a8bbd4; --green:#31d07d; --yellow:#f7c948;
                --red:#ff5c70; --blue:#5cc8ff; --purple:#b49cff; --orange:#ffb86b; --cyan:#7efcff;
            }
            *{box-sizing:border-box}
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:
                radial-gradient(circle at top left,rgba(49,208,125,.20),transparent 30%),
                radial-gradient(circle at top right,rgba(255,92,112,.18),transparent 28%),
                radial-gradient(circle at bottom right,rgba(92,200,255,.13),transparent 30%),var(--bg);color:var(--text)}
            .page{max-width:1460px;margin:0 auto;padding:28px}
            .hero{border:1px solid var(--line);background:linear-gradient(135deg,rgba(16,29,47,.98),rgba(20,40,66,.92));border-radius:26px;padding:30px;box-shadow:0 24px 80px rgba(0,0,0,.42)}
            .eyebrow{color:var(--cyan);font-size:13px;text-transform:uppercase;letter-spacing:1.9px;font-weight:900;margin-bottom:10px}
            h1{margin:0;font-size:42px;line-height:1.08}
            .subtitle{color:var(--muted);font-size:16px;line-height:1.65;max-width:1180px;margin-top:14px}
            .positioning{margin-top:18px;padding:17px 19px;border:1px solid rgba(49,208,125,.38);background:rgba(49,208,125,.10);border-radius:18px;color:#dfffea;line-height:1.6}
            .nav{display:flex;flex-wrap:wrap;gap:10px;margin-top:22px}
            .nav a{color:var(--text);text-decoration:none;border:1px solid var(--line);background:rgba(255,255,255,.06);padding:10px 13px;border-radius:999px;font-size:13px}
            .nav a:hover{border-color:rgba(92,200,255,.7);background:rgba(92,200,255,.12)}
            .kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-top:20px}
            .metric{border:1px solid var(--line);background:var(--panel);border-radius:18px;padding:18px}
            .metric .label{color:var(--muted);font-size:13px;margin-bottom:8px}
            .metric .value{font-size:29px;font-weight:900}
            .metric .note{margin-top:8px;color:var(--muted);font-size:12px;line-height:1.4}
            .section{margin-top:24px;border:1px solid var(--line);background:var(--panel);border-radius:24px;padding:23px}
            .section h2{margin:0 0 8px 0;font-size:23px}
            .section p{color:var(--muted);line-height:1.56;margin-top:0}
            .answer{border:1px solid rgba(92,200,255,.38);background:rgba(92,200,255,.10);color:#d9f3ff;border-radius:18px;padding:20px;margin-top:16px;line-height:1.65;font-size:15px}
            .badge{display:inline-block;padding:6px 9px;border-radius:999px;font-size:12px;font-weight:900;white-space:nowrap}
            .green{color:#04140b;background:var(--green)} .yellow{color:#1d1600;background:var(--yellow)}
            .red{color:#fff;background:var(--red)} .blue{color:#06101d;background:var(--blue)}
            .purple{color:#120b24;background:var(--purple)} .orange{color:#211100;background:var(--orange)}
            .immune-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-top:16px}
            .immune-card{border:1px solid rgba(49,208,125,.32);background:linear-gradient(135deg,rgba(255,255,255,.06),rgba(49,208,125,.07)),rgba(255,255,255,.035);border-radius:22px;padding:22px;min-height:260px}
            .immune-card h3{margin:0 0 12px 0;font-size:21px}
            .immune-card ul{margin:0;padding-left:20px;color:var(--muted);font-size:14px;line-height:1.85}
            .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px}
            .card{border:1px solid var(--line);background:rgba(255,255,255,.045);border-radius:18px;padding:18px;min-height:150px}
            .card h3{margin:0 0 8px 0;font-size:17px}.card p{margin:0;color:var(--muted);font-size:14px;line-height:1.55}
            table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:16px;margin-top:16px}
            th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:#c9dbef;background:rgba(255,255,255,.07);padding:13px 12px;border-bottom:1px solid var(--line)}
            td{padding:13px 12px;border-bottom:1px solid rgba(255,255,255,.08);color:#e9f2ff;vertical-align:top;font-size:14px}
            tr:hover td{background:rgba(92,200,255,.05)}
            .footer{color:var(--muted);font-size:12px;margin-top:22px;line-height:1.6}
            @media(max-width:1180px){.kpis,.cards,.immune-grid{grid-template-columns:1fr}h1{font-size:30px}table{display:block;overflow-x:auto;white-space:nowrap}}
        </style>
    </head>

    <body>
        <div class="page">
            <section class="hero">
                <div class="eyebrow">CITrust™ / ServiceNow AI / Governance Immune Defense</div>
                <h1>CITrust™ Trust Immune System</h1>
                <div class="subtitle">
                    Autonomous governance-defense layer that detects abnormal ServiceNow CI trust behavior, quarantines risky AI-assisted changes, triggers evidence review, and prevents governance infection from spreading across CMDB, access, support, certificates, and executive reliance.
                </div>
                <div class="positioning">
                    <strong>ServiceNow-focused positioning:</strong>
                    ServiceNow automates enterprise workflows. CITrust™ Trust Immune System detects when those workflows begin behaving abnormally from a governance perspective and quarantines trust before weak evidence becomes operational or inspection exposure.
                </div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/regulatory-replay">Regulatory Replay</a>
                    <a href="/citrust/ai-authority-envelope">AI Authority Envelope</a>
                    <a href="/citrust/executive-confidence-index">Executive Confidence</a>
                    <a href="/citrust/governance-entropy">Governance Entropy</a>
                    <a href="/citrust/trust-dna">Trust DNA</a>
                    <a href="/citrust/governance-black-box">Governance Black Box</a>
                    <a href="/citrust/assurance-claim-firewall">Claim Firewall</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Immune Status</div><div class="value" style="color:var(--green);">Active</div><div class="note">Governance anomaly defense is monitoring ServiceNow AI actions.</div></div>
                <div class="metric"><div class="label">Anomalies Detected</div><div class="value" style="color:var(--orange);">7</div><div class="note">Abnormal governance signals detected this cycle.</div></div>
                <div class="metric"><div class="label">Trust Quarantines</div><div class="value" style="color:var(--red);">2</div><div class="note">CIs placed under review pending evidence closure.</div></div>
                <div class="metric"><div class="label">Auto-Blocks</div><div class="value" style="color:var(--red);">4</div><div class="note">Unsafe autonomous actions blocked before execution.</div></div>
                <div class="metric"><div class="label">False Confidence Prevented</div><div class="value" style="color:var(--blue);">89%</div><div class="note">Estimated unsupported reliance risk reduced.</div></div>
                <div class="metric"><div class="label">Recovery State</div><div class="value" style="color:var(--yellow);">Monitoring</div><div class="note">Quarantined trust can recover after reviewer acceptance.</div></div>
            </section>

            <section class="section">
                <h2>Trust Immune System Answer</h2>
                <div class="answer">
                    <strong>Current immune interpretation:</strong>
                    CITrust™ detected abnormal support ownership movement combined with stale access proof and a certificate-readiness claim. The system should quarantine executive trust, block autonomous final updates, require Black Box replay, and force human reviewer acceptance before confidence is restored.
                </div>
            </section>

            <section class="section">
                <h2>Immune Defense Zones</h2>
                <div class="immune-grid">
                    <div class="immune-card">
                        <h3><span class="badge green">Detect</span> Governance Infection Signals</h3>
                        <ul>
                            <li>Owner changed unexpectedly</li>
                            <li>Support group changed without LCM proof</li>
                            <li>Access review becomes stale</li>
                            <li>Certificate renewed while exception open</li>
                            <li>AI action exceeds authority envelope</li>
                        </ul>
                    </div>
                    <div class="immune-card">
                        <h3><span class="badge yellow">Quarantine</span> Trust Reliance</h3>
                        <ul>
                            <li>Downgrade executive claims</li>
                            <li>Freeze certificate-ready language</li>
                            <li>Require human reviewer acceptance</li>
                            <li>Force Black Box replay</li>
                            <li>Block high-impact AI execution</li>
                        </ul>
                    </div>
                    <div class="immune-card">
                        <h3><span class="badge blue">Recover</span> Trust State</h3>
                        <ul>
                            <li>Attach missing evidence</li>
                            <li>Resolve support/LCM ambiguity</li>
                            <li>Refresh access proof</li>
                            <li>Close exception escalation</li>
                            <li>Recalculate Trust DNA</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Immune Anomaly Matrix</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Anomaly</th><th>Detected Pattern</th><th>Immune Response</th><th>ServiceNow AI Impact</th><th>Recovery Requirement</th><th>Trust Decision</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>Support Ownership Mutation</strong></td>
                            <td>Support group changed while LCM evidence remains incomplete.</td>
                            <td><span class="badge red">Quarantine</span></td>
                            <td>AI may recommend only; final update blocked.</td>
                            <td>Support group, resolver path, LCM, escalation owner, reviewer acceptance.</td>
                            <td>Conditional reliance only.</td>
                        </tr>
                        <tr>
                            <td><strong>Access Evidence Infection</strong></td>
                            <td>Privileged access evidence is stale while AI prepares readiness output.</td>
                            <td><span class="badge orange">Block Claim</span></td>
                            <td>Access-related recommendations require human gate.</td>
                            <td>MyAccess mapping, approver group, admin/vendor procedure, access review proof.</td>
                            <td>Do not claim full access defensibility.</td>
                        </tr>
                        <tr>
                            <td><strong>Certificate Overclaim</strong></td>
                            <td>Certificate-ready language appears while exception or evidence freshness is unresolved.</td>
                            <td><span class="badge yellow">Downgrade</span></td>
                            <td>AI cannot certify readiness.</td>
                            <td>Evidence freshness, exception status, decision-ledger rationale.</td>
                            <td>Rely with monitoring only.</td>
                        </tr>
                        <tr>
                            <td><strong>Authority Envelope Breach</strong></td>
                            <td>Agent attempts action outside approved ServiceNow governance envelope.</td>
                            <td><span class="badge red">Auto-Block</span></td>
                            <td>Execution denied and Black Box record created.</td>
                            <td>Governance review and passport refresh.</td>
                            <td>Trust quarantined.</td>
                        </tr>
                        <tr>
                            <td><strong>Hidden Dependency Exposure</strong></td>
                            <td>Dependency supports trusted CI but has no candidate record.</td>
                            <td><span class="badge orange">Immune Alert</span></td>
                            <td>AI cannot rely on dependency until governed.</td>
                            <td>Create CI candidate with owner, support, access, evidence, cadence.</td>
                            <td>Strengthen before reliance.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Immune Defense Engines</h2>
                <div class="cards">
                    <div class="card"><h3>Anomaly Detector</h3><p>Detects abnormal ServiceNow governance patterns across ownership, support, access, exceptions, certificates, and AI actions.</p></div>
                    <div class="card"><h3>Trust Quarantine Engine</h3><p>Places risky CIs, claims, certificates, or AI actions into conditional status until evidence closes.</p></div>
                    <div class="card"><h3>Auto-Block Controller</h3><p>Blocks autonomous ServiceNow AI actions when authority, evidence, rollback, or replay checks fail.</p></div>
                    <div class="card"><h3>Trust Recovery Monitor</h3><p>Restores confidence only after reviewer acceptance, evidence refresh, and Trust DNA recalculation.</p></div>
                </div>
            </section>

            <section class="section">
                <h2>Immune Response Rules</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Trigger</th><th>Response</th><th>Human Gate</th><th>Black Box Requirement</th><th>Final State</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Support owner changes without evidence.</td>
                            <td><span class="badge red">Quarantine Trust</span></td>
                            <td>CMDB / Service Operations</td>
                            <td>Replay before/after state and evidence used.</td>
                            <td>Conditional until accepted.</td>
                        </tr>
                        <tr>
                            <td>AI attempts forbidden action.</td>
                            <td><span class="badge red">Block Execution</span></td>
                            <td>Governance Owner</td>
                            <td>Record attempted action and denial reason.</td>
                            <td>Blocked.</td>
                        </tr>
                        <tr>
                            <td>Evidence freshness drops below threshold.</td>
                            <td><span class="badge yellow">Downgrade Claim</span></td>
                            <td>Evidence Owner</td>
                            <td>Capture outdated evidence marker.</td>
                            <td>Rely with limitation.</td>
                        </tr>
                        <tr>
                            <td>Exception ages without escalation owner.</td>
                            <td><span class="badge orange">Immune Alert</span></td>
                            <td>Governance Reviewer</td>
                            <td>Attach exception timeline.</td>
                            <td>Escalate.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, ServiceNow AI agents, AI Control Tower, CMDB, CSDM, ITSM, ITOM, MyAccess, validation systems, quality systems, audit systems, or accountable human governance. Trust Immune System™ is a governance assurance overlay that detects abnormal ServiceNow AI and CMDB trust behavior, quarantines risky reliance, blocks unsafe autonomous execution, requires human governance, preserves Black Box replay, and restores trust only after evidence-based recovery.
            </div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_TRUST_IMMUNE_SYSTEM_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Trust Immune System installed.")
