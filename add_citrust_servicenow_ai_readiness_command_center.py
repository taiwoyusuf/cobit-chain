from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_SERVICENOW_AI_READINESS_COMMAND_CENTER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/servicenow-ai-readiness-command-center")'
ROUTE_ALIAS = '@app.route("/citrust/servicenow-ai-readiness")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust ServiceNow AI Readiness Command Center already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_SERVICENOW_AI_READINESS_COMMAND_CENTER_V1_ACTIVE
# ============================================================

@app.route("/citrust/servicenow-ai-readiness-command-center")
@app.route("/citrust/servicenow-ai-readiness")
def citrust_servicenow_ai_readiness_command_center():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ ServiceNow AI Readiness Command Center</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <style>
            :root {
                --bg:#040b14; --panel:rgba(14,27,44,.92); --line:rgba(255,255,255,.12);
                --text:#eef5ff; --muted:#a8bbd4; --green:#31d07d; --yellow:#f7c948;
                --red:#ff5c70; --blue:#5cc8ff; --purple:#b49cff; --orange:#ffb86b; --cyan:#7efcff;
            }
            *{box-sizing:border-box}
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:
                radial-gradient(circle at top left,rgba(92,200,255,.22),transparent 30%),
                radial-gradient(circle at top right,rgba(49,208,125,.18),transparent 28%),
                radial-gradient(circle at bottom right,rgba(255,184,107,.14),transparent 30%),var(--bg);color:var(--text)}
            .page{max-width:1460px;margin:0 auto;padding:28px}
            .hero{border:1px solid var(--line);background:linear-gradient(135deg,rgba(16,29,47,.98),rgba(20,40,66,.92));border-radius:26px;padding:30px;box-shadow:0 24px 80px rgba(0,0,0,.42)}
            .eyebrow{color:var(--cyan);font-size:13px;text-transform:uppercase;letter-spacing:1.9px;font-weight:900;margin-bottom:10px}
            h1{margin:0;font-size:42px;line-height:1.08}
            .subtitle{color:var(--muted);font-size:16px;line-height:1.65;max-width:1180px;margin-top:14px}
            .positioning{margin-top:18px;padding:17px 19px;border:1px solid rgba(92,200,255,.38);background:rgba(92,200,255,.10);border-radius:18px;color:#d9f3ff;line-height:1.6}
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
            .readiness-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-top:16px}
            .readiness-card{border:1px solid rgba(92,200,255,.32);background:linear-gradient(135deg,rgba(255,255,255,.06),rgba(92,200,255,.07)),rgba(255,255,255,.035);border-radius:22px;padding:22px;min-height:250px}
            .readiness-card h3{margin:0 0 12px 0;font-size:21px}
            .readiness-card ul{margin:0;padding-left:20px;color:var(--muted);font-size:14px;line-height:1.85}
            .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px}
            .card{border:1px solid var(--line);background:rgba(255,255,255,.045);border-radius:18px;padding:18px;min-height:150px}
            .card h3{margin:0 0 8px 0;font-size:17px}.card p{margin:0;color:var(--muted);font-size:14px;line-height:1.55}
            table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:16px;margin-top:16px}
            th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:#c9dbef;background:rgba(255,255,255,.07);padding:13px 12px;border-bottom:1px solid var(--line)}
            td{padding:13px 12px;border-bottom:1px solid rgba(255,255,255,.08);color:#e9f2ff;vertical-align:top;font-size:14px}
            tr:hover td{background:rgba(92,200,255,.05)}
            .footer{color:var(--muted);font-size:12px;margin-top:22px;line-height:1.6}
            @media(max-width:1180px){.kpis,.cards,.readiness-grid{grid-template-columns:1fr}h1{font-size:30px}table{display:block;overflow-x:auto;white-space:nowrap}}
        </style>
    </head>

    <body>
        <div class="page">
            <section class="hero">
                <div class="eyebrow">CITrust™ / ServiceNow AI / Autonomous Operations Readiness</div>
                <h1>CITrust™ ServiceNow AI Readiness Command Center</h1>
                <div class="subtitle">
                    Executive readiness cockpit for organizations preparing to use ServiceNow AI agents, autonomous workflows, AI Control Tower, CMDB automation, and agentic operations in regulated environments where evidence, human governance, audit defense, and inspection readiness matter.
                </div>
                <div class="positioning">
                    <strong>ServiceNow-focused positioning:</strong>
                    Before ServiceNow AI agents can be trusted in GMP, GxP, clinical, manufacturing, or validated environments, CITrust™ checks whether CMDB quality, ownership, access, support, lifecycle, evidence, rollback, replay, and human oversight are ready.
                </div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/governance-operating-system">GovOS</a>
                    <a href="/citrust/trust-immune-system">Trust Immune System</a>
                    <a href="/citrust/regulatory-replay">Regulatory Replay</a>
                    <a href="/citrust/ai-authority-envelope">AI Authority Envelope</a>
                    <a href="/citrust/autonomous-agent-governance-passport">Agent Passport</a>
                    <a href="/citrust/governance-black-box">Governance Black Box</a>
                    <a href="/citrust/trust-market">Trust Market</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">ServiceNow AI Readiness</div><div class="value" style="color:var(--yellow);">72%</div><div class="note">Ready for bounded AI assistance; not yet ready for high-impact autonomy.</div></div>
                <div class="metric"><div class="label">CMDB Trust</div><div class="value" style="color:var(--blue);">81%</div><div class="note">Strong identity base; support/LCM gaps remain.</div></div>
                <div class="metric"><div class="label">Human Governance</div><div class="value" style="color:var(--green);">Active</div><div class="note">Human approval gates preserved for regulated decisions.</div></div>
                <div class="metric"><div class="label">Replay Readiness</div><div class="value" style="color:var(--green);">Ready</div><div class="note">Black Box and Regulatory Replay are available.</div></div>
                <div class="metric"><div class="label">Autonomy Limit</div><div class="value" style="color:var(--orange);">Bounded</div><div class="note">AI may recommend; final decisions remain gated.</div></div>
                <div class="metric"><div class="label">Go-Live Decision</div><div class="value" style="color:var(--yellow);">Conditional</div><div class="note">Proceed with limited scope and evidence controls.</div></div>
            </section>

            <section class="section">
                <h2>ServiceNow AI Readiness Answer</h2>
                <div class="answer">
                    <strong>Current readiness interpretation:</strong>
                    The environment is ready for ServiceNow AI-assisted governance activities such as evidence preparation, anomaly detection, support recommendation, candidate drafting, and replay generation. It is not ready for autonomous lifecycle, certificate, privileged access, validation, CAPA, readiness, or executive reliance decisions until support/LCM, hidden dependency, access evidence, and exception escalation gates are enforced.
                </div>
            </section>

            <section class="section">
                <h2>Readiness Zones</h2>
                <div class="readiness-grid">
                    <div class="readiness-card">
                        <h3><span class="badge green">Ready Now</span></h3>
                        <ul>
                            <li>AI evidence checklist generation</li>
                            <li>CMDB candidate drafting</li>
                            <li>Governance anomaly detection</li>
                            <li>Claim limitation drafting</li>
                            <li>Black Box replay package creation</li>
                            <li>Support evidence gap flagging</li>
                        </ul>
                    </div>
                    <div class="readiness-card">
                        <h3><span class="badge yellow">Ready With Human Gate</span></h3>
                        <ul>
                            <li>Support group correction</li>
                            <li>LCM confirmation</li>
                            <li>Certificate readiness update</li>
                            <li>Lifecycle status recommendation</li>
                            <li>Access evidence acceptance</li>
                            <li>Exception closure recommendation</li>
                        </ul>
                    </div>
                    <div class="readiness-card">
                        <h3><span class="badge red">Not Autonomous</span></h3>
                        <ul>
                            <li>Privileged access approval</li>
                            <li>CAPA closure</li>
                            <li>Validation override</li>
                            <li>Evidence deletion</li>
                            <li>Trust score override</li>
                            <li>Regulated readiness certification</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>ServiceNow AI Readiness Matrix</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Readiness Domain</th>
                            <th>Current State</th>
                            <th>AI Decision</th>
                            <th>Reason</th>
                            <th>Control Required</th>
                            <th>Go-Live Position</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>CMDB Identity</strong></td>
                            <td>CI identity, class, owner, and relationship evidence mostly available.</td>
                            <td><span class="badge green">Allow Assisted</span></td>
                            <td>Low-risk evidence preparation is supportable.</td>
                            <td>Identity verification and relationship evidence.</td>
                            <td>Ready for assisted AI.</td>
                        </tr>
                        <tr>
                            <td><strong>Support / LCM</strong></td>
                            <td>Support group and LCM evidence not consistently mandatory.</td>
                            <td><span class="badge yellow">Human Gate</span></td>
                            <td>Support ownership affects incident routing and accountability.</td>
                            <td>Mandatory support and LCM evidence gate.</td>
                            <td>Conditional.</td>
                        </tr>
                        <tr>
                            <td><strong>Privileged Access</strong></td>
                            <td>MyAccess mapping improving; review proof and admin/vendor evidence remain conditional.</td>
                            <td><span class="badge red">Block Autonomous</span></td>
                            <td>Access approval is high-impact and must remain human-governed.</td>
                            <td>Full access evidence bundle.</td>
                            <td>Not autonomous.</td>
                        </tr>
                        <tr>
                            <td><strong>Lifecycle State</strong></td>
                            <td>Lifecycle evidence model exists but changes remain regulated.</td>
                            <td><span class="badge yellow">Human Gate</span></td>
                            <td>Lifecycle affects validation, access, certificate, and audit state.</td>
                            <td>Lifecycle owner approval and closure evidence.</td>
                            <td>Recommendation only.</td>
                        </tr>
                        <tr>
                            <td><strong>Regulatory Replay</strong></td>
                            <td>Black Box and replay paths available.</td>
                            <td><span class="badge green">Required</span></td>
                            <td>Every AI action must be reconstructable.</td>
                            <td>Prompt, evidence, policy, authority, approval, rollback.</td>
                            <td>Ready.</td>
                        </tr>
                        <tr>
                            <td><strong>Certificate Trust</strong></td>
                            <td>Certificate model exists but evidence freshness linkage must be enforced.</td>
                            <td><span class="badge yellow">Human Gate</span></td>
                            <td>Certificate-ready is an executive reliance claim.</td>
                            <td>Evidence freshness, exception state, decision-ledger rationale.</td>
                            <td>Conditional.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>ServiceNow AI Readiness Engines</h2>
                <div class="cards">
                    <div class="card"><h3>AI Go-Live Gate</h3><p>Determines whether ServiceNow AI may operate autonomously, assist only, or remain blocked by governance risk.</p></div>
                    <div class="card"><h3>Regulated Scope Classifier</h3><p>Separates low-risk workflow actions from GxP, GMP, access, lifecycle, validation, and audit-impacting actions.</p></div>
                    <div class="card"><h3>Human Gate Map</h3><p>Maps each AI action to the required accountable human reviewer before execution or reliance.</p></div>
                    <div class="card"><h3>Evidence Go/No-Go</h3><p>Blocks ServiceNow AI readiness if evidence sufficiency, rollback, replay, or ownership proof is incomplete.</p></div>
                </div>
            </section>

            <section class="section">
                <h2>Readiness Closure Queue</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Closure Item</th>
                            <th>Why It Blocks Autonomy</th>
                            <th>Required Evidence</th>
                            <th>Readiness Lift</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Mandatory Support and LCM Gate</td>
                            <td>AI cannot safely rely on unclear operational ownership.</td>
                            <td>Support group, resolver path, LCM, escalation owner, cadence.</td>
                            <td>+14%</td>
                        </tr>
                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Hidden Dependency Candidate Trigger</td>
                            <td>AI may rely on invisible dependencies without governance.</td>
                            <td>Candidate record, owner, access, support, evidence, review cadence.</td>
                            <td>+13%</td>
                        </tr>
                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Access Evidence Bundle</td>
                            <td>Privileged access cannot be AI-approved without current proof.</td>
                            <td>MyAccess, approver group, admin/vendor procedure, access review.</td>
                            <td>+11%</td>
                        </tr>
                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Certificate Freshness Linkage</td>
                            <td>Certificate-ready language can become misleading if evidence decays.</td>
                            <td>Evidence age, exception state, access review, lifecycle status.</td>
                            <td>+7%</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, ServiceNow AI agents, AI Control Tower, CMDB, CSDM, ITSM, ITOM, MyAccess, validation systems, quality systems, audit systems, or accountable human governance. ServiceNow AI Readiness Command Center™ is a governance assurance overlay that determines whether ServiceNow AI and autonomous operations are ready for regulated use by validating CMDB quality, evidence sufficiency, support ownership, access governance, lifecycle control, certificate confidence, authority boundaries, human oversight, rollback, replay, and inspection readiness.
            </div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_SERVICENOW_AI_READINESS_COMMAND_CENTER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust ServiceNow AI Readiness Command Center installed.")
