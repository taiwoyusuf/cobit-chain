from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENTIC_EXCEPTION_ESCALATION_ENGINE_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/agentic-exception-escalation-engine")'
ROUTE_ALIAS = '@app.route("/citrust/ai-exception-escalation")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Agentic Exception Escalation Engine already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AGENTIC_EXCEPTION_ESCALATION_ENGINE_V1_ACTIVE
# ============================================================

@app.route("/citrust/agentic-exception-escalation-engine")
@app.route("/citrust/ai-exception-escalation")
def citrust_agentic_exception_escalation_engine():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Agentic Exception Escalation Engine</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root{--bg:#040b14;--panel:rgba(14,27,44,.92);--line:rgba(255,255,255,.12);--text:#eef5ff;--muted:#a8bbd4;--green:#31d07d;--yellow:#f7c948;--red:#ff5c70;--blue:#5cc8ff;--purple:#b49cff;--orange:#ffb86b;--cyan:#7efcff}
            *{box-sizing:border-box}
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at top left,rgba(255,92,112,.22),transparent 30%),radial-gradient(circle at top right,rgba(255,184,107,.18),transparent 28%),radial-gradient(circle at bottom right,rgba(92,200,255,.14),transparent 30%),var(--bg);color:var(--text)}
            .page{max-width:1460px;margin:0 auto;padding:28px}
            .hero{border:1px solid var(--line);background:linear-gradient(135deg,rgba(16,29,47,.98),rgba(20,40,66,.92));border-radius:26px;padding:30px;box-shadow:0 24px 80px rgba(0,0,0,.42)}
            .eyebrow{color:var(--cyan);font-size:13px;text-transform:uppercase;letter-spacing:1.9px;font-weight:900;margin-bottom:10px}
            h1{margin:0;font-size:42px;line-height:1.08}.subtitle{color:var(--muted);font-size:16px;line-height:1.65;max-width:1180px;margin-top:14px}
            .positioning{margin-top:18px;padding:17px 19px;border:1px solid rgba(255,92,112,.38);background:rgba(255,92,112,.10);border-radius:18px;color:#ffe5e9;line-height:1.6}
            .nav{display:flex;flex-wrap:wrap;gap:10px;margin-top:22px}.nav a{color:var(--text);text-decoration:none;border:1px solid var(--line);background:rgba(255,255,255,.06);padding:10px 13px;border-radius:999px;font-size:13px}
            .kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-top:20px}.metric{border:1px solid var(--line);background:var(--panel);border-radius:18px;padding:18px}.metric .label{color:var(--muted);font-size:13px;margin-bottom:8px}.metric .value{font-size:29px;font-weight:900}.metric .note{margin-top:8px;color:var(--muted);font-size:12px;line-height:1.4}
            .section{margin-top:24px;border:1px solid var(--line);background:var(--panel);border-radius:24px;padding:23px}.section h2{margin:0 0 8px 0;font-size:23px}.section p{color:var(--muted);line-height:1.56;margin-top:0}
            .answer{border:1px solid rgba(92,200,255,.38);background:rgba(92,200,255,.10);color:#d9f3ff;border-radius:18px;padding:20px;margin-top:16px;line-height:1.65;font-size:15px}
            .badge{display:inline-block;padding:6px 9px;border-radius:999px;font-size:12px;font-weight:900;white-space:nowrap}.green{color:#04140b;background:var(--green)}.yellow{color:#1d1600;background:var(--yellow)}.red{color:#fff;background:var(--red)}.blue{color:#06101d;background:var(--blue)}.purple{color:#120b24;background:var(--purple)}.orange{color:#211100;background:var(--orange)}
            .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-top:16px}.box{border:1px solid rgba(255,92,112,.32);background:linear-gradient(135deg,rgba(255,255,255,.06),rgba(255,92,112,.07)),rgba(255,255,255,.035);border-radius:22px;padding:22px;min-height:250px}.box h3{margin:0 0 12px 0;font-size:21px}.box ul{margin:0;padding-left:20px;color:var(--muted);font-size:14px;line-height:1.85}
            .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px}.card{border:1px solid var(--line);background:rgba(255,255,255,.045);border-radius:18px;padding:18px;min-height:150px}.card h3{margin:0 0 8px 0;font-size:17px}.card p{margin:0;color:var(--muted);font-size:14px;line-height:1.55}
            table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:16px;margin-top:16px}th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:#c9dbef;background:rgba(255,255,255,.07);padding:13px 12px;border-bottom:1px solid var(--line)}td{padding:13px 12px;border-bottom:1px solid rgba(255,255,255,.08);color:#e9f2ff;vertical-align:top;font-size:14px}tr:hover td{background:rgba(92,200,255,.05)}
            .footer{color:var(--muted);font-size:12px;margin-top:22px;line-height:1.6}
            @media(max-width:1180px){.kpis,.cards,.grid{grid-template-columns:1fr}h1{font-size:30px}table{display:block;overflow-x:auto;white-space:nowrap}}
        </style>
    </head>
    <body>
        <div class="page">
            <section class="hero">
                <div class="eyebrow">CITrust™ / ServiceNow AI / Autonomous Exception Governance</div>
                <h1>CITrust™ Agentic Exception Escalation Engine</h1>
                <div class="subtitle">Detects when ServiceNow AI encounters governance exceptions, determines whether the exception can be monitored, must be escalated, requires human risk acceptance, or must block autonomous execution until closure evidence exists.</div>
                <div class="positioning"><strong>ServiceNow-focused positioning:</strong> CITrust™ prevents ServiceNow AI from normalizing unresolved exceptions. Every exception needs an owner, expiry, escalation path, residual-risk statement, closure evidence, and replayable decision rationale before trust can be restored.</div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a><a href="/citrust/autonomous-action-rollback-vault">Rollback Vault</a><a href="/citrust/agent-evidence-sufficiency-gate">Evidence Gate</a><a href="/citrust/agentic-change-control-gate">Change Gate</a><a href="/citrust/trust-immune-system">Trust Immune System</a><a href="/citrust/regulatory-replay">Regulatory Replay</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Exception Engine</div><div class="value" style="color:var(--green);">Active</div><div class="note">AI exceptions are governed before reliance.</div></div>
                <div class="metric"><div class="label">Open Exceptions</div><div class="value" style="color:var(--orange);">9</div><div class="note">Exceptions requiring owner and closure review.</div></div>
                <div class="metric"><div class="label">Escalation Missing</div><div class="value" style="color:var(--red);">3</div><div class="note">Exceptions without escalation owner are trust blockers.</div></div>
                <div class="metric"><div class="label">Expired Exceptions</div><div class="value" style="color:var(--red);">2</div><div class="note">Expired exceptions require immediate quarantine.</div></div>
                <div class="metric"><div class="label">Risk Accepted</div><div class="value" style="color:var(--yellow);">4</div><div class="note">Accepted with limitation language and owner accountability.</div></div>
                <div class="metric"><div class="label">Trust Decision</div><div class="value" style="color:var(--yellow);">Conditional</div><div class="note">Trust remains conditional until exception closure.</div></div>
            </section>

            <section class="section">
                <h2>Exception Escalation Answer</h2>
                <div class="answer"><strong>Current escalation decision:</strong> CITrust™ allows AI to identify, classify, route, and draft exception closure actions. AI cannot accept residual risk, approve exception extension, close an exception, or restore full trust without accountable human approval and closure evidence.</div>
            </section>

            <section class="section">
                <h2>Exception Escalation Zones</h2>
                <div class="grid">
                    <div class="box"><h3><span class="badge green">AI May Assist</span></h3><ul><li>Detect exception pattern</li><li>Draft exception summary</li><li>Identify missing owner</li><li>Prepare closure checklist</li><li>Generate limitation language</li><li>Recommend escalation route</li></ul></div>
                    <div class="box"><h3><span class="badge yellow">Human Approval Required</span></h3><ul><li>Risk acceptance</li><li>Exception extension</li><li>Residual-risk statement</li><li>Closure decision</li><li>Certificate restoration</li><li>Executive reliance upgrade</li></ul></div>
                    <div class="box"><h3><span class="badge red">Trust Blocking</span></h3><ul><li>No exception owner</li><li>No escalation owner</li><li>Expired exception</li><li>No closure evidence</li><li>No residual-risk statement</li><li>No decision-ledger rationale</li></ul></div>
                </div>
            </section>

            <section class="section">
                <h2>Exception Escalation Matrix</h2>
                <table>
                    <thead><tr><th>Exception Type</th><th>Pattern Detected</th><th>Escalation Decision</th><th>AI Permission</th><th>Human Owner</th><th>Closure Evidence</th></tr></thead>
                    <tbody>
                        <tr><td><strong>Support Owner Gap</strong></td><td>Support group exists but LCM/escalation owner missing.</td><td><span class="badge orange">Escalate</span></td><td>Draft route and evidence request.</td><td>CMDB / Service Operations Owner</td><td>Support group, LCM, resolver path, escalation owner.</td></tr>
                        <tr><td><strong>Access Evidence Gap</strong></td><td>MyAccess route visible but admin/vendor review proof stale.</td><td><span class="badge yellow">Conditional</span></td><td>Flag gap and draft access evidence request.</td><td>Access Governance Owner</td><td>Approver group, review proof, procedure, verification.</td></tr>
                        <tr><td><strong>Expired Exception</strong></td><td>Exception passed expiry without closure proof.</td><td><span class="badge red">Quarantine</span></td><td>Escalation only.</td><td>Exception Owner / Governance Reviewer</td><td>Extension approval or closure evidence.</td></tr>
                        <tr><td><strong>Certificate Exception</strong></td><td>Certificate-ready claim exists while exception remains unresolved.</td><td><span class="badge red">Block Claim</span></td><td>Generate limitation language only.</td><td>Certificate Owner / QA</td><td>Exception closure and decision-ledger rationale.</td></tr>
                        <tr><td><strong>Hidden Dependency Exception</strong></td><td>Dependency supports CI but has no candidate record.</td><td><span class="badge orange">Force Candidate</span></td><td>Create draft candidate record.</td><td>CMDB Governance Owner</td><td>Owner, support, access, evidence, cadence.</td></tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Exception Engine Capabilities</h2>
                <div class="cards">
                    <div class="card"><h3>Exception Pattern Detector</h3><p>Finds unresolved governance exceptions across support, access, lifecycle, certificate, evidence, and hidden dependencies.</p></div>
                    <div class="card"><h3>Escalation Owner Resolver</h3><p>Identifies who must accept, close, extend, or remediate an exception before trust is restored.</p></div>
                    <div class="card"><h3>Residual Risk Gate</h3><p>Requires human-approved residual-risk language before leadership can rely conditionally.</p></div>
                    <div class="card"><h3>Trust Restoration Lock</h3><p>Prevents trust upgrade until exception closure evidence and decision-ledger rationale exist.</p></div>
                </div>
            </section>

            <section class="section">
                <h2>Exception Escalation Rules</h2>
                <table>
                    <thead><tr><th>Condition</th><th>Decision</th><th>AI Action</th><th>Human Gate</th><th>Trust Outcome</th></tr></thead>
                    <tbody>
                        <tr><td>Exception has owner, expiry, risk statement, and closure plan.</td><td><span class="badge yellow">Monitor</span></td><td>Track and remind.</td><td>Owner review by due date.</td><td>Conditional reliance.</td></tr>
                        <tr><td>Exception lacks escalation owner.</td><td><span class="badge orange">Escalate</span></td><td>Draft escalation route.</td><td>Governance reviewer required.</td><td>Trust downgraded.</td></tr>
                        <tr><td>Exception expired without closure.</td><td><span class="badge red">Quarantine</span></td><td>Block reliance and create alert.</td><td>Owner and executive reviewer required.</td><td>Trust blocked.</td></tr>
                        <tr><td>Exception closure evidence accepted.</td><td><span class="badge green">Restore</span></td><td>Prepare trust recovery record.</td><td>Reviewer acceptance required.</td><td>Trust restored with replay.</td></tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">CITrust™ Agentic Exception Escalation Engine™ does not replace ServiceNow, IRM/GRC, QA, CAPA, change control, access governance, or accountable human risk acceptance. It governs ServiceNow AI exception handling by detecting unresolved exceptions, forcing escalation ownership, blocking unsupported trust, preserving replay, and restoring confidence only after evidence-based closure.</div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AGENTIC_EXCEPTION_ESCALATION_ENGINE_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Agentic Exception Escalation Engine installed.")
