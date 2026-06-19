from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AI_POLICY_COMPLIANCE_ROUTER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/ai-policy-compliance-router")'
ROUTE_ALIAS = '@app.route("/citrust/autonomous-policy-router")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust AI Policy Compliance Router already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AI_POLICY_COMPLIANCE_ROUTER_V1_ACTIVE
# ============================================================

@app.route("/citrust/ai-policy-compliance-router")
@app.route("/citrust/autonomous-policy-router")
def citrust_ai_policy_compliance_router():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ AI Policy Compliance Router</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root{--bg:#040b14;--panel:rgba(14,27,44,.92);--line:rgba(255,255,255,.12);--text:#eef5ff;--muted:#a8bbd4;--green:#31d07d;--yellow:#f7c948;--red:#ff5c70;--blue:#5cc8ff;--purple:#b49cff;--orange:#ffb86b;--cyan:#7efcff}
            *{box-sizing:border-box}
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at top left,rgba(247,201,72,.22),transparent 30%),radial-gradient(circle at top right,rgba(92,200,255,.18),transparent 28%),radial-gradient(circle at bottom right,rgba(49,208,125,.14),transparent 30%),var(--bg);color:var(--text)}
            .page{max-width:1460px;margin:0 auto;padding:28px}
            .hero{border:1px solid var(--line);background:linear-gradient(135deg,rgba(16,29,47,.98),rgba(20,40,66,.92));border-radius:26px;padding:30px;box-shadow:0 24px 80px rgba(0,0,0,.42)}
            .eyebrow{color:var(--cyan);font-size:13px;text-transform:uppercase;letter-spacing:1.9px;font-weight:900;margin-bottom:10px}
            h1{margin:0;font-size:42px;line-height:1.08}.subtitle{color:var(--muted);font-size:16px;line-height:1.65;max-width:1180px;margin-top:14px}
            .positioning{margin-top:18px;padding:17px 19px;border:1px solid rgba(247,201,72,.38);background:rgba(247,201,72,.10);border-radius:18px;color:#fff4cc;line-height:1.6}
            .nav{display:flex;flex-wrap:wrap;gap:10px;margin-top:22px}.nav a{color:var(--text);text-decoration:none;border:1px solid var(--line);background:rgba(255,255,255,.06);padding:10px 13px;border-radius:999px;font-size:13px}
            .kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-top:20px}.metric{border:1px solid var(--line);background:var(--panel);border-radius:18px;padding:18px}.metric .label{color:var(--muted);font-size:13px;margin-bottom:8px}.metric .value{font-size:29px;font-weight:900}.metric .note{margin-top:8px;color:var(--muted);font-size:12px;line-height:1.4}
            .section{margin-top:24px;border:1px solid var(--line);background:var(--panel);border-radius:24px;padding:23px}.section h2{margin:0 0 8px 0;font-size:23px}.section p{color:var(--muted);line-height:1.56;margin-top:0}
            .answer{border:1px solid rgba(92,200,255,.38);background:rgba(92,200,255,.10);color:#d9f3ff;border-radius:18px;padding:20px;margin-top:16px;line-height:1.65;font-size:15px}
            .badge{display:inline-block;padding:6px 9px;border-radius:999px;font-size:12px;font-weight:900;white-space:nowrap}.green{color:#04140b;background:var(--green)}.yellow{color:#1d1600;background:var(--yellow)}.red{color:#fff;background:var(--red)}.blue{color:#06101d;background:var(--blue)}.purple{color:#120b24;background:var(--purple)}.orange{color:#211100;background:var(--orange)}
            .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-top:16px}.box{border:1px solid rgba(247,201,72,.32);background:linear-gradient(135deg,rgba(255,255,255,.06),rgba(247,201,72,.07)),rgba(255,255,255,.035);border-radius:22px;padding:22px;min-height:250px}.box h3{margin:0 0 12px 0;font-size:21px}.box ul{margin:0;padding-left:20px;color:var(--muted);font-size:14px;line-height:1.85}
            .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px}.card{border:1px solid var(--line);background:rgba(255,255,255,.045);border-radius:18px;padding:18px;min-height:150px}.card h3{margin:0 0 8px 0;font-size:17px}.card p{margin:0;color:var(--muted);font-size:14px;line-height:1.55}
            table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:16px;margin-top:16px}th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:#c9dbef;background:rgba(255,255,255,.07);padding:13px 12px;border-bottom:1px solid var(--line)}td{padding:13px 12px;border-bottom:1px solid rgba(255,255,255,.08);color:#e9f2ff;vertical-align:top;font-size:14px}tr:hover td{background:rgba(92,200,255,.05)}
            .footer{color:var(--muted);font-size:12px;margin-top:22px;line-height:1.6}
            @media(max-width:1180px){.kpis,.cards,.grid{grid-template-columns:1fr}h1{font-size:30px}table{display:block;overflow-x:auto;white-space:nowrap}}
        </style>
    </head>
    <body>
        <div class="page">
            <section class="hero">
                <div class="eyebrow">CITrust™ / ServiceNow AI / Policy-Aware Governance Routing</div>
                <h1>CITrust™ AI Policy Compliance Router</h1>
                <div class="subtitle">Routes every ServiceNow AI recommendation or action through the correct governance policy lane before execution: CMDB, Change, Access, Validation, QA, Cyber, Lifecycle, Evidence Retention, CAPA, Inspection Readiness, or Executive Reliance.</div>
                <div class="positioning"><strong>ServiceNow-focused positioning:</strong> CITrust™ prevents ServiceNow AI from treating all work as normal workflow. It identifies which policy universe controls the action and routes the agent to the correct human, evidence, approval, and replay requirement.</div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a><a href="/citrust/ai-evidence-lineage-mapper">Evidence Lineage</a><a href="/citrust/ai-decision-rights-matrix">Decision Rights</a><a href="/citrust/ai-evidence-sufficiency-index">Evidence Sufficiency</a><a href="/citrust/human-governed-ai-execution-board">Human-Governed AI</a><a href="/citrust/governance-operating-system">GovOS</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Policy Router Status</div><div class="value" style="color:var(--green);">Active</div><div class="note">AI actions are routed through policy lanes.</div></div>
                <div class="metric"><div class="label">Actions Routed</div><div class="value" style="color:var(--blue);">57</div><div class="note">ServiceNow AI events classified this cycle.</div></div>
                <div class="metric"><div class="label">Policy Conflicts</div><div class="value" style="color:var(--orange);">6</div><div class="note">Actions touching more than one policy domain.</div></div>
                <div class="metric"><div class="label">Human Routes</div><div class="value" style="color:var(--yellow);">24</div><div class="note">Actions routed to accountable human review.</div></div>
                <div class="metric"><div class="label">Blocked Routes</div><div class="value" style="color:var(--red);">5</div><div class="note">Actions blocked due to forbidden policy lane.</div></div>
                <div class="metric"><div class="label">Compliance Decision</div><div class="value" style="color:var(--yellow);">Conditional</div><div class="note">Proceed only through approved policy route.</div></div>
            </section>

            <section class="section">
                <h2>Policy Compliance Router Answer</h2>
                <div class="answer"><strong>Current router interpretation:</strong> The ServiceNow AI action touches CMDB governance, operational support, and change control. CITrust™ routes it to CMDB Governance and Service Operations for approval, requires evidence lineage and rollback proof, and blocks any claim of full readiness until the policy route is closed.</div>
            </section>

            <section class="section">
                <h2>Policy Routing Zones</h2>
                <div class="grid">
                    <div class="box"><h3><span class="badge green">Standard AI Workflow Lane</span></h3><ul><li>Documentation draft</li><li>Evidence checklist</li><li>CI candidate intake</li><li>Gap detection</li><li>Replay summary</li><li>Low-risk recommendation</li></ul></div>
                    <div class="box"><h3><span class="badge yellow">Governed Human Review Lane</span></h3><ul><li>CMDB owner change</li><li>Support group change</li><li>Lifecycle status update</li><li>Certificate readiness</li><li>Access evidence acceptance</li><li>Exception closure route</li></ul></div>
                    <div class="box"><h3><span class="badge red">Forbidden Autonomous Lane</span></h3><ul><li>Privileged access approval</li><li>CAPA closure</li><li>Validation override</li><li>Evidence deletion</li><li>Regulated release approval</li><li>Executive trust certification</li></ul></div>
                </div>
            </section>

            <section class="section">
                <h2>AI Policy Routing Matrix</h2>
                <table>
                    <thead><tr><th>AI Action</th><th>Primary Policy Lane</th><th>Secondary Policy Lane</th><th>Route Decision</th><th>Required Owner</th><th>Required Evidence</th></tr></thead>
                    <tbody>
                        <tr><td><strong>Draft CI candidate</strong></td><td>CMDB Governance</td><td>CSDM / Ownership</td><td><span class="badge green">Route Standard</span></td><td>CMDB Owner</td><td>CI identity, class, owner, relationship rationale.</td></tr>
                        <tr><td><strong>Recommend support group change</strong></td><td>CMDB Governance</td><td>ITSM / Operations</td><td><span class="badge yellow">Human Review</span></td><td>Service Owner / LCM</td><td>Support group, resolver path, LCM, escalation owner.</td></tr>
                        <tr><td><strong>Accept access evidence</strong></td><td>Access Governance</td><td>Cyber / Audit</td><td><span class="badge yellow">Human Review</span></td><td>Access Governance</td><td>MyAccess route, approver group, review proof.</td></tr>
                        <tr><td><strong>Modify validated configuration</strong></td><td>Change Control</td><td>Validation / QA</td><td><span class="badge red">Formal Change</span></td><td>QA / CSV / System Owner</td><td>Impact assessment, test evidence, rollback, approval.</td></tr>
                        <tr><td><strong>Close CAPA</strong></td><td>Quality System</td><td>QA / Effectiveness</td><td><span class="badge red">Forbidden AI</span></td><td>QA / Quality Owner</td><td>CAPA record, effectiveness check, QA approval.</td></tr>
                        <tr><td><strong>Generate executive readiness claim</strong></td><td>Executive Governance</td><td>Claim Firewall</td><td><span class="badge yellow">Approve Language</span></td><td>Governance Owner / Executive</td><td>Evidence sufficiency, residual risk, limitation language.</td></tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Policy Router Engines</h2>
                <div class="cards">
                    <div class="card"><h3>Policy Lane Classifier</h3><p>Detects which governance policy domain controls the AI action before execution.</p></div>
                    <div class="card"><h3>Multi-Policy Conflict Resolver</h3><p>Escalates actions that touch CMDB, access, validation, change, quality, and executive reliance at the same time.</p></div>
                    <div class="card"><h3>Accountable Route Engine</h3><p>Routes each action to the correct human owner, QA reviewer, cyber reviewer, or governance approver.</p></div>
                    <div class="card"><h3>Policy Evidence Binder</h3><p>Attaches the evidence required by the applicable policy lane before trust is granted.</p></div>
                </div>
            </section>

            <div class="footer">CITrust™ AI Policy Compliance Router™ does not replace ServiceNow workflows, policy systems, QA, cyber, validation, access governance, CMDB ownership, or executive accountability. It routes ServiceNow AI actions through the correct policy lane so autonomous work remains governed, evidence-backed, human-approved, replayable, and inspection-defensible.</div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AI_POLICY_COMPLIANCE_ROUTER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust AI Policy Compliance Router installed.")
