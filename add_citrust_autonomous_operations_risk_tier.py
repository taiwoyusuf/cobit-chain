from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AUTONOMOUS_OPERATIONS_RISK_TIER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/autonomous-operations-risk-tier")'
ROUTE_ALIAS = '@app.route("/citrust/ai-operations-risk-tier")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Autonomous Operations Risk Tier already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AUTONOMOUS_OPERATIONS_RISK_TIER_V1_ACTIVE
# ============================================================

@app.route("/citrust/autonomous-operations-risk-tier")
@app.route("/citrust/ai-operations-risk-tier")
def citrust_autonomous_operations_risk_tier():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Autonomous Operations Risk Tier</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root{--bg:#040b14;--panel:rgba(14,27,44,.92);--line:rgba(255,255,255,.12);--text:#eef5ff;--muted:#a8bbd4;--green:#31d07d;--yellow:#f7c948;--red:#ff5c70;--blue:#5cc8ff;--purple:#b49cff;--orange:#ffb86b;--cyan:#7efcff}
            *{box-sizing:border-box}
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at top left,rgba(255,92,112,.22),transparent 30%),radial-gradient(circle at top right,rgba(92,200,255,.18),transparent 28%),radial-gradient(circle at bottom right,rgba(255,184,107,.14),transparent 30%),var(--bg);color:var(--text)}
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
            .tier-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:18px;margin-top:16px}.box{border:1px solid rgba(255,92,112,.32);background:linear-gradient(135deg,rgba(255,255,255,.06),rgba(255,92,112,.07)),rgba(255,255,255,.035);border-radius:22px;padding:22px;min-height:250px}.box h3{margin:0 0 12px 0;font-size:21px}.box ul{margin:0;padding-left:20px;color:var(--muted);font-size:14px;line-height:1.85}
            .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px}.card{border:1px solid var(--line);background:rgba(255,255,255,.045);border-radius:18px;padding:18px;min-height:150px}.card h3{margin:0 0 8px 0;font-size:17px}.card p{margin:0;color:var(--muted);font-size:14px;line-height:1.55}
            table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:16px;margin-top:16px}th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:#c9dbef;background:rgba(255,255,255,.07);padding:13px 12px;border-bottom:1px solid var(--line)}td{padding:13px 12px;border-bottom:1px solid rgba(255,255,255,.08);color:#e9f2ff;vertical-align:top;font-size:14px}tr:hover td{background:rgba(92,200,255,.05)}
            .footer{color:var(--muted);font-size:12px;margin-top:22px;line-height:1.6}
            @media(max-width:1180px){.kpis,.cards,.tier-grid{grid-template-columns:1fr}h1{font-size:30px}table{display:block;overflow-x:auto;white-space:nowrap}}
        </style>
    </head>
    <body>
        <div class="page">
            <section class="hero">
                <div class="eyebrow">CITrust™ / ServiceNow AI / Autonomous Operations Risk Tiering</div>
                <h1>CITrust™ Autonomous Operations Risk Tier</h1>
                <div class="subtitle">Classifies every ServiceNow AI action into an operational risk tier before execution, based on regulated impact, CI criticality, validation sensitivity, access risk, evidence sufficiency, rollback readiness, and human-governance requirements.</div>
                <div class="positioning"><strong>ServiceNow-focused positioning:</strong> ServiceNow AI actions should not be treated equally. CITrust™ assigns each action a governed risk tier so low-risk automation can move quickly while regulated, validated, access-impacting, or trust-changing actions are gated or blocked.</div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a><a href="/citrust/human-governed-ai-execution-board">Human-Governed AI</a><a href="/citrust/ai-evidence-sufficiency-index">Evidence Sufficiency</a><a href="/citrust/agentic-validation-impact-assessor">Validation Impact</a><a href="/citrust/agentic-change-control-gate">Change Gate</a><a href="/citrust/governance-operating-system">GovOS</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Current Risk Tier</div><div class="value" style="color:var(--yellow);">Tier 3</div><div class="note">Human-gated AI assistance for regulated operational impact.</div></div>
                <div class="metric"><div class="label">Tier 1 Actions</div><div class="value" style="color:var(--green);">18</div><div class="note">Low-risk advisory or documentation activity.</div></div>
                <div class="metric"><div class="label">Tier 2 Actions</div><div class="value" style="color:var(--blue);">11</div><div class="note">Reviewable workflow support with rollback and replay.</div></div>
                <div class="metric"><div class="label">Tier 3 Actions</div><div class="value" style="color:var(--yellow);">9</div><div class="note">Human approval required before execution.</div></div>
                <div class="metric"><div class="label">Tier 4 Actions</div><div class="value" style="color:var(--red);">4</div><div class="note">Autonomous execution blocked.</div></div>
                <div class="metric"><div class="label">Decision</div><div class="value" style="color:var(--orange);">Gate</div><div class="note">Proceed only with accountable reviewer approval.</div></div>
            </section>

            <section class="section">
                <h2>Risk Tier Answer</h2>
                <div class="answer"><strong>Current tier interpretation:</strong> The ServiceNow AI action is Tier 3 because it affects operational accountability and may influence regulated readiness. AI may prepare evidence and recommend action, but execution requires human approval, Black Box replay, rollback readiness, and evidence sufficiency confirmation.</div>
            </section>

            <section class="section">
                <h2>Autonomous Operations Risk Tiers</h2>
                <div class="tier-grid">
                    <div class="box"><h3><span class="badge green">Tier 1</span> Advisory</h3><ul><li>Draft text</li><li>Prepare checklist</li><li>Summarize evidence</li><li>Flag missing fields</li><li>No system-of-record change</li><li>No regulated impact</li></ul></div>
                    <div class="box"><h3><span class="badge blue">Tier 2</span> Assisted Workflow</h3><ul><li>Reversible update</li><li>Low criticality CI</li><li>Replay available</li><li>Rollback available</li><li>Post-action review</li><li>No validation impact</li></ul></div>
                    <div class="box"><h3><span class="badge yellow">Tier 3</span> Human-Gated</h3><ul><li>Support ownership impact</li><li>Lifecycle influence</li><li>Certificate implication</li><li>Access evidence dependency</li><li>Operational readiness claim</li><li>Human approval required</li></ul></div>
                    <div class="box"><h3><span class="badge red">Tier 4</span> Forbidden Autonomous</h3><ul><li>Privileged access approval</li><li>Validation override</li><li>CAPA closure</li><li>Evidence deletion</li><li>Trust score override</li><li>Regulated readiness certification</li></ul></div>
                </div>
            </section>

            <section class="section">
                <h2>Risk Tier Classification Matrix</h2>
                <table>
                    <thead><tr><th>ServiceNow AI Action</th><th>Risk Tier</th><th>Risk Reason</th><th>Allowed AI Role</th><th>Required Human Gate</th><th>Execution Rule</th></tr></thead>
                    <tbody>
                        <tr><td><strong>Generate evidence checklist</strong></td><td><span class="badge green">Tier 1</span></td><td>No system change or regulated conclusion.</td><td>Draft and suggest.</td><td>Optional.</td><td>Allowed with replay.</td></tr>
                        <tr><td><strong>Update non-regulated documentation</strong></td><td><span class="badge blue">Tier 2</span></td><td>Low-risk, reversible, non-GxP documentation update.</td><td>Assist execution.</td><td>Post-review.</td><td>Allowed if rollback captured.</td></tr>
                        <tr><td><strong>Recommend support group update</strong></td><td><span class="badge yellow">Tier 3</span></td><td>Affects incident routing and operational accountability.</td><td>Recommend only.</td><td>CMDB / Service Owner.</td><td>Hold for approval.</td></tr>
                        <tr><td><strong>Change lifecycle state</strong></td><td><span class="badge yellow">Tier 3</span></td><td>Affects certificate, access, audit, and readiness state.</td><td>Prepare impact assessment.</td><td>Lifecycle Owner / QA.</td><td>Human approval mandatory.</td></tr>
                        <tr><td><strong>Approve privileged access</strong></td><td><span class="badge red">Tier 4</span></td><td>Access approval must remain accountable human decision.</td><td>Flag gap only.</td><td>Access Governance.</td><td>Autonomous execution blocked.</td></tr>
                        <tr><td><strong>Override validation status</strong></td><td><span class="badge red">Tier 4</span></td><td>Validation decisions require QA/CSV/CSA governance.</td><td>None beyond assessment support.</td><td>QA / Validation.</td><td>Blocked.</td></tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Risk Tier Engines</h2>
                <div class="cards">
                    <div class="card"><h3>Operational Impact Classifier</h3><p>Determines whether the AI action affects support, ownership, lifecycle, access, validation, or readiness.</p></div>
                    <div class="card"><h3>Autonomy Boundary Mapper</h3><p>Maps each risk tier to allowed, assisted, human-gated, or forbidden execution mode.</p></div>
                    <div class="card"><h3>Tier Escalation Trigger</h3><p>Escalates AI actions when evidence is weak, rollback is missing, CI is critical, or GxP impact exists.</p></div>
                    <div class="card"><h3>Tier Recovery Engine</h3><p>Downgrades risk only after evidence closes, reviewer accepts, replay is complete, and rollback is ready.</p></div>
                </div>
            </section>

            <div class="footer">CITrust™ Autonomous Operations Risk Tier™ does not replace ServiceNow AI, Change Management, QA, validation, cyber, or human governance. It classifies ServiceNow AI actions into governed risk tiers so regulated operations can safely separate advisory automation from human-gated and forbidden autonomous execution.</div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AUTONOMOUS_OPERATIONS_RISK_TIER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Autonomous Operations Risk Tier installed.")
