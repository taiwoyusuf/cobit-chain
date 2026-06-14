from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AI_DECISION_RIGHTS_MATRIX_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/ai-decision-rights-matrix")'
ROUTE_ALIAS = '@app.route("/citrust/autonomous-decision-rights")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust AI Decision Rights Matrix already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AI_DECISION_RIGHTS_MATRIX_V1_ACTIVE
# ============================================================

@app.route("/citrust/ai-decision-rights-matrix")
@app.route("/citrust/autonomous-decision-rights")
def citrust_ai_decision_rights_matrix():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ AI Decision Rights Matrix</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root{--bg:#040b14;--panel:rgba(14,27,44,.92);--line:rgba(255,255,255,.12);--text:#eef5ff;--muted:#a8bbd4;--green:#31d07d;--yellow:#f7c948;--red:#ff5c70;--blue:#5cc8ff;--purple:#b49cff;--orange:#ffb86b;--cyan:#7efcff}
            *{box-sizing:border-box}
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at top left,rgba(180,156,255,.22),transparent 30%),radial-gradient(circle at top right,rgba(92,200,255,.18),transparent 28%),radial-gradient(circle at bottom right,rgba(49,208,125,.14),transparent 30%),var(--bg);color:var(--text)}
            .page{max-width:1460px;margin:0 auto;padding:28px}
            .hero{border:1px solid var(--line);background:linear-gradient(135deg,rgba(16,29,47,.98),rgba(20,40,66,.92));border-radius:26px;padding:30px;box-shadow:0 24px 80px rgba(0,0,0,.42)}
            .eyebrow{color:var(--cyan);font-size:13px;text-transform:uppercase;letter-spacing:1.9px;font-weight:900;margin-bottom:10px}
            h1{margin:0;font-size:42px;line-height:1.08}.subtitle{color:var(--muted);font-size:16px;line-height:1.65;max-width:1180px;margin-top:14px}
            .positioning{margin-top:18px;padding:17px 19px;border:1px solid rgba(180,156,255,.38);background:rgba(180,156,255,.10);border-radius:18px;color:#eee7ff;line-height:1.6}
            .nav{display:flex;flex-wrap:wrap;gap:10px;margin-top:22px}.nav a{color:var(--text);text-decoration:none;border:1px solid var(--line);background:rgba(255,255,255,.06);padding:10px 13px;border-radius:999px;font-size:13px}
            .kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-top:20px}.metric{border:1px solid var(--line);background:var(--panel);border-radius:18px;padding:18px}.metric .label{color:var(--muted);font-size:13px;margin-bottom:8px}.metric .value{font-size:29px;font-weight:900}.metric .note{margin-top:8px;color:var(--muted);font-size:12px;line-height:1.4}
            .section{margin-top:24px;border:1px solid var(--line);background:var(--panel);border-radius:24px;padding:23px}.section h2{margin:0 0 8px 0;font-size:23px}.section p{color:var(--muted);line-height:1.56;margin-top:0}
            .answer{border:1px solid rgba(92,200,255,.38);background:rgba(92,200,255,.10);color:#d9f3ff;border-radius:18px;padding:20px;margin-top:16px;line-height:1.65;font-size:15px}
            .badge{display:inline-block;padding:6px 9px;border-radius:999px;font-size:12px;font-weight:900;white-space:nowrap}.green{color:#04140b;background:var(--green)}.yellow{color:#1d1600;background:var(--yellow)}.red{color:#fff;background:var(--red)}.blue{color:#06101d;background:var(--blue)}.purple{color:#120b24;background:var(--purple)}.orange{color:#211100;background:var(--orange)}
            .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-top:16px}.box{border:1px solid rgba(180,156,255,.32);background:linear-gradient(135deg,rgba(255,255,255,.06),rgba(180,156,255,.07)),rgba(255,255,255,.035);border-radius:22px;padding:22px;min-height:250px}.box h3{margin:0 0 12px 0;font-size:21px}.box ul{margin:0;padding-left:20px;color:var(--muted);font-size:14px;line-height:1.85}
            .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px}.card{border:1px solid var(--line);background:rgba(255,255,255,.045);border-radius:18px;padding:18px;min-height:150px}.card h3{margin:0 0 8px 0;font-size:17px}.card p{margin:0;color:var(--muted);font-size:14px;line-height:1.55}
            table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:16px;margin-top:16px}th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:#c9dbef;background:rgba(255,255,255,.07);padding:13px 12px;border-bottom:1px solid var(--line)}td{padding:13px 12px;border-bottom:1px solid rgba(255,255,255,.08);color:#e9f2ff;vertical-align:top;font-size:14px}tr:hover td{background:rgba(92,200,255,.05)}
            .footer{color:var(--muted);font-size:12px;margin-top:22px;line-height:1.6}
            @media(max-width:1180px){.kpis,.cards,.grid{grid-template-columns:1fr}h1{font-size:30px}table{display:block;overflow-x:auto;white-space:nowrap}}
        </style>
    </head>
    <body>
        <div class="page">
            <section class="hero">
                <div class="eyebrow">CITrust™ / ServiceNow AI / Decision Rights Governance</div>
                <h1>CITrust™ AI Decision Rights Matrix</h1>
                <div class="subtitle">Defines exactly which decisions ServiceNow AI may recommend, draft, execute, escalate, or must never make across CMDB, access, support, lifecycle, validation, certificate readiness, change control, CAPA, and regulated operations.</div>
                <div class="positioning"><strong>ServiceNow-focused positioning:</strong> CITrust™ separates AI task permission from decision authority. An agent may have system permission to act, but it does not automatically have governance authority to decide.</div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a><a href="/citrust/ai-action-rollback-verifier">Rollback Verifier</a><a href="/citrust/autonomous-operations-risk-tier">Risk Tier</a><a href="/citrust/human-governed-ai-execution-board">Human-Governed AI</a><a href="/citrust/ai-authority-envelope">Authority Envelope</a><a href="/citrust/governance-operating-system">GovOS</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Decision Rights Status</div><div class="value" style="color:var(--green);">Defined</div><div class="note">AI and human decision boundaries are mapped.</div></div>
                <div class="metric"><div class="label">AI-Recommendable</div><div class="value" style="color:var(--blue);">28</div><div class="note">Decisions AI may support but not own.</div></div>
                <div class="metric"><div class="label">AI-Executable</div><div class="value" style="color:var(--green);">9</div><div class="note">Low-risk actions allowed with replay and rollback.</div></div>
                <div class="metric"><div class="label">Human-Owned</div><div class="value" style="color:var(--yellow);">23</div><div class="note">Regulated or accountability decisions remain human-owned.</div></div>
                <div class="metric"><div class="label">AI-Forbidden</div><div class="value" style="color:var(--red);">12</div><div class="note">Actions AI must never decide or execute autonomously.</div></div>
                <div class="metric"><div class="label">Governance Decision</div><div class="value" style="color:var(--orange);">Bound</div><div class="note">AI operates inside decision-right boundaries.</div></div>
            </section>

            <section class="section">
                <h2>Decision Rights Answer</h2>
                <div class="answer"><strong>Current decision-rights interpretation:</strong> ServiceNow AI may recommend and prepare evidence, but final authority remains human-owned for regulated lifecycle changes, privileged access approval, validation impact conclusions, certificate readiness, CAPA closure, residual-risk acceptance, and executive reliance statements.</div>
            </section>

            <section class="section">
                <h2>Decision Rights Zones</h2>
                <div class="grid">
                    <div class="box"><h3><span class="badge green">AI May Decide / Execute</span></h3><ul><li>Non-regulated documentation update</li><li>Evidence checklist generation</li><li>Draft CI candidate</li><li>Flag stale evidence</li><li>Create recommendation package</li><li>Generate replay summary</li></ul></div>
                    <div class="box"><h3><span class="badge yellow">AI May Recommend Only</span></h3><ul><li>Support group correction</li><li>Lifecycle state recommendation</li><li>Access evidence acceptance</li><li>Certificate readiness package</li><li>Validation impact draft</li><li>Exception closure recommendation</li></ul></div>
                    <div class="box"><h3><span class="badge red">Human Decision Only</span></h3><ul><li>Privileged access approval</li><li>Validation impact conclusion</li><li>CAPA closure</li><li>Residual-risk acceptance</li><li>Certificate approval</li><li>Executive trust reliance</li></ul></div>
                </div>
            </section>

            <section class="section">
                <h2>Decision Rights Matrix</h2>
                <table>
                    <thead><tr><th>Decision Area</th><th>AI Role</th><th>Human Owner</th><th>Evidence Required</th><th>Execution Rule</th><th>Forbidden AI Claim</th></tr></thead>
                    <tbody>
                        <tr><td><strong>CMDB candidate intake</strong></td><td><span class="badge green">Draft / Execute Low-Risk</span></td><td>CMDB Owner</td><td>CI identity, class, owner, relationship rationale.</td><td>AI may draft; owner approves final.</td><td>AI fully onboarded CI without human ownership.</td></tr>
                        <tr><td><strong>Support group ownership</strong></td><td><span class="badge yellow">Recommend Only</span></td><td>Service Owner / LCM / Operations</td><td>Support group, resolver path, LCM, escalation owner.</td><td>Human approval required.</td><td>AI independently assigned support accountability.</td></tr>
                        <tr><td><strong>Privileged access approval</strong></td><td><span class="badge red">Forbidden</span></td><td>Access Governance</td><td>MyAccess route, approver group, review proof, admin/vendor evidence.</td><td>AI can flag gaps only.</td><td>AI approved privileged access.</td></tr>
                        <tr><td><strong>Validation impact conclusion</strong></td><td><span class="badge yellow">Draft Only</span></td><td>QA / CSV / CSA / System Owner</td><td>Impact rationale, risk assessment, test evidence, rollback.</td><td>Human conclusion mandatory.</td><td>AI declared no validation impact.</td></tr>
                        <tr><td><strong>Certificate readiness</strong></td><td><span class="badge yellow">Prepare Package</span></td><td>Governance Owner / QA / Executive</td><td>Evidence freshness, exception state, lifecycle status, decision rationale.</td><td>Human approval required.</td><td>AI certified operational trust.</td></tr>
                        <tr><td><strong>CAPA closure</strong></td><td><span class="badge red">Forbidden</span></td><td>QA / Quality Owner</td><td>CAPA evidence, effectiveness check, QA approval.</td><td>AI cannot close.</td><td>AI closed CAPA or quality record.</td></tr>
                        <tr><td><strong>Executive reliance statement</strong></td><td><span class="badge yellow">Draft Language</span></td><td>Executive / Governance Owner</td><td>Claim Firewall result, evidence sufficiency, residual-risk disclosure.</td><td>Human owner approves.</td><td>AI asserted leadership reliance without approval.</td></tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Decision Rights Engines</h2>
                <div class="cards">
                    <div class="card"><h3>Decision Authority Resolver</h3><p>Determines whether the decision belongs to AI, human owner, QA, cyber, validation, operations, or executive governance.</p></div>
                    <div class="card"><h3>Role Separation Engine</h3><p>Separates recommendation, approval, execution, verification, and reliance so one AI agent cannot collapse governance roles.</p></div>
                    <div class="card"><h3>Forbidden Decision Blocker</h3><p>Blocks AI from approving access, validation, CAPA, certificate trust, residual risk, or executive reliance.</p></div>
                    <div class="card"><h3>Decision Replay Binder</h3><p>Preserves who decided, why they decided, what evidence they used, and what AI contributed.</p></div>
                </div>
            </section>

            <div class="footer">CITrust™ AI Decision Rights Matrix™ does not replace ServiceNow roles, access governance, QA, validation, cyber, CMDB ownership, or executive accountability. It defines which decisions ServiceNow AI can make, which it can only recommend, and which must remain human-owned in regulated environments.</div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AI_DECISION_RIGHTS_MATRIX_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust AI Decision Rights Matrix installed.")
