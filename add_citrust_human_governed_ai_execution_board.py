from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_HUMAN_GOVERNED_AI_EXECUTION_BOARD_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/human-governed-ai-execution-board")'
ROUTE_ALIAS = '@app.route("/citrust/human-governed-ai")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Human-Governed AI Execution Board already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_HUMAN_GOVERNED_AI_EXECUTION_BOARD_V1_ACTIVE
# ============================================================

@app.route("/citrust/human-governed-ai-execution-board")
@app.route("/citrust/human-governed-ai")
def citrust_human_governed_ai_execution_board():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Human-Governed AI Execution Board</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root{--bg:#040b14;--panel:rgba(14,27,44,.92);--line:rgba(255,255,255,.12);--text:#eef5ff;--muted:#a8bbd4;--green:#31d07d;--yellow:#f7c948;--red:#ff5c70;--blue:#5cc8ff;--purple:#b49cff;--orange:#ffb86b;--cyan:#7efcff}
            *{box-sizing:border-box}
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at top left,rgba(92,200,255,.22),transparent 30%),radial-gradient(circle at top right,rgba(49,208,125,.18),transparent 28%),radial-gradient(circle at bottom right,rgba(180,156,255,.14),transparent 30%),var(--bg);color:var(--text)}
            .page{max-width:1460px;margin:0 auto;padding:28px}
            .hero{border:1px solid var(--line);background:linear-gradient(135deg,rgba(16,29,47,.98),rgba(20,40,66,.92));border-radius:26px;padding:30px;box-shadow:0 24px 80px rgba(0,0,0,.42)}
            .eyebrow{color:var(--cyan);font-size:13px;text-transform:uppercase;letter-spacing:1.9px;font-weight:900;margin-bottom:10px}
            h1{margin:0;font-size:42px;line-height:1.08}.subtitle{color:var(--muted);font-size:16px;line-height:1.65;max-width:1180px;margin-top:14px}
            .positioning{margin-top:18px;padding:17px 19px;border:1px solid rgba(92,200,255,.38);background:rgba(92,200,255,.10);border-radius:18px;color:#d9f3ff;line-height:1.6}
            .nav{display:flex;flex-wrap:wrap;gap:10px;margin-top:22px}.nav a{color:var(--text);text-decoration:none;border:1px solid var(--line);background:rgba(255,255,255,.06);padding:10px 13px;border-radius:999px;font-size:13px}
            .kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-top:20px}.metric{border:1px solid var(--line);background:var(--panel);border-radius:18px;padding:18px}.metric .label{color:var(--muted);font-size:13px;margin-bottom:8px}.metric .value{font-size:29px;font-weight:900}.metric .note{margin-top:8px;color:var(--muted);font-size:12px;line-height:1.4}
            .section{margin-top:24px;border:1px solid var(--line);background:var(--panel);border-radius:24px;padding:23px}.section h2{margin:0 0 8px 0;font-size:23px}.section p{color:var(--muted);line-height:1.56;margin-top:0}
            .answer{border:1px solid rgba(92,200,255,.38);background:rgba(92,200,255,.10);color:#d9f3ff;border-radius:18px;padding:20px;margin-top:16px;line-height:1.65;font-size:15px}
            .badge{display:inline-block;padding:6px 9px;border-radius:999px;font-size:12px;font-weight:900;white-space:nowrap}.green{color:#04140b;background:var(--green)}.yellow{color:#1d1600;background:var(--yellow)}.red{color:#fff;background:var(--red)}.blue{color:#06101d;background:var(--blue)}.purple{color:#120b24;background:var(--purple)}.orange{color:#211100;background:var(--orange)}
            .board-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-top:16px}.box{border:1px solid rgba(92,200,255,.32);background:linear-gradient(135deg,rgba(255,255,255,.06),rgba(92,200,255,.07)),rgba(255,255,255,.035);border-radius:22px;padding:22px;min-height:250px}.box h3{margin:0 0 12px 0;font-size:21px}.box ul{margin:0;padding-left:20px;color:var(--muted);font-size:14px;line-height:1.85}
            .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px}.card{border:1px solid var(--line);background:rgba(255,255,255,.045);border-radius:18px;padding:18px;min-height:150px}.card h3{margin:0 0 8px 0;font-size:17px}.card p{margin:0;color:var(--muted);font-size:14px;line-height:1.55}
            table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:16px;margin-top:16px}th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:#c9dbef;background:rgba(255,255,255,.07);padding:13px 12px;border-bottom:1px solid var(--line)}td{padding:13px 12px;border-bottom:1px solid rgba(255,255,255,.08);color:#e9f2ff;vertical-align:top;font-size:14px}tr:hover td{background:rgba(92,200,255,.05)}
            .footer{color:var(--muted);font-size:12px;margin-top:22px;line-height:1.6}
            @media(max-width:1180px){.kpis,.cards,.board-grid{grid-template-columns:1fr}h1{font-size:30px}table{display:block;overflow-x:auto;white-space:nowrap}}
        </style>
    </head>
    <body>
        <div class="page">
            <section class="hero">
                <div class="eyebrow">CITrust™ / ServiceNow AI / Human-Governed Execution</div>
                <h1>CITrust™ Human-Governed AI Execution Board</h1>
                <div class="subtitle">Execution control board that separates AI recommendation from accountable human decision-making for ServiceNow AI actions affecting CMDB trust, access governance, lifecycle state, validation impact, certificate readiness, and regulated operational reliance.</div>
                <div class="positioning"><strong>ServiceNow-focused positioning:</strong> ServiceNow AI may accelerate work, but CITrust™ ensures regulated decisions remain human-governed, evidence-backed, replayable, reversible, and defensible before execution is trusted.</div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a><a href="/citrust/ai-evidence-sufficiency-index">Evidence Sufficiency</a><a href="/citrust/agentic-validation-impact-assessor">Validation Impact</a><a href="/citrust/agentic-change-control-gate">Change Gate</a><a href="/citrust/ai-authority-envelope">Authority Envelope</a><a href="/citrust/regulatory-replay">Regulatory Replay</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Human Governance</div><div class="value" style="color:var(--green);">Enforced</div><div class="note">Regulated decisions require accountable human approval.</div></div>
                <div class="metric"><div class="label">AI Recommendations</div><div class="value" style="color:var(--blue);">42</div><div class="note">AI recommendations awaiting routing, review, or execution.</div></div>
                <div class="metric"><div class="label">Human-Gated</div><div class="value" style="color:var(--yellow);">19</div><div class="note">Actions requiring owner, QA, cyber, or validation review.</div></div>
                <div class="metric"><div class="label">Approved For Execution</div><div class="value" style="color:var(--green);">11</div><div class="note">Evidence-backed actions accepted by accountable humans.</div></div>
                <div class="metric"><div class="label">Execution Blocked</div><div class="value" style="color:var(--red);">5</div><div class="note">Actions blocked for authority, evidence, validation, or access risk.</div></div>
                <div class="metric"><div class="label">Replay Coverage</div><div class="value" style="color:var(--green);">98%</div><div class="note">Human decisions and AI recommendations are replayable.</div></div>
            </section>

            <section class="section">
                <h2>Human-Governed AI Answer</h2>
                <div class="answer"><strong>Current execution interpretation:</strong> CITrust™ allows ServiceNow AI to recommend, draft, assess, detect, and package evidence. Execution is blocked or human-gated when the action touches validated systems, access approval, support ownership, lifecycle status, certificate readiness, CAPA, residual risk, or executive reliance.</div>
            </section>

            <section class="section">
                <h2>Execution Governance Zones</h2>
                <div class="board-grid">
                    <div class="box"><h3><span class="badge green">AI Execution Allowed</span></h3><ul><li>Draft documentation</li><li>Prepare evidence checklist</li><li>Generate impact questions</li><li>Flag stale evidence</li><li>Create review recommendation</li><li>Build replay package</li></ul></div>
                    <div class="box"><h3><span class="badge yellow">Human Approval Required</span></h3><ul><li>Support ownership update</li><li>Lifecycle recommendation</li><li>Certificate state update</li><li>Validation impact conclusion</li><li>Access evidence acceptance</li><li>Residual-risk acceptance</li></ul></div>
                    <div class="box"><h3><span class="badge red">Execution Forbidden</span></h3><ul><li>Approve privileged access</li><li>Close CAPA</li><li>Override validation</li><li>Remove evidence</li><li>Suppress exception</li><li>Directly alter trust score</li></ul></div>
                </div>
            </section>

            <section class="section">
                <h2>Human-Governed Execution Matrix</h2>
                <table>
                    <thead><tr><th>AI Recommendation</th><th>Human Decision Owner</th><th>Evidence Required</th><th>Execution Decision</th><th>Why</th><th>Replay Requirement</th></tr></thead>
                    <tbody>
                        <tr><td><strong>Recommend support group correction</strong></td><td>CMDB Owner / Service Operations</td><td>Support group, resolver path, LCM, escalation owner.</td><td><span class="badge yellow">Human Gate</span></td><td>Impacts operational accountability and incident routing.</td><td>Record recommendation, approval, before/after state.</td></tr>
                        <tr><td><strong>Draft validation impact assessment</strong></td><td>QA / CSV / System Owner</td><td>Impact rationale, affected CI, risk, rollback, verification.</td><td><span class="badge green">AI Draft Allowed</span></td><td>AI may prepare but not approve regulated conclusion.</td><td>Capture prompt, evidence, reviewer acceptance.</td></tr>
                        <tr><td><strong>Approve lifecycle retirement</strong></td><td>Lifecycle Owner / QA</td><td>Closure evidence, access removal, dependency review, backup state.</td><td><span class="badge yellow">Human Gate</span></td><td>Lifecycle affects audit, access, restoration, and readiness.</td><td>Preserve decision-ledger rationale.</td></tr>
                        <tr><td><strong>Approve privileged access</strong></td><td>Access Governance</td><td>MyAccess route, approver group, review proof, admin/vendor procedure.</td><td><span class="badge red">Blocked For AI</span></td><td>Access approval must remain accountable and human-governed.</td><td>Record denied AI authority and human route.</td></tr>
                        <tr><td><strong>Generate executive claim language</strong></td><td>Executive / Governance Owner</td><td>Claim Firewall result, evidence sufficiency, residual risk.</td><td><span class="badge green">AI Assist Allowed</span></td><td>AI may draft limitation language but cannot assert final reliance.</td><td>Capture claim basis and approved language.</td></tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Human Governance Engines</h2>
                <div class="cards">
                    <div class="card"><h3>Decision Ownership Router</h3><p>Routes AI recommendations to the correct human owner: QA, cyber, CMDB, system owner, validation, or executive governance.</p></div>
                    <div class="card"><h3>Execution Separation Gate</h3><p>Separates recommendation, approval, execution, verification, and reliance so AI cannot collapse governance roles.</p></div>
                    <div class="card"><h3>Accountability Preservation</h3><p>Ensures every regulated outcome has named human accountability and decision rationale.</p></div>
                    <div class="card"><h3>Human Approval Replay</h3><p>Preserves who approved, why, under what limitation, using which evidence, and with what rollback path.</p></div>
                </div>
            </section>

            <section class="section">
                <h2>Human-Governed AI Execution Rules</h2>
                <table>
                    <thead><tr><th>Condition</th><th>Rule</th><th>Human Role</th><th>System Response</th><th>Final State</th></tr></thead>
                    <tbody>
                        <tr><td>AI action is advisory and non-regulated.</td><td><span class="badge green">Allow</span></td><td>Optional reviewer.</td><td>Execute with Black Box capture.</td><td>Allowed.</td></tr>
                        <tr><td>AI action affects regulated trust state.</td><td><span class="badge yellow">Human Gate</span></td><td>Accountable owner required.</td><td>Hold for approval.</td><td>Conditional.</td></tr>
                        <tr><td>AI action lacks sufficient evidence.</td><td><span class="badge orange">Escalate</span></td><td>Evidence owner required.</td><td>Request evidence closure.</td><td>Blocked until complete.</td></tr>
                        <tr><td>AI action attempts forbidden decision.</td><td><span class="badge red">Block</span></td><td>Governance escalation.</td><td>Deny execution and preserve replay.</td><td>Blocked.</td></tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">CITrust™ Human-Governed AI Execution Board™ does not replace ServiceNow, AI Control Tower, CMDB, QA, validation, cyber, access governance, change control, or accountable human owners. It governs ServiceNow AI execution by preserving human accountability, evidence sufficiency, authority boundaries, replay, rollback, and inspection-ready decision rationale.</div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_HUMAN_GOVERNED_AI_EXECUTION_BOARD_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Human-Governed AI Execution Board installed.")
