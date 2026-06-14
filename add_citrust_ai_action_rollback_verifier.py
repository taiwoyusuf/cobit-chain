from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AI_ACTION_ROLLBACK_VERIFIER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/ai-action-rollback-verifier")'
ROUTE_ALIAS = '@app.route("/citrust/autonomous-rollback-verifier")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust AI Action Rollback Verifier already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AI_ACTION_ROLLBACK_VERIFIER_V1_ACTIVE
# ============================================================

@app.route("/citrust/ai-action-rollback-verifier")
@app.route("/citrust/autonomous-rollback-verifier")
def citrust_ai_action_rollback_verifier():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ AI Action Rollback Verifier</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root{--bg:#040b14;--panel:rgba(14,27,44,.92);--line:rgba(255,255,255,.12);--text:#eef5ff;--muted:#a8bbd4;--green:#31d07d;--yellow:#f7c948;--red:#ff5c70;--blue:#5cc8ff;--purple:#b49cff;--orange:#ffb86b;--cyan:#7efcff}
            *{box-sizing:border-box}
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at top left,rgba(49,208,125,.22),transparent 30%),radial-gradient(circle at top right,rgba(92,200,255,.18),transparent 28%),radial-gradient(circle at bottom right,rgba(255,92,112,.14),transparent 30%),var(--bg);color:var(--text)}
            .page{max-width:1460px;margin:0 auto;padding:28px}
            .hero{border:1px solid var(--line);background:linear-gradient(135deg,rgba(16,29,47,.98),rgba(20,40,66,.92));border-radius:26px;padding:30px;box-shadow:0 24px 80px rgba(0,0,0,.42)}
            .eyebrow{color:var(--cyan);font-size:13px;text-transform:uppercase;letter-spacing:1.9px;font-weight:900;margin-bottom:10px}
            h1{margin:0;font-size:42px;line-height:1.08}.subtitle{color:var(--muted);font-size:16px;line-height:1.65;max-width:1180px;margin-top:14px}
            .positioning{margin-top:18px;padding:17px 19px;border:1px solid rgba(49,208,125,.38);background:rgba(49,208,125,.10);border-radius:18px;color:#dfffea;line-height:1.6}
            .nav{display:flex;flex-wrap:wrap;gap:10px;margin-top:22px}.nav a{color:var(--text);text-decoration:none;border:1px solid var(--line);background:rgba(255,255,255,.06);padding:10px 13px;border-radius:999px;font-size:13px}
            .kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-top:20px}.metric{border:1px solid var(--line);background:var(--panel);border-radius:18px;padding:18px}.metric .label{color:var(--muted);font-size:13px;margin-bottom:8px}.metric .value{font-size:29px;font-weight:900}.metric .note{margin-top:8px;color:var(--muted);font-size:12px;line-height:1.4}
            .section{margin-top:24px;border:1px solid var(--line);background:var(--panel);border-radius:24px;padding:23px}.section h2{margin:0 0 8px 0;font-size:23px}.section p{color:var(--muted);line-height:1.56;margin-top:0}
            .answer{border:1px solid rgba(92,200,255,.38);background:rgba(92,200,255,.10);color:#d9f3ff;border-radius:18px;padding:20px;margin-top:16px;line-height:1.65;font-size:15px}
            .badge{display:inline-block;padding:6px 9px;border-radius:999px;font-size:12px;font-weight:900;white-space:nowrap}.green{color:#04140b;background:var(--green)}.yellow{color:#1d1600;background:var(--yellow)}.red{color:#fff;background:var(--red)}.blue{color:#06101d;background:var(--blue)}.purple{color:#120b24;background:var(--purple)}.orange{color:#211100;background:var(--orange)}
            .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-top:16px}.box{border:1px solid rgba(49,208,125,.32);background:linear-gradient(135deg,rgba(255,255,255,.06),rgba(49,208,125,.07)),rgba(255,255,255,.035);border-radius:22px;padding:22px;min-height:250px}.box h3{margin:0 0 12px 0;font-size:21px}.box ul{margin:0;padding-left:20px;color:var(--muted);font-size:14px;line-height:1.85}
            .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px}.card{border:1px solid var(--line);background:rgba(255,255,255,.045);border-radius:18px;padding:18px;min-height:150px}.card h3{margin:0 0 8px 0;font-size:17px}.card p{margin:0;color:var(--muted);font-size:14px;line-height:1.55}
            table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:16px;margin-top:16px}th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:#c9dbef;background:rgba(255,255,255,.07);padding:13px 12px;border-bottom:1px solid var(--line)}td{padding:13px 12px;border-bottom:1px solid rgba(255,255,255,.08);color:#e9f2ff;vertical-align:top;font-size:14px}tr:hover td{background:rgba(92,200,255,.05)}
            .footer{color:var(--muted);font-size:12px;margin-top:22px;line-height:1.6}
            @media(max-width:1180px){.kpis,.cards,.grid{grid-template-columns:1fr}h1{font-size:30px}table{display:block;overflow-x:auto;white-space:nowrap}}
        </style>
    </head>
    <body>
        <div class="page">
            <section class="hero">
                <div class="eyebrow">CITrust™ / ServiceNow AI / Rollback Assurance</div>
                <h1>CITrust™ AI Action Rollback Verifier</h1>
                <div class="subtitle">Verifies that every ServiceNow AI-assisted or autonomous action has a recoverable prior state, rollback owner, rollback method, post-rollback verification, and inspection-ready replay before the action can be trusted.</div>
                <div class="positioning"><strong>ServiceNow-focused positioning:</strong> ServiceNow AI should not execute meaningful operational change unless CITrust™ proves the action can be reversed, explained, verified, and defended if the outcome is rejected or unsafe.</div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a><a href="/citrust/autonomous-operations-risk-tier">Risk Tier</a><a href="/citrust/human-governed-ai-execution-board">Human-Governed AI</a><a href="/citrust/ai-evidence-sufficiency-index">Evidence Sufficiency</a><a href="/citrust/agentic-change-control-gate">Change Gate</a><a href="/citrust/regulatory-replay">Regulatory Replay</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Rollback Readiness</div><div class="value" style="color:var(--green);">Ready</div><div class="note">Rollback package exists for current AI action.</div></div>
                <div class="metric"><div class="label">Prior State Captured</div><div class="value" style="color:var(--green);">Yes</div><div class="note">Before-state preserved before execution.</div></div>
                <div class="metric"><div class="label">Rollback Owner</div><div class="value" style="color:var(--blue);">Assigned</div><div class="note">Accountable owner identified for recovery.</div></div>
                <div class="metric"><div class="label">Verification Plan</div><div class="value" style="color:var(--yellow);">Pending</div><div class="note">Post-rollback verification requires owner acceptance.</div></div>
                <div class="metric"><div class="label">Unsafe Actions Blocked</div><div class="value" style="color:var(--red);">3</div><div class="note">Actions blocked because rollback was not defensible.</div></div>
                <div class="metric"><div class="label">Execution Decision</div><div class="value" style="color:var(--yellow);">Conditional</div><div class="note">Proceed only after verification plan acceptance.</div></div>
            </section>

            <section class="section">
                <h2>Rollback Verifier Answer</h2>
                <div class="answer"><strong>Current rollback interpretation:</strong> CITrust™ allows ServiceNow AI to proceed only when the previous state, rollback method, rollback owner, recovery evidence, and verification criteria are captured. If rollback is missing, unclear, untested, or ownerless, the AI action is blocked or forced into human review.</div>
            </section>

            <section class="section">
                <h2>Rollback Readiness Zones</h2>
                <div class="grid">
                    <div class="box"><h3><span class="badge green">Rollback Ready</span></h3><ul><li>Previous state captured</li><li>Recovery method documented</li><li>Rollback owner assigned</li><li>Verification criteria defined</li><li>Replay package available</li><li>Residual risk accepted</li></ul></div>
                    <div class="box"><h3><span class="badge yellow">Rollback Conditional</span></h3><ul><li>Verification pending</li><li>Owner acceptance pending</li><li>Test evidence incomplete</li><li>Dependency review open</li><li>Exception unresolved</li><li>Claim must be limited</li></ul></div>
                    <div class="box"><h3><span class="badge red">Rollback Not Defensible</span></h3><ul><li>No prior state</li><li>No owner</li><li>No recovery path</li><li>No post-check</li><li>Evidence removed</li><li>Validated state uncertain</li></ul></div>
                </div>
            </section>

            <section class="section">
                <h2>Rollback Verification Matrix</h2>
                <table>
                    <thead><tr><th>AI Action</th><th>Rollback Requirement</th><th>Status</th><th>Risk If Missing</th><th>Execution Rule</th><th>Required Closure</th></tr></thead>
                    <tbody>
                        <tr><td><strong>Support group recommendation</strong></td><td>Previous support group, resolver path, approval history.</td><td><span class="badge green">Captured</span></td><td>Incident routing cannot be restored.</td><td>Allow recommendation; final update human-gated.</td><td>Reviewer approval.</td></tr>
                        <tr><td><strong>Lifecycle state change</strong></td><td>Prior lifecycle state, access state, closure proof, restoration path.</td><td><span class="badge yellow">Conditional</span></td><td>CI may be restored without defensible evidence.</td><td>Human approval mandatory.</td><td>Lifecycle owner and QA acceptance.</td></tr>
                        <tr><td><strong>Access-impacting update</strong></td><td>Previous entitlement, approver, access review, removal method.</td><td><span class="badge red">Incomplete</span></td><td>Privileged access state becomes indefensible.</td><td>Block autonomous execution.</td><td>Full access evidence bundle.</td></tr>
                        <tr><td><strong>Validated configuration update</strong></td><td>Baseline configuration, change record, test evidence, rollback test.</td><td><span class="badge red">Blocked</span></td><td>Validated state may be compromised.</td><td>AI cannot execute.</td><td>Formal change and validation review.</td></tr>
                        <tr><td><strong>Documentation update</strong></td><td>Previous text, change reason, author, approval if regulated.</td><td><span class="badge green">Ready</span></td><td>Incorrect documentation could persist.</td><td>Allow low-risk update with replay.</td><td>Post-action review.</td></tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Rollback Assurance Engines</h2>
                <div class="cards">
                    <div class="card"><h3>Prior-State Capture</h3><p>Preserves the state before AI-assisted change so recovery can be proven.</p></div>
                    <div class="card"><h3>Recovery Path Verifier</h3><p>Checks whether rollback can be executed, owned, verified, and documented.</p></div>
                    <div class="card"><h3>Post-Rollback Verification</h3><p>Requires evidence that the system returned to expected governed state.</p></div>
                    <div class="card"><h3>Rollback Claim Firewall</h3><p>Blocks any claim that an AI action is safe if recovery cannot be defended.</p></div>
                </div>
            </section>

            <section class="section">
                <h2>Rollback Go/No-Go Rules</h2>
                <table>
                    <thead><tr><th>Condition</th><th>Decision</th><th>Human Gate</th><th>Replay Requirement</th><th>Final State</th></tr></thead>
                    <tbody>
                        <tr><td>Rollback complete, owner assigned, verification defined.</td><td><span class="badge green">Allow</span></td><td>Optional for low risk.</td><td>Capture before/after and recovery method.</td><td>Rollback ready.</td></tr>
                        <tr><td>Rollback available but verification pending.</td><td><span class="badge yellow">Conditional</span></td><td>Required for Tier 3 actions.</td><td>Capture limitation and pending verification.</td><td>Human-gated.</td></tr>
                        <tr><td>Rollback missing or ownerless.</td><td><span class="badge red">Block</span></td><td>Governance escalation.</td><td>Record denial reason.</td><td>Execution blocked.</td></tr>
                        <tr><td>Validated state may be affected.</td><td><span class="badge red">Formal Change</span></td><td>QA / Validation required.</td><td>Capture impact and test plan.</td><td>No autonomous execution.</td></tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">CITrust™ AI Action Rollback Verifier™ does not replace ServiceNow Change, QA, validation, system owner approval, or technical recovery procedures. It governs ServiceNow AI actions by requiring prior-state capture, rollback ownership, recovery path, verification evidence, replay, and human approval before operational trust is granted.</div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AI_ACTION_ROLLBACK_VERIFIER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust AI Action Rollback Verifier installed.")
