from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AI_RESIDUAL_RISK_ACCEPTANCE_LEDGER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/ai-residual-risk-acceptance-ledger")'
ROUTE_ALIAS = '@app.route("/citrust/autonomous-risk-acceptance-ledger")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust AI Residual Risk Acceptance Ledger already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AI_RESIDUAL_RISK_ACCEPTANCE_LEDGER_V1_ACTIVE
# ============================================================

@app.route("/citrust/ai-residual-risk-acceptance-ledger")
@app.route("/citrust/autonomous-risk-acceptance-ledger")
def citrust_ai_residual_risk_acceptance_ledger():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ AI Residual Risk Acceptance Ledger</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root{--bg:#040b14;--panel:rgba(14,27,44,.92);--line:rgba(255,255,255,.12);--text:#eef5ff;--muted:#a8bbd4;--green:#31d07d;--yellow:#f7c948;--red:#ff5c70;--blue:#5cc8ff;--purple:#b49cff;--orange:#ffb86b;--cyan:#7efcff}
            *{box-sizing:border-box}
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at top left,rgba(255,184,107,.22),transparent 30%),radial-gradient(circle at top right,rgba(255,92,112,.18),transparent 28%),radial-gradient(circle at bottom right,rgba(92,200,255,.14),transparent 30%),var(--bg);color:var(--text)}
            .page{max-width:1460px;margin:0 auto;padding:28px}
            .hero{border:1px solid var(--line);background:linear-gradient(135deg,rgba(16,29,47,.98),rgba(20,40,66,.92));border-radius:26px;padding:30px;box-shadow:0 24px 80px rgba(0,0,0,.42)}
            .eyebrow{color:var(--cyan);font-size:13px;text-transform:uppercase;letter-spacing:1.9px;font-weight:900;margin-bottom:10px}
            h1{margin:0;font-size:42px;line-height:1.08}.subtitle{color:var(--muted);font-size:16px;line-height:1.65;max-width:1180px;margin-top:14px}
            .positioning{margin-top:18px;padding:17px 19px;border:1px solid rgba(255,184,107,.38);background:rgba(255,184,107,.10);border-radius:18px;color:#ffe8c9;line-height:1.6}
            .nav{display:flex;flex-wrap:wrap;gap:10px;margin-top:22px}.nav a{color:var(--text);text-decoration:none;border:1px solid var(--line);background:rgba(255,255,255,.06);padding:10px 13px;border-radius:999px;font-size:13px}
            .kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-top:20px}.metric{border:1px solid var(--line);background:var(--panel);border-radius:18px;padding:18px}.metric .label{color:var(--muted);font-size:13px;margin-bottom:8px}.metric .value{font-size:29px;font-weight:900}.metric .note{margin-top:8px;color:var(--muted);font-size:12px;line-height:1.4}
            .section{margin-top:24px;border:1px solid var(--line);background:var(--panel);border-radius:24px;padding:23px}.section h2{margin:0 0 8px 0;font-size:23px}.section p{color:var(--muted);line-height:1.56;margin-top:0}
            .answer{border:1px solid rgba(92,200,255,.38);background:rgba(92,200,255,.10);color:#d9f3ff;border-radius:18px;padding:20px;margin-top:16px;line-height:1.65;font-size:15px}
            .badge{display:inline-block;padding:6px 9px;border-radius:999px;font-size:12px;font-weight:900;white-space:nowrap}.green{color:#04140b;background:var(--green)}.yellow{color:#1d1600;background:var(--yellow)}.red{color:#fff;background:var(--red)}.blue{color:#06101d;background:var(--blue)}.purple{color:#120b24;background:var(--purple)}.orange{color:#211100;background:var(--orange)}
            .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-top:16px}.box{border:1px solid rgba(255,184,107,.32);background:linear-gradient(135deg,rgba(255,255,255,.06),rgba(255,184,107,.07)),rgba(255,255,255,.035);border-radius:22px;padding:22px;min-height:250px}.box h3{margin:0 0 12px 0;font-size:21px}.box ul{margin:0;padding-left:20px;color:var(--muted);font-size:14px;line-height:1.85}
            .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px}.card{border:1px solid var(--line);background:rgba(255,255,255,.045);border-radius:18px;padding:18px;min-height:150px}.card h3{margin:0 0 8px 0;font-size:17px}.card p{margin:0;color:var(--muted);font-size:14px;line-height:1.55}
            table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:16px;margin-top:16px}th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:#c9dbef;background:rgba(255,255,255,.07);padding:13px 12px;border-bottom:1px solid var(--line)}td{padding:13px 12px;border-bottom:1px solid rgba(255,255,255,.08);color:#e9f2ff;vertical-align:top;font-size:14px}tr:hover td{background:rgba(92,200,255,.05)}
            .footer{color:var(--muted);font-size:12px;margin-top:22px;line-height:1.6}
            @media(max-width:1180px){.kpis,.cards,.grid{grid-template-columns:1fr}h1{font-size:30px}table{display:block;overflow-x:auto;white-space:nowrap}}
        </style>
    </head>
    <body>
        <div class="page">
            <section class="hero">
                <div class="eyebrow">CITrust™ / ServiceNow AI / Residual Risk Accountability</div>
                <h1>CITrust™ AI Residual Risk Acceptance Ledger</h1>
                <div class="subtitle">Records who accepted residual risk when ServiceNow AI recommendations proceed with incomplete evidence, conditional readiness, open exceptions, access gaps, validation uncertainty, or limited executive reliance.</div>
                <div class="positioning"><strong>ServiceNow-focused positioning:</strong> CITrust™ prevents ServiceNow AI from silently converting unresolved governance gaps into operational confidence. Every residual risk must have owner, rationale, evidence boundary, expiry, escalation path, and replay record.</div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a><a href="/citrust/ai-policy-compliance-router">Policy Router</a><a href="/citrust/ai-evidence-lineage-mapper">Evidence Lineage</a><a href="/citrust/ai-decision-rights-matrix">Decision Rights</a><a href="/citrust/ai-evidence-sufficiency-index">Evidence Sufficiency</a><a href="/citrust/governance-operating-system">GovOS</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Residual Risks</div><div class="value" style="color:var(--orange);">12</div><div class="note">Open AI-related governance risks requiring owner tracking.</div></div>
                <div class="metric"><div class="label">Accepted With Owner</div><div class="value" style="color:var(--green);">8</div><div class="note">Risks with named accountable owner and rationale.</div></div>
                <div class="metric"><div class="label">Owner Missing</div><div class="value" style="color:var(--red);">2</div><div class="note">Residual risk cannot be accepted without ownership.</div></div>
                <div class="metric"><div class="label">Expiry Required</div><div class="value" style="color:var(--yellow);">5</div><div class="note">Temporary acceptances need closure date.</div></div>
                <div class="metric"><div class="label">AI Reliance Impact</div><div class="value" style="color:var(--yellow);">Conditional</div><div class="note">Executive claims must use limitation language.</div></div>
                <div class="metric"><div class="label">Ledger Decision</div><div class="value" style="color:var(--orange);">Escalate</div><div class="note">Unowned risks require governance escalation.</div></div>
            </section>

            <section class="section">
                <h2>Residual Risk Ledger Answer</h2>
                <div class="answer"><strong>Current ledger interpretation:</strong> ServiceNow AI recommendations can proceed only where residual risk is explicitly accepted by an accountable human owner, tied to evidence boundaries, given an expiry date, linked to a closure action, and preserved in the Governance Black Box. Unowned residual risk blocks executive reliance.</div>
            </section>

            <section class="section">
                <h2>Residual Risk Acceptance Zones</h2>
                <div class="grid">
                    <div class="box"><h3><span class="badge green">Acceptable With Controls</span></h3><ul><li>Named risk owner</li><li>Documented rationale</li><li>Evidence boundary clear</li><li>Expiry date assigned</li><li>Closure action defined</li><li>Replay preserved</li></ul></div>
                    <div class="box"><h3><span class="badge yellow">Conditional Acceptance</span></h3><ul><li>Temporary evidence gap</li><li>Pending reviewer acceptance</li><li>Open exception with expiry</li><li>Limited reliance language</li><li>Escalation owner required</li><li>Monitoring cadence defined</li></ul></div>
                    <div class="box"><h3><span class="badge red">Not Acceptable</span></h3><ul><li>No risk owner</li><li>No rationale</li><li>No expiry</li><li>No evidence boundary</li><li>No closure action</li><li>AI overstates readiness</li></ul></div>
                </div>
            </section>

            <section class="section">
                <h2>AI Residual Risk Ledger Matrix</h2>
                <table>
                    <thead><tr><th>Residual Risk</th><th>AI Context</th><th>Owner</th><th>Status</th><th>Allowed Claim</th><th>Closure Requirement</th></tr></thead>
                    <tbody>
                        <tr><td><strong>Support / LCM evidence partial</strong></td><td>AI recommends support correction.</td><td>Service Owner / LCM</td><td><span class="badge yellow">Accepted Temporarily</span></td><td>Conditionally supportable.</td><td>Support group, resolver path, LCM, escalation owner acceptance.</td></tr>
                        <tr><td><strong>Access proof stale</strong></td><td>AI prepares access defensibility package.</td><td>Access Governance</td><td><span class="badge orange">Open</span></td><td>Access defensibility improving, not complete.</td><td>MyAccess, approver group, review proof, admin/vendor procedure.</td></tr>
                        <tr><td><strong>Validation impact uncertainty</strong></td><td>AI drafts impact assessment.</td><td>QA / CSV / System Owner</td><td><span class="badge yellow">Human Review</span></td><td>Impact assessment pending approval.</td><td>QA/CSV conclusion and test evidence.</td></tr>
                        <tr><td><strong>Certificate readiness limitation</strong></td><td>AI prepares certificate pack.</td><td>Governance Owner</td><td><span class="badge yellow">Conditional</span></td><td>Certificate-ready only after evidence freshness check.</td><td>Evidence age, exception state, decision rationale.</td></tr>
                        <tr><td><strong>Unowned hidden dependency</strong></td><td>AI detects dependency with no CI candidate.</td><td>Missing</td><td><span class="badge red">Blocked</span></td><td>No reliance allowed.</td><td>Create CI candidate with owner, support, access, evidence, cadence.</td></tr>
                        <tr><td><strong>Rollback verification pending</strong></td><td>AI action has rollback but no accepted verification.</td><td>Technical Owner</td><td><span class="badge orange">Pending</span></td><td>Execution conditional.</td><td>Post-rollback verification acceptance.</td></tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Residual Risk Engines</h2>
                <div class="cards">
                    <div class="card"><h3>Risk Acceptance Gate</h3><p>Blocks AI-supported reliance unless residual risk has a named owner, rationale, expiry, and closure action.</p></div>
                    <div class="card"><h3>Limitation Language Engine</h3><p>Converts residual-risk state into safe executive wording that avoids overclaiming readiness.</p></div>
                    <div class="card"><h3>Expiry Escalation Engine</h3><p>Escalates residual risk when expiry date approaches or closure evidence is missing.</p></div>
                    <div class="card"><h3>Risk Replay Binder</h3><p>Links accepted risk to AI recommendation, evidence boundary, human approval, and Black Box replay.</p></div>
                </div>
            </section>

            <div class="footer">CITrust™ AI Residual Risk Acceptance Ledger™ does not replace ServiceNow risk, IRM/GRC, QA, validation, cyber, or executive accountability. It ensures residual risk created by ServiceNow AI-assisted operations is human-owned, evidence-bounded, time-limited, replayable, and clearly reflected in executive reliance language.</div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AI_RESIDUAL_RISK_ACCEPTANCE_LEDGER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust AI Residual Risk Acceptance Ledger installed.")
