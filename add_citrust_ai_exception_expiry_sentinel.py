from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AI_EXCEPTION_EXPIRY_SENTINEL_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/ai-exception-expiry-sentinel")'
ROUTE_ALIAS = '@app.route("/citrust/autonomous-exception-sentinel")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust AI Exception Expiry Sentinel already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AI_EXCEPTION_EXPIRY_SENTINEL_V1_ACTIVE
# ============================================================

@app.route("/citrust/ai-exception-expiry-sentinel")
@app.route("/citrust/autonomous-exception-sentinel")
def citrust_ai_exception_expiry_sentinel():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ AI Exception Expiry Sentinel</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root{--bg:#040b14;--panel:rgba(14,27,44,.92);--line:rgba(255,255,255,.12);--text:#eef5ff;--muted:#a8bbd4;--green:#31d07d;--yellow:#f7c948;--red:#ff5c70;--blue:#5cc8ff;--purple:#b49cff;--orange:#ffb86b;--cyan:#7efcff}
            *{box-sizing:border-box}
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at top left,rgba(255,92,112,.22),transparent 30%),radial-gradient(circle at top right,rgba(247,201,72,.18),transparent 28%),radial-gradient(circle at bottom right,rgba(92,200,255,.14),transparent 30%),var(--bg);color:var(--text)}
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
                <div class="eyebrow">CITrust™ / ServiceNow AI / Exception Expiry Governance</div>
                <h1>CITrust™ AI Exception Expiry Sentinel</h1>
                <div class="subtitle">Monitors every exception used by ServiceNow AI, detects expiry risk, blocks expired exception reliance, escalates unowned exceptions, and prevents temporary governance exceptions from becoming permanent operational trust debt.</div>
                <div class="positioning"><strong>ServiceNow-focused positioning:</strong> CITrust™ ensures ServiceNow AI cannot rely on expired, ownerless, stale, or unclosed exceptions when making recommendations, generating readiness language, or supporting executive trust claims.</div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a><a href="/citrust/ai-residual-risk-acceptance-ledger">Residual Risk Ledger</a><a href="/citrust/ai-policy-compliance-router">Policy Router</a><a href="/citrust/ai-evidence-lineage-mapper">Evidence Lineage</a><a href="/citrust/trust-immune-system">Trust Immune System</a><a href="/citrust/governance-operating-system">GovOS</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Open Exceptions</div><div class="value" style="color:var(--orange);">14</div><div class="note">Exceptions currently influencing ServiceNow AI trust posture.</div></div>
                <div class="metric"><div class="label">Expiring Soon</div><div class="value" style="color:var(--yellow);">5</div><div class="note">Exceptions requiring closure, renewal, or escalation.</div></div>
                <div class="metric"><div class="label">Expired</div><div class="value" style="color:var(--red);">2</div><div class="note">Expired exceptions cannot support AI reliance.</div></div>
                <div class="metric"><div class="label">Owner Missing</div><div class="value" style="color:var(--red);">1</div><div class="note">Exception requires governance assignment before reliance.</div></div>
                <div class="metric"><div class="label">AI Claims Downgraded</div><div class="value" style="color:var(--yellow);">6</div><div class="note">Readiness claims limited due to exception exposure.</div></div>
                <div class="metric"><div class="label">Sentinel Decision</div><div class="value" style="color:var(--red);">Escalate</div><div class="note">Expired and unowned exceptions need immediate escalation.</div></div>
            </section>

            <section class="section">
                <h2>Exception Expiry Sentinel Answer</h2>
                <div class="answer"><strong>Current sentinel interpretation:</strong> ServiceNow AI may reference open exceptions only if each exception has an owner, expiry date, residual-risk rationale, closure action, escalation owner, and evidence link. Expired or unowned exceptions must block readiness claims and trigger escalation.</div>
            </section>

            <section class="section">
                <h2>Exception Sentinel Zones</h2>
                <div class="grid">
                    <div class="box"><h3><span class="badge green">Controlled Exception</span></h3><ul><li>Owner assigned</li><li>Expiry date active</li><li>Risk rationale documented</li><li>Closure action defined</li><li>Evidence linked</li><li>Replay preserved</li></ul></div>
                    <div class="box"><h3><span class="badge yellow">Expiring Exception</span></h3><ul><li>Expiry approaching</li><li>Renewal requires review</li><li>Claim language limited</li><li>Escalation owner required</li><li>Closure evidence pending</li><li>AI reliance conditional</li></ul></div>
                    <div class="box"><h3><span class="badge red">Expired / Unsafe Exception</span></h3><ul><li>Expired exception</li><li>No owner</li><li>No closure action</li><li>No residual-risk approval</li><li>No evidence link</li><li>Blocks AI reliance</li></ul></div>
                </div>
            </section>

            <section class="section">
                <h2>Exception Expiry Matrix</h2>
                <table>
                    <thead><tr><th>Exception</th><th>AI Context</th><th>Status</th><th>Trust Impact</th><th>Required Action</th><th>Allowed Claim</th></tr></thead>
                    <tbody>
                        <tr><td><strong>Support evidence exception</strong></td><td>AI recommends support group correction.</td><td><span class="badge yellow">Expiring Soon</span></td><td>Support trust remains conditional.</td><td>Confirm LCM, resolver path, escalation owner.</td><td>Support readiness improving, not complete.</td></tr>
                        <tr><td><strong>Access review exception</strong></td><td>AI prepares access defensibility package.</td><td><span class="badge red">Expired</span></td><td>Access claim blocked.</td><td>Refresh access review and approver evidence.</td><td>No full access defensibility claim allowed.</td></tr>
                        <tr><td><strong>Hidden dependency exception</strong></td><td>AI detects dependency without CI candidate.</td><td><span class="badge red">Owner Missing</span></td><td>Dependency cannot support trust.</td><td>Create candidate record and assign owner.</td><td>No reliance allowed.</td></tr>
                        <tr><td><strong>Certificate freshness exception</strong></td><td>AI prepares certificate package.</td><td><span class="badge yellow">Open</span></td><td>Certificate-ready is conditional.</td><td>Link evidence freshness to certificate decision.</td><td>Certificate-ready pending evidence closure.</td></tr>
                        <tr><td><strong>Rollback verification exception</strong></td><td>AI action has rollback but pending post-check.</td><td><span class="badge orange">Open</span></td><td>Execution remains conditional.</td><td>Complete verification and owner acceptance.</td><td>Proceed with limits only.</td></tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Exception Sentinel Engines</h2>
                <div class="cards">
                    <div class="card"><h3>Expiry Watch Engine</h3><p>Tracks exception age, expiry, renewal attempts, closure evidence, and escalation timing.</p></div>
                    <div class="card"><h3>Expired Reliance Blocker</h3><p>Blocks ServiceNow AI and executive claims from relying on expired or ownerless exceptions.</p></div>
                    <div class="card"><h3>Escalation Router</h3><p>Routes exception risk to the accountable owner before trust debt becomes normalized.</p></div>
                    <div class="card"><h3>Exception Claim Downgrader</h3><p>Forces limitation language where exceptions remain open or evidence is incomplete.</p></div>
                </div>
            </section>

            <div class="footer">CITrust™ AI Exception Expiry Sentinel™ does not replace ServiceNow IRM/GRC, change, QA, validation, cyber, or human governance. It ensures ServiceNow AI cannot rely on expired, unowned, stale, or unresolved exceptions when generating recommendations, readiness packages, certificates, or executive assurance language.</div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AI_EXCEPTION_EXPIRY_SENTINEL_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust AI Exception Expiry Sentinel installed.")
