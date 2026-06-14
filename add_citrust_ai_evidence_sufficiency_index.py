from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AI_EVIDENCE_SUFFICIENCY_INDEX_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/ai-evidence-sufficiency-index")'
ROUTE_ALIAS = '@app.route("/citrust/evidence-sufficiency-index")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust AI Evidence Sufficiency Index already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AI_EVIDENCE_SUFFICIENCY_INDEX_V1_ACTIVE
# ============================================================

@app.route("/citrust/ai-evidence-sufficiency-index")
@app.route("/citrust/evidence-sufficiency-index")
def citrust_ai_evidence_sufficiency_index():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ AI Evidence Sufficiency Index</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root{--bg:#040b14;--panel:rgba(14,27,44,.92);--line:rgba(255,255,255,.12);--text:#eef5ff;--muted:#a8bbd4;--green:#31d07d;--yellow:#f7c948;--red:#ff5c70;--blue:#5cc8ff;--purple:#b49cff;--orange:#ffb86b;--cyan:#7efcff}
            *{box-sizing:border-box}
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at top left,rgba(49,208,125,.22),transparent 30%),radial-gradient(circle at top right,rgba(92,200,255,.18),transparent 28%),radial-gradient(circle at bottom right,rgba(247,201,72,.14),transparent 30%),var(--bg);color:var(--text)}
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
            .index-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:16px}.box{border:1px solid rgba(49,208,125,.32);background:linear-gradient(135deg,rgba(255,255,255,.06),rgba(49,208,125,.07)),rgba(255,255,255,.035);border-radius:22px;padding:22px;min-height:300px}.box h3{margin:0 0 12px 0;font-size:21px}
            .row{display:grid;grid-template-columns:190px 1fr 70px;gap:12px;align-items:center;padding:11px 0;border-bottom:1px solid rgba(255,255,255,.08);font-size:14px}.row .key{color:var(--muted)}.bar{height:11px;border-radius:999px;background:rgba(255,255,255,.10);overflow:hidden}.fill{height:100%;border-radius:999px}.score{text-align:right;color:var(--text);font-weight:900}
            .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px}.card{border:1px solid var(--line);background:rgba(255,255,255,.045);border-radius:18px;padding:18px;min-height:150px}.card h3{margin:0 0 8px 0;font-size:17px}.card p{margin:0;color:var(--muted);font-size:14px;line-height:1.55}
            table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:16px;margin-top:16px}th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:#c9dbef;background:rgba(255,255,255,.07);padding:13px 12px;border-bottom:1px solid var(--line)}td{padding:13px 12px;border-bottom:1px solid rgba(255,255,255,.08);color:#e9f2ff;vertical-align:top;font-size:14px}tr:hover td{background:rgba(92,200,255,.05)}
            .footer{color:var(--muted);font-size:12px;margin-top:22px;line-height:1.6}
            @media(max-width:1180px){.kpis,.cards,.index-grid{grid-template-columns:1fr}.row{grid-template-columns:1fr}.score{text-align:left}h1{font-size:30px}table{display:block;overflow-x:auto;white-space:nowrap}}
        </style>
    </head>
    <body>
        <div class="page">
            <section class="hero">
                <div class="eyebrow">CITrust™ / ServiceNow AI / Evidence Sufficiency Gate</div>
                <h1>CITrust™ AI Evidence Sufficiency Index</h1>
                <div class="subtitle">Measures whether the evidence available in and around ServiceNow is sufficient for an AI agent to recommend, execute, escalate, block, or support a regulated governance decision.</div>
                <div class="positioning"><strong>ServiceNow-focused positioning:</strong> ServiceNow AI can act only when the evidence is strong enough. CITrust™ converts raw CI, access, support, lifecycle, validation, exception, rollback, and replay signals into a defensible evidence sufficiency decision.</div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a><a href="/citrust/agentic-validation-impact-assessor">Validation Impact</a><a href="/citrust/agentic-change-control-gate">Change Gate</a><a href="/citrust/servicenow-ai-readiness-command-center">AI Readiness</a><a href="/citrust/governance-operating-system">GovOS</a><a href="/citrust/regulatory-replay">Regulatory Replay</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Evidence Sufficiency</div><div class="value" style="color:var(--green);">87%</div><div class="note">Sufficient for recommendation, conditional for execution.</div></div>
                <div class="metric"><div class="label">Decision</div><div class="value" style="color:var(--yellow);">Human Gate</div><div class="note">High-impact action requires accountable approval.</div></div>
                <div class="metric"><div class="label">Weakest Evidence</div><div class="value" style="color:var(--orange);">Access</div><div class="note">Access proof and review freshness require closure.</div></div>
                <div class="metric"><div class="label">Replay Proof</div><div class="value" style="color:var(--green);">Ready</div><div class="note">Black Box replay supports inspection defense.</div></div>
                <div class="metric"><div class="label">Blocked Claims</div><div class="value" style="color:var(--red);">3</div><div class="note">Claims rejected due to evidence insufficiency.</div></div>
                <div class="metric"><div class="label">Go/No-Go</div><div class="value" style="color:var(--yellow);">Proceed With Limits</div><div class="note">AI may assist; final reliance remains human-governed.</div></div>
            </section>

            <section class="section">
                <h2>Evidence Sufficiency Answer</h2>
                <div class="answer"><strong>Current sufficiency interpretation:</strong> The evidence is strong enough for ServiceNow AI to prepare recommendations, generate readiness packs, and flag governance gaps. It is not strong enough for autonomous privileged access, certificate readiness, lifecycle change, validation-impacting execution, or executive reliance without human approval.</div>
            </section>

            <section class="section">
                <h2>Evidence Sufficiency Profile</h2>
                <div class="index-grid">
                    <div class="box">
                        <h3>Evidence Domain Scores</h3>
                        <div class="row"><div class="key">CMDB Identity</div><div class="bar"><div class="fill" style="width:94%;background:var(--green)"></div></div><div class="score">94</div></div>
                        <div class="row"><div class="key">Support / LCM</div><div class="bar"><div class="fill" style="width:76%;background:var(--yellow)"></div></div><div class="score">76</div></div>
                        <div class="row"><div class="key">Access Governance</div><div class="bar"><div class="fill" style="width:68%;background:var(--orange)"></div></div><div class="score">68</div></div>
                        <div class="row"><div class="key">Lifecycle Evidence</div><div class="bar"><div class="fill" style="width:91%;background:var(--green)"></div></div><div class="score">91</div></div>
                        <div class="row"><div class="key">Validation Impact</div><div class="bar"><div class="fill" style="width:82%;background:var(--blue)"></div></div><div class="score">82</div></div>
                        <div class="row"><div class="key">Rollback / Replay</div><div class="bar"><div class="fill" style="width:96%;background:var(--green)"></div></div><div class="score">96</div></div>
                    </div>
                    <div class="box">
                        <h3>Decision Thresholds</h3>
                        <table>
                            <thead><tr><th>Index</th><th>AI Decision</th><th>Governance Rule</th></tr></thead>
                            <tbody>
                                <tr><td>90–100%</td><td><span class="badge green">Allow Assisted</span></td><td>AI can prepare, recommend, and route with Black Box capture.</td></tr>
                                <tr><td>75–89%</td><td><span class="badge yellow">Human Gate</span></td><td>AI may recommend; accountable owner must approve.</td></tr>
                                <tr><td>60–74%</td><td><span class="badge orange">Conditional</span></td><td>Claim must be downgraded; evidence closure required.</td></tr>
                                <tr><td>Below 60%</td><td><span class="badge red">Block</span></td><td>AI action and executive claim blocked until evidence recovers.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Evidence Sufficiency Matrix</h2>
                <table>
                    <thead><tr><th>Evidence Area</th><th>Required Proof</th><th>Status</th><th>AI Action Allowed</th><th>Blocked Claim</th><th>Closure Requirement</th></tr></thead>
                    <tbody>
                        <tr><td><strong>CMDB Identity</strong></td><td>CI name, class, owner, environment, relationship basis.</td><td><span class="badge green">Strong</span></td><td>Draft candidate and evidence pack.</td><td>None.</td><td>Maintain relationship verification.</td></tr>
                        <tr><td><strong>Support / LCM</strong></td><td>Support group, resolver path, LCM, escalation owner, cadence.</td><td><span class="badge yellow">Partial</span></td><td>Recommend only.</td><td>Support is fully reliable.</td><td>Make support and LCM gate mandatory.</td></tr>
                        <tr><td><strong>Access Governance</strong></td><td>MyAccess, approver group, admin/vendor procedure, review proof.</td><td><span class="badge orange">Weak</span></td><td>Flag gaps only.</td><td>Access is fully defensible.</td><td>Complete access evidence bundle.</td></tr>
                        <tr><td><strong>Validation Impact</strong></td><td>Impact rationale, QA/CSV review, test evidence, rollback.</td><td><span class="badge blue">Reviewable</span></td><td>Prepare assessment.</td><td>AI approved no-impact.</td><td>Human validation approval required.</td></tr>
                        <tr><td><strong>Replay / Rollback</strong></td><td>Prompt, evidence, policy, authority, previous state, rollback owner.</td><td><span class="badge green">Strong</span></td><td>Replay package generation.</td><td>None if complete.</td><td>Preserve Black Box record.</td></tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Evidence Sufficiency Engines</h2>
                <div class="cards">
                    <div class="card"><h3>Proof Completeness Engine</h3><p>Checks whether all required evidence artifacts exist before AI action or reliance.</p></div>
                    <div class="card"><h3>Evidence Freshness Engine</h3><p>Detects stale access reviews, outdated support records, aged exceptions, and certificate drift.</p></div>
                    <div class="card"><h3>Claim Support Engine</h3><p>Maps each executive or AI claim to the proof required to defend it.</p></div>
                    <div class="card"><h3>Go/No-Go Engine</h3><p>Converts sufficiency score into allow, human-gate, conditional, or block decision.</p></div>
                </div>
            </section>

            <div class="footer">CITrust™ AI Evidence Sufficiency Index™ does not replace ServiceNow, QA, validation, cyber, CMDB governance, or human approval. It determines whether ServiceNow AI has enough governed evidence to recommend, execute, escalate, block, or support a regulated assurance claim.</div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AI_EVIDENCE_SUFFICIENCY_INDEX_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust AI Evidence Sufficiency Index installed.")
