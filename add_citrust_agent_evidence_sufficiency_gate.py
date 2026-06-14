from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENT_EVIDENCE_SUFFICIENCY_GATE_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/agent-evidence-sufficiency-gate")'
ROUTE_ALIAS = '@app.route("/citrust/evidence-sufficiency-gate")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Agent Evidence Sufficiency Gate already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AGENT_EVIDENCE_SUFFICIENCY_GATE_V1_ACTIVE
# ============================================================

@app.route("/citrust/agent-evidence-sufficiency-gate")
@app.route("/citrust/evidence-sufficiency-gate")
def citrust_agent_evidence_sufficiency_gate():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Agent Evidence Sufficiency Gate</title>
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
                <div class="eyebrow">CITrust™ / ServiceNow AI / Evidence Sufficiency Governance</div>
                <h1>CITrust™ Agent Evidence Sufficiency Gate</h1>
                <div class="subtitle">Determines whether a ServiceNow AI agent has enough evidence to recommend, route, execute, escalate, or support a governance claim before any CI trust, access, lifecycle, support, certificate, validation, or readiness decision is allowed.</div>
                <div class="positioning"><strong>ServiceNow-focused positioning:</strong> ServiceNow AI can act quickly. CITrust™ Evidence Sufficiency Gate decides whether the evidence is strong enough for that action to be trusted, replayed, defended, and accepted by human governance.</div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a><a href="/citrust/agentic-validation-impact-assessor">Validation Impact</a><a href="/citrust/agentic-change-control-gate">Agentic Change Gate</a><a href="/citrust/servicenow-ai-readiness-command-center">AI Readiness</a><a href="/citrust/governance-operating-system">GovOS</a><a href="/citrust/regulatory-replay">Regulatory Replay</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Evidence Sufficiency</div><div class="value" style="color:var(--green);">91%</div><div class="note">Strong for assisted actions; conditional for regulated decisions.</div></div>
                <div class="metric"><div class="label">Minimum Threshold</div><div class="value" style="color:var(--blue);">85%</div><div class="note">Minimum evidence threshold for bounded ServiceNow AI execution.</div></div>
                <div class="metric"><div class="label">Critical Gaps</div><div class="value" style="color:var(--orange);">3</div><div class="note">Support, access, and exception evidence require closure.</div></div>
                <div class="metric"><div class="label">Action Decision</div><div class="value" style="color:var(--yellow);">Partial Allow</div><div class="note">Allow recommendations; human-gate final decisions.</div></div>
                <div class="metric"><div class="label">Claim Firewall</div><div class="value" style="color:var(--green);">Passed</div><div class="note">With limitation language and evidence boundary.</div></div>
                <div class="metric"><div class="label">Inspection Defense</div><div class="value" style="color:var(--blue);">Replayable</div><div class="note">Evidence basis is sufficient for replay package.</div></div>
            </section>

            <section class="section">
                <h2>Evidence Sufficiency Answer</h2>
                <div class="answer"><strong>Current gate decision:</strong> The evidence is sufficient for the ServiceNow AI agent to draft recommendations, prepare evidence packs, flag gaps, and generate replay records. It is not sufficient for autonomous final approval of lifecycle, access, certificate, validation, support ownership, or regulated readiness decisions.</div>
            </section>

            <section class="section">
                <h2>Evidence Sufficiency Zones</h2>
                <div class="grid">
                    <div class="box"><h3><span class="badge green">Sufficient</span></h3><ul><li>CMDB identity</li><li>CI class and environment</li><li>Basic owner evidence</li><li>Lifecycle status visibility</li><li>Black Box replay trace</li><li>Rollback draft</li></ul></div>
                    <div class="box"><h3><span class="badge yellow">Conditionally Sufficient</span></h3><ul><li>Support group evidence</li><li>LCM confirmation</li><li>Certificate freshness</li><li>Exception owner</li><li>Access review proof</li><li>Post-change verification</li></ul></div>
                    <div class="box"><h3><span class="badge red">Insufficient for Autonomy</span></h3><ul><li>Privileged access approval</li><li>Validation impact conclusion</li><li>CAPA closure</li><li>Regulated readiness certification</li><li>Trust score override</li><li>Evidence deletion</li></ul></div>
                </div>
            </section>

            <section class="section">
                <h2>Evidence Sufficiency Matrix</h2>
                <table>
                    <thead><tr><th>Evidence Domain</th><th>Current Proof</th><th>Score</th><th>AI Permission</th><th>Human Gate</th><th>Closure Requirement</th></tr></thead>
                    <tbody>
                        <tr><td><strong>CMDB Identity</strong></td><td>CI name, class, owner, environment, criticality, and relationship basis.</td><td><span class="badge green">96%</span></td><td>Draft and recommend allowed.</td><td>Final approval if regulated.</td><td>Maintain identity verification.</td></tr>
                        <tr><td><strong>Support / LCM</strong></td><td>Support group visible; resolver path and LCM evidence need stronger enforcement.</td><td><span class="badge yellow">76%</span></td><td>Recommendation only.</td><td>Service owner / CMDB owner.</td><td>Mandatory support and LCM gate.</td></tr>
                        <tr><td><strong>Access Governance</strong></td><td>MyAccess mapping exists; admin/vendor procedure and review proof conditional.</td><td><span class="badge yellow">72%</span></td><td>Gap detection only.</td><td>Access governance owner.</td><td>Full access evidence bundle.</td></tr>
                        <tr><td><strong>Lifecycle Evidence</strong></td><td>Lifecycle state visible with closure model defined.</td><td><span class="badge green">89%</span></td><td>Prepare evidence only.</td><td>QA / lifecycle owner.</td><td>Closure proof and access deactivation.</td></tr>
                        <tr><td><strong>Validation Impact</strong></td><td>Impact questions available; final conclusion requires QA/CSV/CSA.</td><td><span class="badge orange">68%</span></td><td>Draft assessment only.</td><td>QA / validation owner.</td><td>Impact rationale and approved assessment.</td></tr>
                        <tr><td><strong>Regulatory Replay</strong></td><td>Prompt, trigger, evidence, authority, rollback, and decision trace available.</td><td><span class="badge green">97%</span></td><td>Replay generation allowed.</td><td>Reviewer for high-impact actions.</td><td>Maintain Black Box integrity.</td></tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Evidence Gate Engines</h2>
                <div class="cards">
                    <div class="card"><h3>Proof Threshold Engine</h3><p>Sets minimum evidence score before ServiceNow AI may recommend, execute, escalate, or claim readiness.</p></div>
                    <div class="card"><h3>Evidence Freshness Monitor</h3><p>Detects when support, access, certificate, lifecycle, exception, or validation evidence becomes stale.</p></div>
                    <div class="card"><h3>Claim-to-Evidence Resolver</h3><p>Maps every AI recommendation and executive claim to required evidence before reliance.</p></div>
                    <div class="card"><h3>Human Gate Trigger</h3><p>Routes decisions to human owners when evidence is below threshold or regulated impact exists.</p></div>
                </div>
            </section>

            <section class="section">
                <h2>Evidence-Based Execution Rules</h2>
                <table>
                    <thead><tr><th>Evidence Score</th><th>Decision</th><th>Allowed AI Behavior</th><th>Blocked Behavior</th><th>Required Next Step</th></tr></thead>
                    <tbody>
                        <tr><td>95–100%</td><td><span class="badge green">Allow Assisted / Low-Risk</span></td><td>Draft, recommend, generate replay, prepare evidence pack.</td><td>Regulated final approval remains blocked.</td><td>Record Black Box trace.</td></tr>
                        <tr><td>85–94%</td><td><span class="badge yellow">Allow With Limits</span></td><td>Recommendations and conditional language.</td><td>Autonomous high-impact change.</td><td>Human reviewer acceptance.</td></tr>
                        <tr><td>70–84%</td><td><span class="badge orange">Human Gate Required</span></td><td>Gap detection and evidence request.</td><td>Execution and reliance claims.</td><td>Attach missing proof.</td></tr>
                        <tr><td>Below 70%</td><td><span class="badge red">Block</span></td><td>Escalation only.</td><td>Recommendation as trusted output.</td><td>Quarantine trust and remediate evidence.</td></tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">CITrust™ Agent Evidence Sufficiency Gate™ does not replace ServiceNow, AI Control Tower, CMDB, QA, CSV/CSA, change control, validation, MyAccess, or human approval. It governs ServiceNow AI by validating evidence sufficiency, freshness, traceability, authority, rollback, replay, and human accountability before actions or claims are trusted.</div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AGENT_EVIDENCE_SUFFICIENCY_GATE_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Agent Evidence Sufficiency Gate installed.")
