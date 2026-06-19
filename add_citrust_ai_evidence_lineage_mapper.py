from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AI_EVIDENCE_LINEAGE_MAPPER_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/ai-evidence-lineage-mapper")'
ROUTE_ALIAS = '@app.route("/citrust/autonomous-evidence-lineage")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust AI Evidence Lineage Mapper already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AI_EVIDENCE_LINEAGE_MAPPER_V1_ACTIVE
# ============================================================

@app.route("/citrust/ai-evidence-lineage-mapper")
@app.route("/citrust/autonomous-evidence-lineage")
def citrust_ai_evidence_lineage_mapper():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ AI Evidence Lineage Mapper</title>
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
            .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-top:16px}.box{border:1px solid rgba(92,200,255,.32);background:linear-gradient(135deg,rgba(255,255,255,.06),rgba(92,200,255,.07)),rgba(255,255,255,.035);border-radius:22px;padding:22px;min-height:250px}.box h3{margin:0 0 12px 0;font-size:21px}.box ul{margin:0;padding-left:20px;color:var(--muted);font-size:14px;line-height:1.85}
            .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px}.card{border:1px solid var(--line);background:rgba(255,255,255,.045);border-radius:18px;padding:18px;min-height:150px}.card h3{margin:0 0 8px 0;font-size:17px}.card p{margin:0;color:var(--muted);font-size:14px;line-height:1.55}
            table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:16px;margin-top:16px}th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:#c9dbef;background:rgba(255,255,255,.07);padding:13px 12px;border-bottom:1px solid var(--line)}td{padding:13px 12px;border-bottom:1px solid rgba(255,255,255,.08);color:#e9f2ff;vertical-align:top;font-size:14px}tr:hover td{background:rgba(92,200,255,.05)}
            .footer{color:var(--muted);font-size:12px;margin-top:22px;line-height:1.6}
            @media(max-width:1180px){.kpis,.cards,.grid{grid-template-columns:1fr}h1{font-size:30px}table{display:block;overflow-x:auto;white-space:nowrap}}
        </style>
    </head>
    <body>
        <div class="page">
            <section class="hero">
                <div class="eyebrow">CITrust™ / ServiceNow AI / Evidence Lineage Governance</div>
                <h1>CITrust™ AI Evidence Lineage Mapper</h1>
                <div class="subtitle">Maps every evidence artifact used by ServiceNow AI from source system to CI record, decision, human approval, rollback, replay, certificate claim, and executive reliance statement.</div>
                <div class="positioning"><strong>ServiceNow-focused positioning:</strong> ServiceNow AI may consume evidence, but CITrust™ proves where that evidence came from, whether it was current, who accepted it, which decision it supported, and whether the resulting claim can survive inspection.</div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a><a href="/citrust/ai-decision-rights-matrix">Decision Rights</a><a href="/citrust/ai-action-rollback-verifier">Rollback Verifier</a><a href="/citrust/ai-evidence-sufficiency-index">Evidence Sufficiency</a><a href="/citrust/governance-black-box">Governance Black Box</a><a href="/citrust/regulatory-replay">Regulatory Replay</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Lineage Completeness</div><div class="value" style="color:var(--green);">93%</div><div class="note">Evidence can be traced from source to decision.</div></div>
                <div class="metric"><div class="label">Evidence Sources</div><div class="value" style="color:var(--blue);">11</div><div class="note">CMDB, MyAccess, change, lifecycle, validation, and replay sources mapped.</div></div>
                <div class="metric"><div class="label">Broken Lineage</div><div class="value" style="color:var(--red);">2</div><div class="note">Evidence items missing source or acceptance link.</div></div>
                <div class="metric"><div class="label">Human Acceptance</div><div class="value" style="color:var(--yellow);">Partial</div><div class="note">Some evidence requires reviewer acceptance.</div></div>
                <div class="metric"><div class="label">Inspection Trace</div><div class="value" style="color:var(--green);">Ready</div><div class="note">Lineage supports regulatory replay.</div></div>
                <div class="metric"><div class="label">Claim Decision</div><div class="value" style="color:var(--yellow);">Condition</div><div class="note">Claims limited where lineage is incomplete.</div></div>
            </section>

            <section class="section">
                <h2>Evidence Lineage Answer</h2>
                <div class="answer"><strong>Current lineage interpretation:</strong> CITrust™ can trace most evidence used by ServiceNow AI to source, owner, reviewer, and decision. Any evidence without source, timestamp, owner, acceptance, or replay link must not support certificate readiness, access defensibility, validation conclusion, or executive reliance.</div>
            </section>

            <section class="section">
                <h2>Evidence Lineage Zones</h2>
                <div class="grid">
                    <div class="box"><h3><span class="badge green">Traceable Evidence</span></h3><ul><li>Source system identified</li><li>Timestamp available</li><li>Owner known</li><li>Reviewer accepted</li><li>Decision linked</li><li>Replay preserved</li></ul></div>
                    <div class="box"><h3><span class="badge yellow">Conditional Evidence</span></h3><ul><li>Source known but stale</li><li>Owner pending</li><li>Reviewer not accepted</li><li>Decision link incomplete</li><li>Rollback not connected</li><li>Claim must be limited</li></ul></div>
                    <div class="box"><h3><span class="badge red">Broken Lineage</span></h3><ul><li>No source</li><li>No timestamp</li><li>No owner</li><li>No acceptance</li><li>No replay record</li><li>Cannot support trust claim</li></ul></div>
                </div>
            </section>

            <section class="section">
                <h2>AI Evidence Lineage Matrix</h2>
                <table>
                    <thead><tr><th>Evidence Artifact</th><th>Source</th><th>Used By AI For</th><th>Lineage Status</th><th>Decision Impact</th><th>Required Closure</th></tr></thead>
                    <tbody>
                        <tr><td><strong>CI owner and class</strong></td><td>ServiceNow CMDB</td><td>CI identity and candidate reasoning.</td><td><span class="badge green">Traceable</span></td><td>Supports draft recommendation.</td><td>Maintain relationship verification.</td></tr>
                        <tr><td><strong>Support group / resolver path</strong></td><td>ServiceNow / Operations Evidence</td><td>Support trust recommendation.</td><td><span class="badge yellow">Conditional</span></td><td>Human gate required.</td><td>LCM and escalation owner acceptance.</td></tr>
                        <tr><td><strong>MyAccess role mapping</strong></td><td>MyAccess / IAM evidence</td><td>Access defensibility check.</td><td><span class="badge orange">Partial</span></td><td>Access claim downgraded.</td><td>Approver group and access review proof.</td></tr>
                        <tr><td><strong>Validation impact rationale</strong></td><td>Change / QA / CSV assessment</td><td>Validation impact classification draft.</td><td><span class="badge yellow">Reviewer Needed</span></td><td>AI cannot conclude impact.</td><td>QA/CSV acceptance.</td></tr>
                        <tr><td><strong>Rollback state</strong></td><td>Black Box / Change record</td><td>Recovery and reversibility proof.</td><td><span class="badge green">Traceable</span></td><td>Supports conditional execution.</td><td>Post-rollback verification acceptance.</td></tr>
                        <tr><td><strong>Executive readiness claim</strong></td><td>Claim Firewall / Decision Ledger</td><td>Leadership reliance language.</td><td><span class="badge yellow">Conditional</span></td><td>Use limitation language.</td><td>Evidence sufficiency closure.</td></tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Evidence Lineage Engines</h2>
                <div class="cards">
                    <div class="card"><h3>Source Trace Engine</h3><p>Links each evidence object to its origin system, timestamp, owner, and freshness status.</p></div>
                    <div class="card"><h3>Decision Linker</h3><p>Maps each evidence item to the AI recommendation, human approval, rollback, and final trust state it supports.</p></div>
                    <div class="card"><h3>Broken Lineage Blocker</h3><p>Blocks AI claims and executive reliance when evidence cannot be traced to source and acceptance.</p></div>
                    <div class="card"><h3>Inspection Lineage Binder</h3><p>Packages evidence lineage into a replay-ready inspection defense bundle.</p></div>
                </div>
            </section>

            <div class="footer">CITrust™ AI Evidence Lineage Mapper™ does not replace ServiceNow, MyAccess, change records, validation systems, QA evidence, or human approval. It maps evidence lineage from source to AI recommendation, human decision, rollback, replay, certificate claim, and executive reliance so ServiceNow AI remains inspection-defensible.</div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AI_EVIDENCE_LINEAGE_MAPPER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust AI Evidence Lineage Mapper installed.")
