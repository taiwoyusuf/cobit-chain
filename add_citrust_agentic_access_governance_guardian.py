from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENTIC_ACCESS_GOVERNANCE_GUARDIAN_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/agentic-access-governance-guardian")'
ROUTE_ALIAS = '@app.route("/citrust/ai-access-governance-guardian")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Agentic Access Governance Guardian already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AGENTIC_ACCESS_GOVERNANCE_GUARDIAN_V1_ACTIVE
# ============================================================

@app.route("/citrust/agentic-access-governance-guardian")
@app.route("/citrust/ai-access-governance-guardian")
def citrust_agentic_access_governance_guardian():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Agentic Access Governance Guardian</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root{--bg:#040b14;--panel:rgba(14,27,44,.92);--line:rgba(255,255,255,.12);--text:#eef5ff;--muted:#a8bbd4;--green:#31d07d;--yellow:#f7c948;--red:#ff5c70;--blue:#5cc8ff;--purple:#b49cff;--orange:#ffb86b;--cyan:#7efcff}
            *{box-sizing:border-box}
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at top left,rgba(92,200,255,.22),transparent 30%),radial-gradient(circle at top right,rgba(255,92,112,.18),transparent 28%),radial-gradient(circle at bottom right,rgba(247,201,72,.14),transparent 30%),var(--bg);color:var(--text)}
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
                <div class="eyebrow">CITrust™ / ServiceNow AI / MyAccess & Privileged Access Governance</div>
                <h1>CITrust™ Agentic Access Governance Guardian</h1>
                <div class="subtitle">Prevents ServiceNow AI agents from approving, modifying, or relying on access pathways unless MyAccess, approver ownership, privileged account rules, vendor access, CyberArk/PSM path, review evidence, and post-access verification are governed and defensible.</div>
                <div class="positioning"><strong>ServiceNow-focused positioning:</strong> CITrust™ does not replace MyAccess, IAM, CyberArk, or ServiceNow workflows. It governs whether ServiceNow AI can safely recommend, route, or rely on access-related actions in regulated environments.</div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/agentic-exception-escalation-engine">Exception Escalation</a>
                    <a href="/citrust/autonomous-action-rollback-vault">Rollback Vault</a>
                    <a href="/citrust/agent-evidence-sufficiency-gate">Evidence Gate</a>
                    <a href="/citrust/ai-authority-envelope">AI Authority Envelope</a>
                    <a href="/citrust/regulatory-replay">Regulatory Replay</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Access Guardian</div><div class="value" style="color:var(--green);">Active</div><div class="note">Access-impacting AI actions are being guarded.</div></div>
                <div class="metric"><div class="label">Access Sufficiency</div><div class="value" style="color:var(--yellow);">74%</div><div class="note">Evidence supports gap detection, not autonomous approval.</div></div>
                <div class="metric"><div class="label">Privileged Access</div><div class="value" style="color:var(--red);">Blocked</div><div class="note">AI cannot approve privileged access.</div></div>
                <div class="metric"><div class="label">MyAccess Mapping</div><div class="value" style="color:var(--blue);">Partial</div><div class="note">Mapping available but requires owner confirmation.</div></div>
                <div class="metric"><div class="label">Review Proof</div><div class="value" style="color:var(--orange);">Stale</div><div class="note">Access review proof requires refresh before reliance.</div></div>
                <div class="metric"><div class="label">Trust Decision</div><div class="value" style="color:var(--yellow);">Conditional</div><div class="note">Access assurance is conditional until bundle closes.</div></div>
            </section>

            <section class="section">
                <h2>Access Governance Guardian Answer</h2>
                <div class="answer"><strong>Current guardian decision:</strong> ServiceNow AI may identify access gaps, prepare access evidence requests, map likely approver groups, and generate limitation language. It cannot approve access, modify privileged access, bypass MyAccess, accept vendor access risk, or certify access readiness without accountable human approval.</div>
            </section>

            <section class="section">
                <h2>Access Governance Zones</h2>
                <div class="grid">
                    <div class="box"><h3><span class="badge green">AI May Assist</span></h3><ul><li>Detect stale access evidence</li><li>Draft access evidence request</li><li>Map CI to access dependency</li><li>Flag orphaned approver group</li><li>Prepare review checklist</li><li>Generate limitation language</li></ul></div>
                    <div class="box"><h3><span class="badge yellow">Human Approval Required</span></h3><ul><li>Access entitlement ownership</li><li>Approver group change</li><li>Vendor access acceptance</li><li>Admin access procedure approval</li><li>Privileged session route acceptance</li><li>Post-access verification acceptance</li></ul></div>
                    <div class="box"><h3><span class="badge red">AI Forbidden</span></h3><ul><li>Approve privileged access</li><li>Grant access</li><li>Remove reviewer requirement</li><li>Bypass MyAccess</li><li>Override CyberArk/PSM path</li><li>Suppress access exception</li></ul></div>
                </div>
            </section>

            <section class="section">
                <h2>Access Governance Matrix</h2>
                <table>
                    <thead><tr><th>Access Domain</th><th>Evidence State</th><th>Guardian Decision</th><th>AI Permission</th><th>Human Owner</th><th>Closure Evidence</th></tr></thead>
                    <tbody>
                        <tr><td><strong>MyAccess Mapping</strong></td><td>Entitlement mapping exists but owner confirmation is incomplete.</td><td><span class="badge yellow">Conditional</span></td><td>Recommend mapping only.</td><td>Access Governance / Entitlement Owner</td><td>Confirmed entitlement owner and approver group.</td></tr>
                        <tr><td><strong>Privileged Access</strong></td><td>Admin/vendor route requires review proof and approved procedure.</td><td><span class="badge red">Block Autonomous</span></td><td>Gap detection only.</td><td>Cyber / Access Governance</td><td>Admin procedure, review proof, session route, approval.</td></tr>
                        <tr><td><strong>Vendor Access</strong></td><td>Vendor route must prove scope, identity, session control, and approval.</td><td><span class="badge yellow">Human Gate</span></td><td>Prepare evidence checklist.</td><td>System Owner / Cyber</td><td>Vendor approval, access period, session control, review record.</td></tr>
                        <tr><td><strong>CyberArk / PSM Path</strong></td><td>Session-control expectation exists; CI-specific evidence may be incomplete.</td><td><span class="badge yellow">Verify</span></td><td>Flag missing proof.</td><td>CyberArk / Infrastructure Owner</td><td>Safe/route evidence, session control, approval path.</td></tr>
                        <tr><td><strong>Access Review</strong></td><td>Review evidence stale or not linked to CI trust state.</td><td><span class="badge orange">Escalate</span></td><td>Draft review request.</td><td>Access Reviewer</td><td>Completed review, exceptions, removals, acceptance.</td></tr>
                        <tr><td><strong>Post-Access Verification</strong></td><td>Verification evidence not consistently captured.</td><td><span class="badge yellow">Conditional</span></td><td>Prepare verification checklist.</td><td>System Owner / Access Owner</td><td>Post-access check and closure record.</td></tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Access Guardian Engines</h2>
                <div class="cards">
                    <div class="card"><h3>MyAccess Evidence Resolver</h3><p>Maps CI trust to entitlement ownership, approver group, access role, and reviewer accountability.</p></div>
                    <div class="card"><h3>Privileged Access Blocker</h3><p>Prevents AI from approving privileged, vendor, or admin access without human governance.</p></div>
                    <div class="card"><h3>Session Route Verifier</h3><p>Checks whether CyberArk, PSM, RDP Gateway, or approved access route evidence is available.</p></div>
                    <div class="card"><h3>Access Trust Restorer</h3><p>Restores access confidence only after review proof, exception closure, and post-access verification are accepted.</p></div>
                </div>
            </section>

            <section class="section">
                <h2>Access Execution Rules</h2>
                <table>
                    <thead><tr><th>Condition</th><th>Decision</th><th>AI Action</th><th>Human Gate</th><th>Trust Outcome</th></tr></thead>
                    <tbody>
                        <tr><td>Access evidence complete and action is advisory.</td><td><span class="badge green">Allow Assisted</span></td><td>Prepare summary or evidence pack.</td><td>Optional reviewer.</td><td>Trust maintained.</td></tr>
                        <tr><td>Access change affects approver, entitlement, admin, or vendor route.</td><td><span class="badge yellow">Human Gate</span></td><td>Recommend and route.</td><td>Access owner required.</td><td>Conditional until accepted.</td></tr>
                        <tr><td>AI attempts to approve or grant privileged access.</td><td><span class="badge red">Block</span></td><td>Denied and logged.</td><td>Cyber / Access Governance.</td><td>Trust quarantined if attempted.</td></tr>
                        <tr><td>Access review proof is stale.</td><td><span class="badge orange">Escalate</span></td><td>Generate review request.</td><td>Reviewer acceptance.</td><td>Rely with limitation only.</td></tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">CITrust™ Agentic Access Governance Guardian™ does not replace ServiceNow, MyAccess, CyberArk, PSM, IAM, access reviewers, cyber governance, or human approval. It governs ServiceNow AI access-related actions by validating MyAccess evidence, privileged access boundaries, vendor access proof, session control, reviewer accountability, post-access verification, and inspection-ready replay before access trust is granted.</div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AGENTIC_ACCESS_GOVERNANCE_GUARDIAN_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Agentic Access Governance Guardian installed.")
