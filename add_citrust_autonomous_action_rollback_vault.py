from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AUTONOMOUS_ACTION_ROLLBACK_VAULT_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/autonomous-action-rollback-vault")'
ROUTE_ALIAS = '@app.route("/citrust/ai-rollback-vault")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Autonomous Action Rollback Vault already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AUTONOMOUS_ACTION_ROLLBACK_VAULT_V1_ACTIVE
# ============================================================

@app.route("/citrust/autonomous-action-rollback-vault")
@app.route("/citrust/ai-rollback-vault")
def citrust_autonomous_action_rollback_vault():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Autonomous Action Rollback Vault</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root{--bg:#040b14;--panel:rgba(14,27,44,.92);--line:rgba(255,255,255,.12);--text:#eef5ff;--muted:#a8bbd4;--green:#31d07d;--yellow:#f7c948;--red:#ff5c70;--blue:#5cc8ff;--purple:#b49cff;--orange:#ffb86b;--cyan:#7efcff}
            *{box-sizing:border-box}
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at top left,rgba(92,200,255,.22),transparent 30%),radial-gradient(circle at top right,rgba(49,208,125,.18),transparent 28%),radial-gradient(circle at bottom right,rgba(255,92,112,.14),transparent 30%),var(--bg);color:var(--text)}
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
                <div class="eyebrow">CITrust™ / ServiceNow AI / Autonomous Recovery Governance</div>
                <h1>CITrust™ Autonomous Action Rollback Vault</h1>
                <div class="subtitle">Preserves the before-state, rollback path, reviewer, evidence, verification criteria, and trust recovery record for every ServiceNow AI-assisted action before the action is allowed to execute or be trusted.</div>
                <div class="positioning"><strong>ServiceNow-focused positioning:</strong> CITrust™ ensures no ServiceNow AI action becomes trusted unless the organization can reverse it, explain it, verify it, and defend the recovery path during governance, audit, or inspection review.</div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a><a href="/citrust/agent-evidence-sufficiency-gate">Evidence Gate</a><a href="/citrust/agentic-validation-impact-assessor">Validation Impact</a><a href="/citrust/agentic-change-control-gate">Change Gate</a><a href="/citrust/regulatory-replay">Regulatory Replay</a><a href="/citrust/governance-black-box">Black Box</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Rollback Vault</div><div class="value" style="color:var(--green);">Armed</div><div class="note">Rollback package required before trusted AI execution.</div></div>
                <div class="metric"><div class="label">Rollback Coverage</div><div class="value" style="color:var(--green);">94%</div><div class="note">Most AI-assisted actions have recovery state preserved.</div></div>
                <div class="metric"><div class="label">Unreversible Actions</div><div class="value" style="color:var(--red);">3</div><div class="note">Blocked until recovery path is defined.</div></div>
                <div class="metric"><div class="label">Recovery Owner</div><div class="value" style="color:var(--blue);">Assigned</div><div class="note">Rollback accountability must be explicit.</div></div>
                <div class="metric"><div class="label">Verification Required</div><div class="value" style="color:var(--yellow);">Yes</div><div class="note">Post-rollback verification required before trust recovery.</div></div>
                <div class="metric"><div class="label">Trust Recovery</div><div class="value" style="color:var(--yellow);">Conditional</div><div class="note">Recovered trust requires reviewer acceptance.</div></div>
            </section>

            <section class="section">
                <h2>Rollback Vault Answer</h2>
                <div class="answer"><strong>Current rollback decision:</strong> ServiceNow AI may recommend or prepare low-risk changes only when previous state, rollback owner, recovery method, verification criteria, and Black Box replay are captured. If an action cannot be reversed or verified, CITrust™ blocks execution and quarantines trust.</div>
            </section>

            <section class="section">
                <h2>Rollback Vault Zones</h2>
                <div class="grid">
                    <div class="box"><h3><span class="badge green">Rollback Ready</span></h3><ul><li>Previous value captured</li><li>Changed field identified</li><li>Recovery owner assigned</li><li>Rollback method documented</li><li>Verification checklist prepared</li><li>Black Box link available</li></ul></div>
                    <div class="box"><h3><span class="badge yellow">Recovery Review Required</span></h3><ul><li>Support owner change</li><li>Lifecycle recommendation</li><li>Certificate state update</li><li>Access evidence acceptance</li><li>Validated system dependency</li><li>High-impact CMDB relationship</li></ul></div>
                    <div class="box"><h3><span class="badge red">Execution Blocked</span></h3><ul><li>No previous state</li><li>No rollback owner</li><li>No verification method</li><li>Evidence cannot be restored</li><li>Validation baseline affected</li><li>Replay missing</li></ul></div>
                </div>
            </section>

            <section class="section">
                <h2>Rollback Vault Matrix</h2>
                <table>
                    <thead><tr><th>AI Action</th><th>Rollback Requirement</th><th>Vault Status</th><th>Execution Decision</th><th>Recovery Owner</th><th>Verification</th></tr></thead>
                    <tbody>
                        <tr><td><strong>Draft CI candidate</strong></td><td>Draft version and evidence source preserved.</td><td><span class="badge green">Ready</span></td><td>Allow assisted.</td><td>CMDB reviewer.</td><td>Candidate review completed.</td></tr>
                        <tr><td><strong>Recommend support group change</strong></td><td>Previous support group and resolver path preserved.</td><td><span class="badge yellow">Review</span></td><td>Human-gated.</td><td>Service operations owner.</td><td>Incident routing verified.</td></tr>
                        <tr><td><strong>Change lifecycle state</strong></td><td>Previous lifecycle state, access state, closure proof, restoration condition.</td><td><span class="badge red">Blocked</span></td><td>No autonomous execution.</td><td>Lifecycle owner / QA.</td><td>Lifecycle restoration verified.</td></tr>
                        <tr><td><strong>Access governance update</strong></td><td>Prior access mapping, approver group, review evidence, rollback route.</td><td><span class="badge yellow">Conditional</span></td><td>Human approval required.</td><td>Access governance owner.</td><td>Access route verified.</td></tr>
                        <tr><td><strong>Validation-impacting config change</strong></td><td>Validated baseline, test evidence, rollback procedure, QA acceptance.</td><td><span class="badge red">Blocked</span></td><td>Formal change required.</td><td>QA / CSV / System Owner.</td><td>Post-change and rollback test.</td></tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Rollback Vault Engines</h2>
                <div class="cards">
                    <div class="card"><h3>Before-State Capture</h3><p>Preserves CI field values, evidence references, support ownership, access mapping, lifecycle state, and certificate state before AI action.</p></div>
                    <div class="card"><h3>Recovery Owner Resolver</h3><p>Assigns accountable owner for restoring governance state if the AI-assisted change fails review.</p></div>
                    <div class="card"><h3>Rollback Verification Gate</h3><p>Requires proof that rollback restored the expected CMDB, access, support, lifecycle, or validation state.</p></div>
                    <div class="card"><h3>Trust Recovery Ledger</h3><p>Records whether trust was restored, remained conditional, or stayed quarantined after rollback.</p></div>
                </div>
            </section>

            <section class="section">
                <h2>Rollback Execution Rules</h2>
                <table>
                    <thead><tr><th>Condition</th><th>Decision</th><th>Required Proof</th><th>Human Gate</th><th>Trust Outcome</th></tr></thead>
                    <tbody>
                        <tr><td>Rollback state complete and action low-risk.</td><td><span class="badge green">Allow Assisted</span></td><td>Previous state, recovery owner, verification criteria.</td><td>Optional reviewer.</td><td>Trust maintained.</td></tr>
                        <tr><td>Rollback state complete but action affects support/access/lifecycle.</td><td><span class="badge yellow">Human Gate</span></td><td>Before/after state, approval, recovery plan.</td><td>Mandatory.</td><td>Conditional until accepted.</td></tr>
                        <tr><td>Rollback state incomplete.</td><td><span class="badge red">Block</span></td><td>Missing previous state or recovery owner.</td><td>Governance escalation.</td><td>Trust quarantined.</td></tr>
                        <tr><td>Rollback fails verification.</td><td><span class="badge red">Escalate</span></td><td>Failed verification record and remediation plan.</td><td>System owner / QA.</td><td>Trust remains quarantined.</td></tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">CITrust™ Autonomous Action Rollback Vault™ does not replace ServiceNow Change, CMDB, QA, validation, cyber, system owner review, or human governance. It ensures ServiceNow AI actions are reversible, verified, owned, replayable, and trust-recoverable before they are treated as reliable in regulated operations.</div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AUTONOMOUS_ACTION_ROLLBACK_VAULT_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Autonomous Action Rollback Vault installed.")
