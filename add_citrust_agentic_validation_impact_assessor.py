from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENTIC_VALIDATION_IMPACT_ASSESSOR_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/agentic-validation-impact-assessor")'
ROUTE_ALIAS = '@app.route("/citrust/ai-validation-impact")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Agentic Validation Impact Assessor already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AGENTIC_VALIDATION_IMPACT_ASSESSOR_V1_ACTIVE
# ============================================================

@app.route("/citrust/agentic-validation-impact-assessor")
@app.route("/citrust/ai-validation-impact")
def citrust_agentic_validation_impact_assessor():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Agentic Validation Impact Assessor</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root{--bg:#040b14;--panel:rgba(14,27,44,.92);--line:rgba(255,255,255,.12);--text:#eef5ff;--muted:#a8bbd4;--green:#31d07d;--yellow:#f7c948;--red:#ff5c70;--blue:#5cc8ff;--purple:#b49cff;--orange:#ffb86b;--cyan:#7efcff}
            *{box-sizing:border-box}
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at top left,rgba(180,156,255,.22),transparent 30%),radial-gradient(circle at top right,rgba(92,200,255,.18),transparent 28%),radial-gradient(circle at bottom right,rgba(255,92,112,.14),transparent 30%),var(--bg);color:var(--text)}
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
                <div class="eyebrow">CITrust™ / ServiceNow AI / Validation Impact Governance</div>
                <h1>CITrust™ Agentic Validation Impact Assessor</h1>
                <div class="subtitle">Determines whether a ServiceNow AI-proposed action affects validated systems, GxP operations, GMP evidence, configuration baseline, data integrity, qualification state, or inspection readiness before any autonomous execution or readiness claim is allowed.</div>
                <div class="positioning"><strong>ServiceNow-focused positioning:</strong> CITrust™ ensures ServiceNow AI does not quietly turn an IT workflow into a validation-impacting change without QA, CSV/CSA, system owner, evidence, rollback, and post-change verification controls.</div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a><a href="/citrust/agentic-change-control-gate">Agentic Change Gate</a><a href="/citrust/servicenow-ai-readiness-command-center">ServiceNow AI Readiness</a><a href="/citrust/governance-operating-system">GovOS</a><a href="/citrust/regulatory-replay">Regulatory Replay</a><a href="/citrust/ai-authority-envelope">AI Authority Envelope</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Validation Impact</div><div class="value" style="color:var(--orange);">Possible</div><div class="note">AI-proposed changes must pass impact screening.</div></div>
                <div class="metric"><div class="label">GxP Signal</div><div class="value" style="color:var(--yellow);">Medium</div><div class="note">CI supports regulated operational context.</div></div>
                <div class="metric"><div class="label">Autonomy Decision</div><div class="value" style="color:var(--red);">Block</div><div class="note">No autonomous validation-impacting execution.</div></div>
                <div class="metric"><div class="label">QA Gate</div><div class="value" style="color:var(--green);">Required</div><div class="note">QA/CSV/CSA review required before reliance.</div></div>
                <div class="metric"><div class="label">Rollback Evidence</div><div class="value" style="color:var(--yellow);">Needed</div><div class="note">Rollback must be defined before change approval.</div></div>
                <div class="metric"><div class="label">Inspection Status</div><div class="value" style="color:var(--yellow);">Conditional</div><div class="note">Defensible only after impact assessment closure.</div></div>
            </section>

            <section class="section">
                <h2>Validation Impact Answer</h2>
                <div class="answer"><strong>Current assessment:</strong> ServiceNow AI may prepare the validation impact assessment, gather evidence, draft risk questions, and recommend classification. It must not autonomously classify a regulated change as non-impacting, override validation, alter validated configuration, or certify readiness without accountable human approval.</div>
            </section>

            <section class="section">
                <h2>Validation Impact Zones</h2>
                <div class="grid">
                    <div class="box"><h3><span class="badge green">AI May Assist</span></h3><ul><li>Draft impact assessment</li><li>Collect CI evidence</li><li>Prepare rollback checklist</li><li>Map affected systems</li><li>Generate QA review questions</li><li>Flag validation uncertainty</li></ul></div>
                    <div class="box"><h3><span class="badge yellow">Human Review Required</span></h3><ul><li>GxP impact classification</li><li>Validation impact conclusion</li><li>Test evidence acceptance</li><li>Risk acceptance</li><li>Post-change verification approval</li><li>Release readiness decision</li></ul></div>
                    <div class="box"><h3><span class="badge red">AI Forbidden</span></h3><ul><li>Override validation status</li><li>Declare no-impact alone</li><li>Modify validated configuration</li><li>Close validation deviation</li><li>Approve release readiness</li><li>Remove validation evidence</li></ul></div>
                </div>
            </section>

            <section class="section">
                <h2>Validation Impact Matrix</h2>
                <table>
                    <thead><tr><th>AI-Proposed Action</th><th>Validation Concern</th><th>Impact Decision</th><th>Required Human Role</th><th>Evidence Required</th><th>Execution Rule</th></tr></thead>
                    <tbody>
                        <tr><td><strong>Update CMDB support group</strong></td><td>May affect incident routing for validated system.</td><td><span class="badge yellow">Potential Impact</span></td><td>System Owner / CMDB Governance</td><td>Support path, LCM, escalation owner, approval record.</td><td>AI recommendation only.</td></tr>
                        <tr><td><strong>Change validated server configuration</strong></td><td>Could alter validated baseline.</td><td><span class="badge red">Validation Impact</span></td><td>QA / CSV / Validation</td><td>Change control, risk assessment, test evidence, rollback, approval.</td><td>Autonomous execution blocked.</td></tr>
                        <tr><td><strong>Retire a CI linked to GxP process</strong></td><td>May affect evidence, access, audit trail, and operational continuity.</td><td><span class="badge yellow">Impact Review</span></td><td>QA / Lifecycle Owner</td><td>Closure evidence, access removal, dependency review, backup status.</td><td>Human approval required.</td></tr>
                        <tr><td><strong>Prepare post-change verification plan</strong></td><td>Supports validation evidence but does not approve outcome.</td><td><span class="badge green">Assist Allowed</span></td><td>System Owner accepts final plan.</td><td>Acceptance criteria, affected CI, expected state, rollback test.</td><td>AI may draft.</td></tr>
                        <tr><td><strong>Approve no-validation-impact conclusion</strong></td><td>Regulated conclusion requiring accountable human decision.</td><td><span class="badge red">Forbidden</span></td><td>QA / CSV / CSA</td><td>Impact rationale, documented approval, risk acceptance.</td><td>AI cannot approve.</td></tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Validation Impact Engines</h2>
                <div class="cards">
                    <div class="card"><h3>GxP Signal Detector</h3><p>Identifies whether CI, workflow, evidence, access, or change touches regulated operations.</p></div>
                    <div class="card"><h3>Impact Boundary Classifier</h3><p>Separates IT-only workflow changes from validation, CSV/CSA, GMP, and inspection-impacting changes.</p></div>
                    <div class="card"><h3>Human Review Router</h3><p>Routes impact decisions to QA, system owner, validation, cyber, CMDB, or change control owner.</p></div>
                    <div class="card"><h3>Evidence Sufficiency Gate</h3><p>Blocks reliance when assessment, rollback, test evidence, approval, or verification proof is incomplete.</p></div>
                </div>
            </section>

            <section class="section">
                <h2>Impact Closure Requirements</h2>
                <table>
                    <thead><tr><th>Closure Item</th><th>Why Required</th><th>Evidence</th><th>Owner</th><th>Result</th></tr></thead>
                    <tbody>
                        <tr><td>Impact classification</td><td>Prevents AI from mislabeling regulated changes.</td><td>GxP/validation impact rationale.</td><td>QA / CSV / System Owner</td><td>Change route confirmed.</td></tr>
                        <tr><td>Rollback readiness</td><td>Ensures change can be safely reversed.</td><td>Previous state, rollback method, owner, verification.</td><td>Technical Owner</td><td>Recovery defensible.</td></tr>
                        <tr><td>Post-change verification</td><td>Proves intended state was achieved.</td><td>Verification checklist and accepted results.</td><td>System Owner / QA</td><td>Readiness defensible.</td></tr>
                        <tr><td>Regulatory replay</td><td>Preserves why AI assisted and how humans approved.</td><td>Prompt, evidence, authority, decision, approval, outcome.</td><td>Governance Owner</td><td>Inspection-ready record.</td></tr>
                    </tbody>
                </table>
            </section>

            <div class="footer">CITrust™ Agentic Validation Impact Assessor™ does not replace ServiceNow Change, QA, validation, CSV/CSA, system owner review, or formal change control. It governs ServiceNow AI proposals by detecting validation impact, routing human review, enforcing evidence sufficiency, blocking unsafe autonomy, preserving regulatory replay, and protecting GMP/GxP readiness.</div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AGENTIC_VALIDATION_IMPACT_ASSESSOR_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Agentic Validation Impact Assessor installed.")
